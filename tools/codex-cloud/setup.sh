#!/usr/bin/env bash
# Build the committed Nmap engine without touching working-tree source files.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/codex-cloud/setup.sh [--rebuild] [--jobs N]

Build Nmap and standalone Lua from git archive HEAD using bundled libraries.
No packages or downloads are requested. OpenSSL and libssh2 are disabled.
The engine is committed source; NMAPDIR points at the live NSE working tree.

  --rebuild  Ignore a successful cached build.
  --jobs N   Compiler jobs, 1 through 16 (default: 4).
EOF
}

rebuild=false
jobs=4
while (($#)); do
  case "$1" in
    --rebuild) rebuild=true; shift ;;
    --jobs)
      if (($# < 2)); then echo '--jobs requires a value' >&2; exit 2; fi
      jobs=$2
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ ! "$jobs" =~ ^([1-9]|1[0-6])$ ]]; then
  echo '--jobs must be an integer from 1 through 16' >&2
  exit 2
fi
for prerequisite in git python3 gcc g++ make tar install mktemp; do
  if ! command -v "$prerequisite" >/dev/null 2>&1; then
    printf 'Missing prerequisite: %s\n' "$prerequisite" >&2
    exit 1
  fi
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else "Python 3.9 or newer is required")'

script_path=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "${BASH_SOURCE[0]}")
repo_dir=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).parent.parent.parent)' "$script_path")
git_root=$(git -C "$repo_dir" rev-parse --show-toplevel)
if [[ "$git_root" != "$repo_dir" ]]; then
  echo 'Run this script from its tools/codex-cloud location in the repository.' >&2
  exit 1
fi
# Shell arguments below are quoted. Upstream Makefile recipes themselves do
# not quote build/install paths, so refuse paths they cannot safely handle.
if [[ ! "$repo_dir" =~ ^/[-A-Za-z0-9_./+]+$ ]]; then
  echo 'Upstream Nmap Makefiles require a checkout path without spaces or shell metacharacters.' >&2
  exit 1
fi
source_commit=$(git -C "$repo_dir" rev-parse HEAD)
cache_dir="$repo_dir/.codex-cache"
prefix="$cache_dir/runtime"
stamp="$prefix/.build-stamp.json"
mkdir -p "$cache_dir/build" "$cache_dir/setup-logs"
log_path=$(mktemp "$cache_dir/setup-logs/setup.XXXXXXXX.log")
lock_dir="$cache_dir/setup.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
  printf 'Another setup may be running; inspect %s before removing a stale lock.\n' "$lock_dir" >&2
  exit 1
fi
printf '%s\n' "pid=$$" "log=$log_path" > "$lock_dir/owner"
cleanup() {
  local status=$?
  trap - EXIT
  if ((status != 0)); then
    printf 'Setup failed (exit %s). Log: %s\n' "$status" "$log_path" >&2
    tail -n 20 "$log_path" >&2 || true
  fi
  rm -f -- "$lock_dir/owner"
  rmdir -- "$lock_dir" || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_logged() {
  local status
  { printf '+ '; printf '%q ' "$@"; printf '\n'; } >> "$log_path"
  if "$@" >> "$log_path" 2>&1; then
    printf '[exit 0]\n' >> "$log_path"
  else
    status=$?
    printf '[exit %s]\n' "$status" >> "$log_path"
    return "$status"
  fi
}
show_runtime() {
  printf 'Runtime ready: %s\nSource commit: %s\nLog: %s\n' "$prefix" "$source_commit" "$log_path"
  printf 'OpenSSL and libssh2 are disabled in this local build.\n'
  printf 'For development with the live NSE files:\n'
  printf 'export PATH=%q:$PATH\n' "$prefix/bin"
  printf 'export NMAPDIR=%q\n' "$repo_dir"
}
verify_runtime() {
  local location=$1
  local item
  for item in nse_main.lua scripts/netbus-version.nse nselib/stdnse.lua; do
    [[ -f "$location/share/nmap/$item" ]] || return 1
  done
  run_logged "$location/bin/nmap" --version || return
  run_logged "$location/bin/lua" -v || return
  run_logged "$location/bin/luac" -v || return
}

# A moved checkout or changed compiler/settings invalidates the cache because
# configure embeds absolute paths. Environment values are hashed, not logged.
cache_key=$(python3 - "$repo_dir" "$prefix" "$source_commit" "$script_path" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
repo, prefix, commit, script = sys.argv[1:]
keys = ('CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'AR', 'RANLIB',
        'MAKEFLAGS', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH')
state = {
    'schema': 1, 'repo': repo, 'prefix': prefix, 'commit': commit,
    'script_sha256': hashlib.sha256(pathlib.Path(script).read_bytes()).hexdigest(),
    'environment': {key: os.environ.get(key) for key in keys},
    'compilers': [subprocess.check_output([cc, '--version']).decode(errors='replace')
                  for cc in ('gcc', 'g++')],
    'machine': subprocess.check_output(['gcc', '-dumpmachine']).decode().strip(),
}
print(hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest())
PY
)
printf 'source_commit=%s\ncache_key=%s\nrepository=%s\nprefix=%s\njobs=%s\n' \
  "$source_commit" "$cache_key" "$repo_dir" "$prefix" "$jobs" >> "$log_path"
if [[ "$rebuild" == false && -f "$stamp" ]] && python3 - "$stamp" "$cache_key" <<'PY'
import json, pathlib, sys
try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text())
    valid = value.get('cache_key') == sys.argv[2] and value.get('status') == 'success'
except (OSError, ValueError, AttributeError):
    valid = False
sys.exit(0 if valid else 1)
PY
then
  if verify_runtime "$prefix"; then
    printf 'Using verified cached build.\n' | tee -a "$log_path"
    show_runtime
    exit 0
  fi
  printf 'Cached runtime verification failed; rebuilding.\n' | tee -a "$log_path"
fi

work_dir=$(mktemp -d "$cache_dir/build/setup.XXXXXXXX")
source_dir="$work_dir/src"
stage_dir="$work_dir/stage"
staged_prefix="$stage_dir$prefix"
mkdir -p "$source_dir" "$stage_dir"
printf 'Building committed source %s with %s jobs. Log: %s\n' "$source_commit" "$jobs" "$log_path"
run_logged git -C "$repo_dir" archive --format=tar --output="$work_dir/source.tar" "$source_commit"
run_logged tar -xf "$work_dir/source.tar" -C "$source_dir"
cd "$source_dir"
printf 'Configuring bundled dependencies...\n'
run_logged ./configure \
  --prefix="$prefix" \
  --without-zenmap --without-ndiff --without-ncat --without-nping \
  --without-openssl --without-libssh2 \
  --with-libpcap=included --with-libpcre=included --with-libz=included \
  --with-liblua=included --with-libdnet=included --with-liblinear=included \
  CC=gcc CXX=g++
printf 'Building Nmap and standalone Lua...\n'
run_logged make "-j$jobs"
run_logged make "-j$jobs" -C liblua linux-noreadline
printf 'Installing and verifying the staged runtime...\n'
run_logged make "-j$jobs" install "DESTDIR=$stage_dir"
run_logged install -m 755 liblua/lua liblua/luac "$staged_prefix/bin/"
verify_runtime "$staged_prefix"

# The success stamp belongs to the verified staged runtime. Publish it with
# that runtime only after all build/install/verification commands succeeded.
run_logged python3 - "$staged_prefix" "$prefix" "$source_commit" "$cache_key" "$log_path" "$work_dir" <<'PY'
import datetime, json, pathlib, subprocess, sys
staged, prefix, commit, key, log, work = sys.argv[1:]
staged_path = pathlib.Path(staged)
record = {
    'schema_version': 1, 'status': 'success', 'cache_key': key,
    'source_commit': commit, 'runtime_prefix': prefix,
    'built_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'log': log, 'source_directory': str(pathlib.Path(work) / 'src'),
    'nmap_version': subprocess.check_output([str(staged_path / 'bin/nmap'), '--version'], text=True).strip(),
    'lua_version': subprocess.check_output([str(staged_path / 'bin/lua'), '-v'], text=True).strip(),
}
(staged_path / '.build-stamp.json').write_text(json.dumps(record, indent=2) + '\n')
destination = pathlib.Path(prefix)
backup = pathlib.Path(work) / 'previous-runtime'
had_previous = destination.exists() or destination.is_symlink()
if had_previous:
    destination.rename(backup)
try:
    staged_path.rename(destination)
except BaseException:
    if had_previous:
        backup.rename(destination)
    raise
print('Published verified runtime:', destination)
if had_previous:
    print('Previous runtime retained at:', backup)
PY
show_runtime
