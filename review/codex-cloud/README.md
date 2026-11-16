# Codex Cloud migration verification — 2026-11-11

The clean-source bootstrap and the full development test workflow passed in
Codex Cloud. [validation.json](validation.json) is the unmodified aggregate
report. [results-20261111.tar.gz](results-20261111.tar.gz) contains the fresh
localhost XML, server events, harness reports, command/output logs, and setup
logs. Verify both files with [SHA256SUMS](SHA256SUMS).

## Reproduce

From the Cloud development branch, run:

```sh
bash tools/codex-cloud/setup.sh
python3 tools/codex-cloud/test.py --suite all
```

See [the development guide](../../docs/codex-cloud-netbus.md) for prerequisites
and individual suites. The bootstrap uses bundled dependencies, builds outside
the working source tree, and installs Nmap and standalone Lua under the ignored
`.codex-cache/` directory. A second setup invocation from another working
directory successfully reused the cache.

## What ran

| Check | Result |
| --- | --- |
| Nmap engine source | `1aa2aaa7ae695bed2f89c2e475f6e003e52b97fb` |
| Runtime | Nmap 7.992SVN; Lua 5.4.9; Python 3.12.14; Linux x86-64 |
| Working NSE contracts | 169 passed; 0 failed |
| Working NSE saved-response replay | 20 cases passed on loopback |
| Working NSE comparison | 28 synthetic loopback scans passed across 7 conditions; includes 14 warmups |
| Frozen archive | 1,739 manifest files, both patches, six fixture files, and 169 snapshot contracts verified |
| Retained synthetic records | 136 scans rechecked |
| Retained Wine/QEMU application records | 168 scans rechecked |

Working NSE SHA256:

```text
1dab4ae5605d6830daade00ea7fe859ec9f9276f8ea85c9c86bc83a59e38b130
```

The source commit in the report precedes the commit that adds these migration
files. The NSE itself was unchanged. The live suites explicitly use
`scripts/netbus-version.nse` from the working tree and record its hash; they do
not validate an installed or frozen substitute. The exact tested wrapper hash
is recorded as `test_runner_sha256`.

The frozen `review` subreport says its optional fresh replay and comparison
were not run. Those tests ran separately against the working NSE and appear in
the top-level `replay` and `compare` results. Snapshot contract checks overlap
the live cases and must not be counted as additional unique live coverage.

## Scope

This run performed no new Wine/QEMU application measurements. The historic
application records were rechecked; their raw data remain in the unchanged
[multiversion review archive](../netbus-multiversion/README.md) and are not
duplicated in the new results archive.

The local runtime omits OpenSSL and libssh2. The workflow establishes this
NetBus TCP development setup, not TLS/SSH-dependent Nmap functionality or
native Windows behavior. Preparing and testing the checkout does not publish
a reusable named Cloud environment; that registration remains a separate
authenticated settings operation.
