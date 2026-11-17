#!/usr/bin/env python3
"""Run NetBus development checks against the working NSE, plus frozen evidence checks."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".codex-cache"
ARCHIVE = ROOT / "review/netbus-multiversion/netbus-multiversion-review.tar.gz"
ARCHIVE_SHA256 = "c33688a0a5d0babf03bf3bb3ab0799e762a04e3d7e2e33c9fc7a2b85d5770f47"
BUNDLE_NAME = "netbus-multiversion-review"
BOUNDARY = "evidence/netbuster112-retry-boundary"
REPLAY_CASES = [
    "real_positive", "real_negative", "info112_real", "info112_eof_55",
    "info112_altered", "response_eof_7", "response_timeout_0",
    "late1500_version_refused", "apps_requery", "apps_only",
]
ORDINARY_CASES = [
    "real_positive", "real_negative", "negative_denied", "split_7",
    "response_eof_7", "response_timeout_0", "malformed_status", "other_version",
    "info112_real", "info112_altered", "info112_eof_55", "info112_timeout_55",
]
COMPARISON_CASES = [
    "retry_coalescing:1.30", "retry_coalescing:1.31",
    "retry_coalescing_refuse:1.30", "retry_coalescing_refuse:1.31",
    "hold400_refuse:1.12", "delay1500_refuse:1.30", "delay1500_refuse:1.31",
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as source:
        checksum = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def prepare_bundle():
    """Extract a pinned archive without links, and verify cached bytes before use."""
    require(digest(ARCHIVE) == ARCHIVE_SHA256, "The retained review archive checksum differs")
    parent = CACHE / "review" / ARCHIVE_SHA256
    bundle = parent / BUNDLE_NAME
    existing = parent.exists()
    if not existing:
        parent.mkdir(parents=True)
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            require(relative.parts and relative.parts[0] == BUNDLE_NAME
                    and not relative.is_absolute() and ".." not in relative.parts,
                    "Unexpected path in review archive")
            require(member.isfile() or member.isdir(), "Archive links and special files are not supported")
            target = parent.joinpath(*relative.parts)
            require(not target.is_symlink() and target.resolve().is_relative_to(parent.resolve()),
                    "External path in extracted review cache")
            if member.isdir():
                if not existing:
                    target.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            require(source is not None, "Missing archive member")
            with source:
                if existing:
                    expected = hashlib.sha256(source.read()).hexdigest()
                    require(target.is_file() and digest(target) == expected,
                            f"Review cache changed: {target}; remove this generated cache directory and rerun")
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as destination:
                        shutil.copyfileobj(source, destination)
    return bundle


def run(command, output, name, environment, timeout=180):
    command = [str(part) for part in command]
    (output / (name + ".command.json")).write_text(json.dumps(command, indent=2) + "\n")
    try:
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        for stream in ("stdout", "stderr"):
            content = getattr(error, stream) or ""
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            (output / (name + "." + stream + ".log")).write_text(content, encoding="utf-8")
        raise RuntimeError(f"{name} exceeded {timeout}s; see {output}") from error
    (output / (name + ".stdout.log")).write_text(result.stdout, encoding="utf-8")
    (output / (name + ".stderr.log")).write_text(result.stderr, encoding="utf-8")
    require(result.returncode == 0, f"{name} failed with exit {result.returncode}; see {output}")
    return result.stdout


def contracts(bundle, candidate, output, environment):
    run(["luac", "-p", candidate], output, "syntax", environment)
    result = json.loads(run(["lua", bundle / BOUNDARY / "tests/contracts.lua", candidate],
                            output, "contracts", environment))
    require(result["status"] == "pass" and result["total"] == 169 and result["failed"] == 0,
            "Live-source contract checks did not all pass")
    return {"status": "pass", "total": result["total"], "failed": result["failed"]}


def replay(bundle, candidate, candidate_sha, output, environment, selection="forced"):
    cases = ORDINARY_CASES if selection == "ordinary" else REPLAY_CASES
    label = "ordinary" if selection == "ordinary" else "replay"
    counts = {}
    positives = negatives = 0
    for version in ("1.30", "1.31"):
        name = label + "-" + version
        folder = output / name
        command = [sys.executable, bundle / "tests/test_netbuster_detection.py",
                   "--script", candidate, "--selection", selection, "--output", folder,
                   "--implementation", "candidate", "--cases", *cases]
        if version == "1.30":
            command += ["--positive-fixture", bundle / "tests/fixtures/real/netbuster/combined-130-default.json"]
        run(command, output, name, environment)
        result = load(folder / "report.json")
        require(result["status"] == "pass" and result["failed_cases"] == 0
                and [case["case"] for case in result["cases"]] == cases
                and all(case["status"] == "pass" for case in result["cases"]),
                f"Incomplete live {label} replay for {version}")
        require(result["script_sha256"] == candidate_sha
                and Path(result["script"]).resolve() == candidate.resolve()
                and result["positive_recorded_version"] == version, "Wrong replay source or fixture")
        require(result["selection"] == selection and result["implementation"] == "candidate",
                "Wrong replay selection or implementation")
        if selection == "ordinary":
            require(result.get("overlay_script_verified") is True,
                    "Ordinary selection did not verify the working-script overlay")
        counts[version] = len(result["cases"])
        positives += sum(case["expected_signal"] is True for case in result["cases"])
        negatives += sum(case["expected_signal"] is False for case in result["cases"])
    summary = {"status": "pass", "selection": selection, "cases": counts,
               "total": sum(counts.values()), "positive_cases": positives, "negative_cases": negatives,
               "scope": "Fresh Nmap scans of saved-response replay servers on 127.0.0.1"}
    if selection == "ordinary":
        summary["overlay_script_verified"] = True
        summary["scope"] = ("Service-based selection with -sV and only netbus-version indexed; "
                            "original service probes retained; negative service metadata checked")
    return summary


def compare(bundle, candidate, candidate_sha, output, environment):
    folder = output / "comparison"
    baseline = bundle / BOUNDARY / "tests/comparison-sources-final-guarded/baseline/netbus-version.nse"
    command = [sys.executable, bundle / BOUNDARY / "tests/compare_localhost.py",
               "--baseline", baseline, "--candidate", candidate,
               "--repetitions", "1", "--output", folder]
    for case in COMPARISON_CASES:
        command += ["--case", case]
    run(command, output, "comparison", environment, timeout=300)
    result = load(folder / "summary.json")
    require(result["status"] == "pass" and len(result["runs"]) == 28,
            "Incomplete live-source comparison")
    require(result["source_sha256"]["candidate"] == candidate_sha, "Wrong comparison candidate")
    return {"status": "pass", "conditions": len(COMPARISON_CASES), "scans": len(result["runs"]),
            "baseline_sha256": result["source_sha256"]["baseline"],
            "scope": "Fresh synthetic localhost scans; baseline is the retained local candidate, not PR #3570"}


def review(bundle, output, environment):
    folder = output / "frozen-review"
    run([sys.executable, bundle / "run_review.py", "--output", folder],
        output, "frozen-review", environment)
    result = load(folder / "review-report.json")
    require(result["status"] == "pass" and result["new_application_runs"] is False,
            "Frozen evidence verification failed")
    return {"status": "pass", "scope": "Frozen archive validation and saved measurements; not live-source coverage",
            "candidate_sha256": result["candidate_sha256"], "checks": result["checks"],
            "new_application_runs": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("contracts", "replay", "ordinary", "compare", "review", "all"),
                        default="contracts")
    parser.add_argument("--output", type=Path, help="New results directory (default: .codex-cache/results/<run>)")
    args = parser.parse_args()
    if sys.version_info < (3, 9):
        parser.error("Python 3.9 or newer is required")
    results = CACHE / "results"
    results.mkdir(parents=True, exist_ok=True)
    if args.output:
        output = args.output.resolve()
        if output.exists():
            parser.error("--output must be a new directory")
        output.mkdir(parents=True)
    else:
        prefix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + args.suite + "-"
        output = Path(tempfile.mkdtemp(prefix=prefix, dir=results))
    environment = os.environ.copy()
    environment["PATH"] = str(CACHE / "runtime/bin") + os.pathsep + environment.get("PATH", "")
    environment["NMAPDIR"] = str(ROOT)
    report = {"status": "incomplete", "at_utc": datetime.now(timezone.utc).isoformat(),
              "suite": args.suite, "python_version": sys.version.split()[0],
              "test_runner_sha256": digest(Path(__file__)),
              "new_application_runs": False, "checks": {}}
    started = time.monotonic()
    try:
        required = {"lua", "luac"}
        if args.suite in ("replay", "ordinary", "compare", "all"):
            required.add("nmap")
        for name in required:
            require(shutil.which(name, path=environment["PATH"]),
                    f"{name} is unavailable; run bash tools/codex-cloud/setup.sh first")
        stamp = CACHE / "runtime/.build-stamp.json"
        if stamp.is_file():
            build = load(stamp)
            report["runtime_build"] = {key: build[key] for key in
                                       ("source_commit", "built_at_utc", "nmap_version", "lua_version")}
        candidate = ROOT / "scripts/netbus-version.nse"
        candidate_sha = digest(candidate)
        report["source_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        report["working_script_sha256"] = candidate_sha
        report["archive_sha256"] = ARCHIVE_SHA256
        report["lua_version"] = run(["lua", "-v"], output, "lua-version", environment).strip()
        if "nmap" in required:
            report["nmap_version"] = run(["nmap", "--version"], output, "nmap-version", environment).strip()
        bundle = prepare_bundle()
        report["frozen_script_sha256"] = digest(bundle / "nse/netbus-version.nse")
        selected = ("contracts", "replay", "ordinary", "compare", "review") if args.suite == "all" else (args.suite,)
        for suite in selected:
            print(f"Running {suite} ...", flush=True)
            if suite == "contracts":
                result = contracts(bundle, candidate, output, environment)
            elif suite in ("replay", "ordinary"):
                selection = "ordinary" if suite == "ordinary" else "forced"
                result = replay(bundle, candidate, candidate_sha, output, environment, selection)
            elif suite == "compare":
                result = compare(bundle, candidate, candidate_sha, output, environment)
            else:
                result = review(bundle, output, environment)
            report["checks"][suite] = result
        require(digest(candidate) == candidate_sha, "The working NSE changed during the run")
        prepare_bundle()
        report["status"] = "pass"
    except Exception as error:
        report["status"] = "fail"
        report["error"] = str(error)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Report: {report_path}")
    return int(report["status"] != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
