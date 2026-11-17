#!/usr/bin/env python3
"""Run the working NetBus detector without replacing installed Nmap files."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "scripts/netbus-version.nse"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ports(value):
    for item in value.split(","):
        if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", item):
            raise argparse.ArgumentTypeError("ports must be TCP numbers or ranges, such as 12345 or 12345-12346")
        bounds = [int(number) for number in item.split("-")]
        if not all(1 <= number <= 65535 for number in bounds) or bounds[0] > bounds[-1]:
            raise argparse.ArgumentTypeError("port numbers must be 1 through 65535, with ascending ranges")
    return value


def target(value):
    if not value or value.startswith("-") or any(character.isspace() or ord(character) < 32 for character in value):
        raise argparse.ArgumentTypeError("targets must be nonempty Nmap target expressions, without leading '-' or whitespace")
    return value


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def execute(command, output, name, timeout=30, report=None):
    (output / (name + ".command.json")).write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
    with (output / (name + ".stdout.log")).open("wb") as stdout:
        with (output / (name + ".stderr.log")).open("wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            try:
                return process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                stop(process)
                raise RuntimeError(f"{name} exceeded {timeout}s") from error
            except KeyboardInterrupt:
                stop(process)
                raise
            finally:
                if report is not None:
                    report["nmap_exit_code"] = process.poll()


def help_scripts(command, output, name):
    require(execute(command, output, name) == 0, f"{name} failed; see {name}.stderr.log")
    document = ET.parse(output / (name + ".stdout.log")).getroot()
    require(document.tag == "nse-scripts", f"{name} did not return Nmap script-help XML")
    # Keep the selected directory when an installed script is a symlink: its
    # script.db belongs beside that installed name, not beside the link target.
    selected = [Path(script.attrib["filename"]).absolute() for script in document.findall("script")]
    require(all(path.is_file() for path in selected), f"{name} selected an unavailable script")
    return selected


def script_failures(output):
    failures = []
    pattern = re.compile(r"^NSE:\s+netbus-version(?:\s+against\s+.+)?\s+"
                         r"(?:threw an error!|timed out\b|yielded unexpectedly\b)")
    for name in ("scan.stdout.log", "scan.stderr.log"):
        for line in (output / name).read_text(encoding="utf-8", errors="replace").splitlines():
            if pattern.match(line):
                failures.append(line)
    return failures


def read_scan(path):
    document = ET.parse(path).getroot()
    require(document.tag == "nmaprun", "Scan output is not Nmap XML")
    finished = document.find("./runstats/finished")
    hosts = document.find("./runstats/hosts")
    require(finished is not None and finished.get("exit") == "success", "Nmap XML does not record successful completion")
    require(hosts is not None and int(hosts.get("total", "0")) > 0, "Nmap scanned no hosts; check target resolution")
    errors = [script.get("output", "") for script in document.findall(".//script")
              if script.get("id") == "netbus-version" and script.get("output", "").lstrip().startswith("ERROR:")]
    require(not errors, "netbus-version reported an NSE execution error; see scan.xml")
    services = []
    for host in document.findall("host"):
        addresses = [dict(address.attrib) for address in host.findall("address")]
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            services.append({"addresses": addresses, "port": int(port.attrib["portid"]),
                             "protocol": port.get("protocol"),
                             "state": state.get("state") if state is not None else None,
                             "service": dict(service.attrib) if service is not None else {}})
    return services


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", type=target, help="Nmap host, address, or network expressions")
    parser.add_argument("-p", "--ports", type=ports, default="12345", help="TCP port list or ranges (default: 12345)")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Use IPv6")
    parser.add_argument("--nmap", help="Nmap executable (default: Cloud runtime, then PATH)")
    parser.add_argument("--output", type=Path, help="New results directory (default: .codex-cache/scans/<run>)")
    args = parser.parse_args()
    if sys.version_info < (3, 9):
        parser.error("Python 3.9 or newer is required")
    try:
        if args.output:
            output = args.output.resolve()
            output.mkdir(parents=True, exist_ok=False)
        else:
            parent = ROOT / ".codex-cache/scans"
            parent.mkdir(parents=True, exist_ok=True)
            prefix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
            output = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    except OSError as error:
        parser.error(f"Cannot create a fresh output directory: {error}")
    report = {"schema_version": 1, "status": "fail", "at_utc": datetime.now(timezone.utc).isoformat(),
              "targets": args.targets, "ports": args.ports, "ipv6": args.ipv6,
              "source_script": str(CANDIDATE), "overlay_script_verified": False,
              "nmap_exit_code": None, "scan_completed": False, "nse_diagnostics": [], "services": []}
    started = time.monotonic()
    exit_code = 1
    try:
        local_nmap = ROOT / ".codex-cache/runtime/bin/nmap"
        executable = args.nmap or (str(local_nmap) if local_nmap.is_file() else "nmap")
        resolved = shutil.which(executable)
        require(resolved is not None, "Nmap is unavailable; use --nmap or prepare the Cloud runtime")
        nmap = str(Path(resolved).resolve())
        report["nmap_executable"] = nmap
        require(execute([nmap, "--version"], output, "nmap-version") == 0, "Nmap version check failed")
        report["nmap_version"] = (output / "nmap-version.stdout.log").read_text(encoding="utf-8", errors="replace").strip()
        source = CANDIDATE.read_bytes()
        report["working_script_sha256"] = digest(source)
        installed = help_scripts([nmap, "--script-help", "netbus-version", "-oX", "-"], output, "discovery")
        require(len(installed) == 1 and installed[0].name == "netbus-version.nse",
                "Expected exactly one installed netbus-version script")
        report["installed_script"] = str(installed[0])
        database_path = installed[0].parent / "script.db"
        database = database_path.read_bytes()
        entries = re.findall(r"\bfilename\s*=\s*[\"']netbus-version\.nse[\"']", database.decode("utf-8"))
        require(len(entries) == 1, "Expected exactly one netbus-version entry in the installed script.db")
        report["script_db"] = str(database_path)
        report["script_db_sha256"] = digest(database)
        with tempfile.TemporaryDirectory(prefix="netbus-overlay-") as temporary:
            overlay = Path(temporary).resolve()
            scripts = overlay / "scripts"
            scripts.mkdir()
            selected_script = scripts / "netbus-version.nse"
            selected_script.write_bytes(source)
            (scripts / "script.db").write_bytes(database)
            require((scripts / "script.db").read_bytes() == database, "Overlay script.db differs from the full installed database")
            selected = help_scripts([nmap, "--datadir", str(overlay), "--script-help",
                                     "version or netbus-version", "-oX", "-"], output, "overlay-selection")
            netbus = [path for path in selected if path.name == "netbus-version.nse"]
            require(netbus == [selected_script] and digest(selected_script.read_bytes()) == report["working_script_sha256"],
                    "Nmap did not select the expected working-script overlay")
            report["overlay_script_verified"] = True
            report["version_script_count"] = len(selected)
            report["version_scripts"] = [path.stem for path in selected]
            # Nmap can exit 0 after a script timeout or exception. Level-one
            # diagnostics expose those failures; they stay in the saved logs.
            command = [nmap, "--unprivileged", "-n", "-Pn", "-sT", "-sV", "-d1", "--version-intensity", "7",
                       "--datadir", str(overlay), "--script", "netbus-version", "--script-timeout", "20s",
                       "-p", args.ports, "-oX", str(output / "scan.xml")]
            if args.ipv6:
                command.append("-6")
            command += ["--", *args.targets]
            report["command"] = command
            returncode = execute(command, output, "scan", timeout=None, report=report)
            report["nse_diagnostics"] = script_failures(output)
            require(returncode == 0, f"Nmap exited with status {returncode}; see scan.stderr.log")
            require(not report["nse_diagnostics"], "netbus-version did not complete successfully; see nse_diagnostics and scan logs")
            report["services"] = read_scan(output / "scan.xml")
            report["scan_completed"] = True
            report["status"] = "pass"
            exit_code = 0
    except KeyboardInterrupt:
        report["error"] = "Interrupted by user"
        exit_code = 130
    except Exception as error:
        report["error"] = str(error)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["exit_code"] = exit_code
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {output / 'report.json'}")
    if exit_code:
        print(report.get("error", "Scan did not complete"), file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
