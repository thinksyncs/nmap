#!/usr/bin/env python3
"""Reproduce the frozen HTTP camouflage baseline on IPv4 loopback.

Exit 0 means that the OFF/ON/OFF classification experiment reproduced the
baseline, including its known HTTP OPTIONS incompatibility. It does not mean
that the fixture is suitable for production or that attacks were deterred.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_SHA256 = "a9a6d80faf6fc4093175ae9432b2ce74e1da031adbd251a6c778c1476fcd02f4"
FIXTURE_SHA256 = "dfb695260ca1ce22716a4a6f33dc7908daa9fabc9759effd9b7d0e2b9834ccfa"
PROBES_SHA256 = "57cc029b3610a55124e35bf1cb4830010ecf19d678298bafbee2ed8482bb4239"
PORT = 8081
REQUESTS = (
    ("root", "GET", "/", 200, b"Example application is running.\n"),
    ("health", "GET", "/health", 200, b"ok\n"),
    ("head", "HEAD", "/", 200, b""),
    ("missing", "GET", "/missing", 404, b"not found\n"),
    ("options", "OPTIONS", "/", None, b""),
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def extract_fixture(archive, output):
    require(digest(archive) == ARCHIVE_SHA256, "Frozen source ZIP checksum differs")
    source = output / "source"
    source.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        require(sum(item.file_size for item in entries) <= 20 * 1024 * 1024,
                "Source ZIP exceeds extraction bound")
        paths = set()
        for item in entries:
            path = PurePosixPath(item.filename)
            require(not path.is_absolute() and ".." not in path.parts
                    and path.parts and path.parts[0] == "honeypot-signals"
                    and "\\" not in item.filename,
                    "Unsafe source ZIP member")
            require(item.filename not in paths, "Duplicate source ZIP member")
            paths.add(item.filename)
            require(not stat.S_ISLNK(item.external_attr >> 16), "ZIP symlink rejected")
            target = source.joinpath(*path.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(bundle.read(item))
    project = source / "honeypot-signals"
    for line in (project / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        relative = relative.lstrip("*")
        path = (project / relative).resolve()
        require(path.is_relative_to(project.resolve()), "Unsafe checksum manifest path")
        require(digest(path) == expected, f"Frozen manifest mismatch: {relative}")
    fixture = project / "examples" / "camouflage_lab.py"
    require(digest(fixture) == FIXTURE_SHA256, "Frozen fixture checksum differs")
    spec = importlib.util.spec_from_file_location("frozen_camouflage_lab", fixture)
    require(spec is not None and spec.loader is not None, "Cannot load frozen fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, fixture


def runtime_hashes(nmap, data, archive, fixture):
    paths = {"nmap": nmap, "probe_database": data / "nmap-service-probes",
             "script_index": data / "scripts" / "script.db",
             "source_archive": archive, "fixture": fixture}
    return {name: {"path": str(path), "sha256": digest(path)}
            for name, path in paths.items()}


def request_record(method, path):
    request = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
               "Connection: close\r\n\r\n").encode("ascii")
    with socket.create_connection(("127.0.0.1", PORT), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall(request)
        chunks = []
        size = 0
        while True:
            data = connection.recv(4096)
            if not data:
                break
            chunks.append(data)
            size += len(data)
            require(size <= 65536, "HTTP response exceeds capture bound")
    raw = b"".join(chunks)
    head, separator, body = raw.partition(b"\r\n\r\n")
    require(separator, "Incomplete HTTP headers")
    lines = head.split(b"\r\n")
    status = re.fullmatch(rb"HTTP/(1\.[01]) ([0-9]{3}) [^\r\n]*", lines[0])
    require(status is not None, "Invalid HTTP status line")
    headers = []
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        require(separator, "Invalid HTTP header")
        headers.append([name.decode("ascii"), value.strip().decode("latin-1")])
    content_lengths = [value for name, value in headers if name.lower() == "content-length"]
    require(len(content_lengths) == 1 and content_lengths[0].isdigit(),
            "Missing or ambiguous HTTP content length")
    length = int(content_lengths[0])
    require((method == "HEAD" and not body) or (method != "HEAD" and length == len(body)),
            "Incomplete HTTP response body")
    return {"method": method, "path": path, "status": int(status[2]),
            "http_version": status[1].decode("ascii"), "headers": headers,
            "body_base64": base64.b64encode(body).decode("ascii"),
            "request_base64": base64.b64encode(request).decode("ascii"),
            "response_base64": base64.b64encode(raw).decode("ascii"),
            "response_text": raw.decode("latin-1")}


def application_checks(profile):
    records = {}
    for name, method, path, expected_status, expected_body in REQUESTS:
        record = request_record(method, path)
        if name == "options":
            expected_status = 200 if profile == "dionaea-legacy" else 204
        require(record["status"] == expected_status, f"Unexpected {name} HTTP status")
        require(base64.b64decode(record["body_base64"]) == expected_body,
                f"Unexpected {name} HTTP body")
        if method == "HEAD":
            require([value for key, value in record["headers"] if key.lower() == "content-length"]
                    == ["32"], "HEAD no longer describes the GET body")
        records[name] = record
    return records


def parse_scan(xml_path, stdout, stderr, returncode):
    require(returncode == 0, f"Nmap exited with status {returncode}")
    document = ET.parse(xml_path).getroot()
    require(document.tag == "nmaprun", "Unexpected XML document")
    finished = document.find("runstats/finished")
    require(finished is not None and finished.get("exit") == "success", "Incomplete Nmap run")
    hosts = document.findall("host")
    require(len(hosts) == 1, "Unexpected host inventory")
    host = hosts[0]
    require(host.find("status") is not None and host.find("status").get("state") == "up",
            "Loopback target was not reported up")
    require(any(address.get("addr") == "127.0.0.1" for address in host.findall("address")),
            "Wrong target in XML")
    ports = host.findall("ports/port")
    require(len(ports) == 1 and ports[0].get("portid") == str(PORT)
            and ports[0].get("protocol") == "tcp", "Wrong port inventory")
    port = ports[0]
    require(port.find("state") is not None and port.find("state").get("state") == "open",
            "HTTP port was not open")
    service = port.find("service")
    require(service is not None and service.get("method") in ("probed", "table"),
            "Missing service result")
    lines = (stdout + "\n" + stderr).splitlines()
    diagnostics = [line for line in lines if re.search(
        r"^NSE:.*(?:threw an error!|timed out\b|yielded unexpectedly\b|failed to initialize)", line)]
    diagnostics += [script.get("output", "") for script in document.findall(".//script")
                    if re.search(r"(?:^|\n)ERROR:", script.get("output", ""))]
    require(not diagnostics, "NSE execution failure: " + "; ".join(diagnostics))
    return {"service": dict(service.attrib),
            "service_identity": {key: value for key, value in service.attrib.items()
                                 if key != "servicefp"},
            "service_result_kind": "fingerprint_match" if service.get("method") == "probed"
                                   else "port_table_fallback_not_product_identification",
            "nse_execution_errors": diagnostics,
            "sent_probes": [line for line in lines if "Service scan sending probe" in line],
            "hard_matches": [line for line in lines if "Service scan hard match" in line],
            "soft_matches": [line for line in lines if "Service scan soft match" in line]}


def run_case(module, nmap, data, env, output, name, profile, timeout):
    case_dir = output / name
    case_dir.mkdir()
    command = [str(nmap), "--datadir", str(data), "--unprivileged", "-sT", "-Pn", "-n",
               "-sV", "--version-intensity", "7", "--version-trace", "-d1",
               "-p", str(PORT), "-oA", str(case_dir / "scan"), "127.0.0.1"]
    result = {"name": name, "profile": profile, "command": command,
              "target": "127.0.0.1", "port": PORT, "status": "fail"}
    start = time.monotonic()
    try:
        # Binding is the ownership check. A pre-existing listener fails here;
        # this runner never terminates unrelated processes or changes ports.
        with module.LabServer(profile, PORT) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result["application_before"] = application_checks(profile)
                with (case_dir / "stdout.log").open("wb") as stdout_file, \
                     (case_dir / "stderr.log").open("wb") as stderr_file:
                    completed = subprocess.run(command, cwd=case_dir, env=env,
                                               stdout=stdout_file, stderr=stderr_file,
                                               timeout=timeout, check=False)
                result["exit_code"] = completed.returncode
                result["application_after"] = application_checks(profile)
                result["application_stable"] = result["application_before"] == result["application_after"]
                require(result["application_stable"], "Application responses changed during the scan")
                stdout = (case_dir / "stdout.log").read_text(errors="replace")
                stderr = (case_dir / "stderr.log").read_text(errors="replace")
                result.update(parse_scan(case_dir / "scan.xml", stdout, stderr, completed.returncode))
                service = result["service"]
                if profile == "dionaea-legacy":
                    require(service.get("name") == "honeypot"
                            and service.get("product") == "Dionaea Honeypot httpd"
                            and service.get("method") == "probed",
                            "Camouflage did not induce the expected Dionaea identification")
                    require(any("Probe SIPOptions matched with SIPOptions" in line
                                for line in result["hard_matches"]), "No SIPOptions hard-match evidence")
                else:
                    # A completed negative control means no honeypot label. A
                    # port-table fallback is not an HTTP/product identification.
                    require(any("sending probe GetRequest " in line for line in result["sent_probes"])
                            and any("sending probe SIPOptions " in line for line in result["sent_probes"]),
                            "Baseline did not exercise the relevant service probes")
                    require("honeypot" not in json.dumps(result["service_identity"]).lower()
                            and "dionaea" not in json.dumps(result["service_identity"]).lower(),
                            "Unmodified baseline unexpectedly identified as a honeypot")
                result["status"] = "pass"
            finally:
                server.shutdown()
                thread.join(timeout=3)
    except (OSError, RuntimeError, ValueError, ET.ParseError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    result["elapsed_seconds"] = round(time.monotonic() - start, 3)
    write_json(case_dir / "result.json", result)
    print(f"{name}: {result['status']} ({result['elapsed_seconds']}s)", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nmap", type=Path, default=ROOT / ".codex-cache/runtime/bin/nmap")
    parser.add_argument("--data-dir", type=Path,
                        help="Complete matching Nmap data directory; defaults to runtime/share/nmap")
    parser.add_argument("--archive", type=Path,
                        default=ROOT / "review/honeypot-signals-v0.1.0/honeypot-signals-v0.1.0.zip")
    parser.add_argument("--output", type=Path,
                        default=ROOT / ".codex-cache" / ("camouflage-baseline-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    parser.add_argument("--timeout", type=float, default=180,
                        help="Maximum seconds for each Nmap process (default: 180)")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be 1..600 seconds")
    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        parser.error(f"A fresh output directory is required: {error}")
    report = {"schema_version": 1, "purpose": "frozen_baseline_reproduction_only",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "reproduction_status": "fail", "production_readiness": "not_established",
              "deterrence": "not_tested", "cases": []}
    try:
        nmap = args.nmap.resolve(strict=True)
        data = (args.data_dir or nmap.parent.parent / "share/nmap").resolve(strict=True)
        archive = args.archive.resolve(strict=True)
        module, fixture = extract_fixture(archive, output)
        env = os.environ.copy()
        env.pop("NMAP_PRIVILEGED", None)
        env["NMAPDIR"] = str(data)
        env["TZ"] = "UTC"
        report["environment"] = {"NMAPDIR": str(data), "TZ": "UTC"}
        report["hashes_before"] = runtime_hashes(nmap, data, archive, fixture)
        require(report["hashes_before"]["probe_database"]["sha256"] == PROBES_SHA256,
                "Probe database differs from the fixed Cloud baseline")
        version = subprocess.run([str(nmap), "--version"], capture_output=True, text=True,
                                 env=env, timeout=10, check=True)
        report["nmap_version"] = version.stdout
        (output / "nmap-version.txt").write_text(version.stdout + version.stderr)
        for name, profile in [("off-before", "normal"), ("on", "dionaea-legacy"), ("off-after", "normal")]:
            report["cases"].append(run_case(module, nmap, data, env, output,
                                            name, profile, args.timeout))
            write_json(output / "summary.json", report)
        report["hashes_after"] = runtime_hashes(nmap, data, archive, fixture)
        report["inputs_unchanged"] = report["hashes_before"] == report["hashes_after"]
        require(report["inputs_unchanged"], "Fixed experiment inputs changed")
        require(all(case["status"] == "pass" for case in report["cases"]),
                "At least one classification experiment failed; inspect per-case evidence")
        before, on, after = report["cases"]
        report["disable_restores_baseline"] = (
            before["application_before"] == after["application_after"]
            and before["service_identity"] == after["service_identity"])
        require(report["disable_restores_baseline"], "Disabling camouflage did not restore baseline")
        differences = [name for name, *_ in REQUESTS
                       if before["application_before"][name] != on["application_before"][name]]
        report["off_on_http_compatibility"] = {
            "status": "fail" if differences else "pass", "differing_requests": differences,
            "scope": "GET /, GET /health, HEAD /, GET /missing, HTTP OPTIONS /",
            "known_limitation": "The legacy profile changes valid HTTP OPTIONS as well as SIPOptions; authentication, stateful writes, CORS and production frontends are not covered."}
        require(differences == ["options"], "Unexpected compatibility change beyond legacy OPTIONS")
        report["reproduction_status"] = "pass"
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        report["error"] = str(error)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_json(output / "summary.json", report)
    print(json.dumps({"reproduction_status": report["reproduction_status"],
                      "off_on_http_compatibility": report.get("off_on_http_compatibility", {}).get("status", "not_evaluated"),
                      "summary": str(output / "summary.json"), "error": report.get("error")}, indent=2))
    return 0 if report["reproduction_status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
