#!/usr/bin/env python3
"""Exercise the scan CLI against recorded responses and a full NSE script index."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET

import test as cloud


RUNNER = cloud.ROOT / "tools/codex-cloud/scan.py"
CANDIDATE = cloud.ROOT / "scripts/netbus-version.nse"
QUERY = b"nbver\rGetInfo\r"


@contextmanager
def fixture(banner, response, mode="reply", ipv6=False):
    stopped = threading.Event()
    events = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(0.2)
            pending = b""
            queried = False
            try:
                self.request.sendall(banner)
                while not stopped.is_set():
                    try:
                        chunk = self.request.recv(4096)
                    except socket.timeout:
                        continue
                    if not chunk:
                        return
                    pending += chunk
                    if not queried:
                        if len(pending) < len(QUERY):
                            continue
                        if not pending.startswith(QUERY):
                            events.append({"unexpected_query_hex": pending.hex()})
                            return
                        pending = pending[len(QUERY):]
                        queried = True
                        events.append({"query_hex": QUERY.hex()})
                        if mode == "reply":
                            self.request.sendall(response)
                            events.append({"response_hex": response.hex()})
                            return
                    while b"\r" in pending:
                        command, _, pending = pending.partition(b"\r")
                        events.append({"query_hex": (command + b"\r").hex()})
                        if mode == "info" and command == b"GetInfo":
                            self.request.sendall(response)
                            events.append({"response_hex": response.hex()})
                            return
            except (BrokenPipeError, ConnectionResetError):
                # The TCP connect scan and service probe close before the NSE query.
                pass
            except OSError as error:
                if not stopped.is_set():
                    events.append({"error": str(error)})

    class Server(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

    address = "::1" if ipv6 else "127.0.0.1"
    with Server((address, 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        worker.start()
        try:
            yield address, server.server_address[1], events
        finally:
            stopped.set()
            server.shutdown()
            worker.join(timeout=2)


def execute(command, folder, name, environment, timeout=45):
    command = [str(value) for value in command]
    (folder / (name + ".command.json")).write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, cwd=cloud.ROOT, env=environment, capture_output=True,
                            text=True, timeout=timeout)
    (folder / (name + ".stdout.log")).write_text(result.stdout)
    (folder / (name + ".stderr.log")).write_text(result.stderr)
    return result


def recorded(bundle, path):
    data = cloud.load(bundle / "tests/fixtures/real" / path)
    return {key: bytes.fromhex(data[key + "_hex"]) for key in ("banner", "response")}


def run(output):
    bundle = cloud.prepare_bundle()
    nmap = shutil.which("nmap")
    cloud.require(nmap, "Nmap is unavailable")
    nmap = str(Path(nmap).resolve())
    environment = os.environ.copy()
    sources = {
        "positive130": recorded(bundle, "netbuster/combined-130-default.json"),
        "positive131": recorded(bundle, "netbuster/combined-default.json"),
        "info112": recorded(bundle, "netbuster/getinfo-112-default.json"),
        "negative170": recorded(bundle, "netbus/getinfo-170-complete.json"),
    }
    cases = [
        ("positive130", sources["positive130"], "reply", ["netbus", "NetBuster", "1.30", "honeypot"]),
        ("positive131", sources["positive131"], "reply", ["netbus", "NetBuster", "1.31", "honeypot"]),
        ("info112", sources["info112"], "info", ["netbus", "NetBuster", None, "honeypot"]),
        ("negative170", sources["negative170"], "reply", ["netbus", "NetBus trojan", "1.70", None]),
        ("denied", {"banner": sources["negative170"]["banner"],
                    "response": b"Info;Sorry, host is password protected.\r"}, "reply",
         ["netbus", "NetBus trojan", "1.70", None]),
        ("eof7", {"banner": sources["positive131"]["banner"],
                  "response": sources["positive131"]["response"][:7]}, "reply",
         ["netbus", "NetBus trojan", "1.60", None]),
        ("timeout", {"banner": sources["positive131"]["banner"], "response": b""}, "silent",
         ["netbus", "NetBus trojan", "1.60", None]),
    ]
    report = {"status": "incomplete", "source_sha256": cloud.digest(CANDIDATE),
              "scan_runner_sha256": cloud.digest(RUNNER), "test_sha256": cloud.digest(Path(__file__)),
              "new_application_runs": False, "cases": [], "controls": {},
              "scope": "Fresh loopback CLI scans with the unfiltered installed NSE index; recorded responses and controlled failures"}
    try:
        with tempfile.TemporaryDirectory(prefix="netbus-installed-") as temporary:
            installed = Path(temporary) / "scripts"
            installed.mkdir()
            shutil.copyfile(cloud.ROOT / "scripts/script.db", installed / "script.db")
            shutil.copyfile(bundle / "tests/fixtures/upstream/netbus-version.nse", installed / "netbus-version.nse")
            installed_hashes = {p.name: cloud.digest(p) for p in installed.iterdir()}
            report["installed_fixture_sha256"] = installed_hashes
            environment["NMAPDIR"] = temporary

            # A successful replacement must run in an environment containing an older copy.
            with fixture(**sources["negative170"]) as (host, port, events):
                command = [nmap, "--unprivileged", "-n", "-Pn", "-sT", "-sV", "--datadir", temporary,
                           "-p", port, "--script", CANDIDATE, "--script-timeout", "20s",
                           "-oX", output / "duplicate.xml", "--", host]
                result = execute(command, output, "duplicate", environment)
            duplicate = result.returncode != 0 and "duplicate script ID: 'netbus-version'" in result.stderr + result.stdout
            cloud.require(duplicate, "The external-path collision control did not reproduce")
            cloud.require(not events, "The duplicate-ID control unexpectedly reached the fixture")
            report["controls"]["external_path_collision_reproduced"] = True

            ipv6_available = True
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                    probe.bind(("::1", 0))
            except OSError as error:
                ipv6_available = False
                report["ipv6_skipped"] = str(error)
            inventory = [(case, False) for case in cases]
            if ipv6_available:
                inventory += [(cases[1], True), (cases[3], True)]
            for (name, data, mode, expected), ipv6 in inventory:
                name += "-ipv6" if ipv6 else "-ipv4"
                folder = output / name
                with fixture(**data, mode=mode, ipv6=ipv6) as (host, port, events):
                    command = [sys.executable, RUNNER, "--nmap", nmap, "--output", folder, "-p", port]
                    if ipv6:
                        command.append("-6")
                    command.append(host)
                    result = execute(command, output, name, environment)
                cloud.require(result.returncode == 0, f"{name}: scan CLI failed; see its logs")
                scan = cloud.load(folder / "report.json")
                cloud.require(scan["status"] == "pass" and scan["scan_completed"], f"{name}: incomplete scan")
                cloud.require(scan["working_script_sha256"] == report["source_sha256"]
                              and scan["overlay_script_verified"] is True, f"{name}: wrong candidate")
                cloud.require(scan["script_db_sha256"] == installed_hashes["script.db"], f"{name}: index was filtered")
                cloud.require(scan["version_script_count"] > 1, f"{name}: full version collection was not selected")
                loaded = re.search(r"NSE: Loaded (\d+) scripts for scanning\.",
                                   (folder / "scan.stdout.log").read_text())
                cloud.require(loaded is not None and int(loaded[1]) == scan["version_script_count"],
                              f"{name}: actual scan did not load the preflight version collection")
                xml = ET.parse(folder / "scan.xml").getroot()
                service = xml.find(f"./host/ports/port[@portid='{port}']/service")
                cloud.require(service is not None, f"{name}: no service result")
                actual = [service.get(key) for key in ("name", "product", "version", "extrainfo")]
                cloud.require(actual == expected, f"{name}: wrong service metadata {actual}")
                cloud.require(any(event.get("query_hex") == QUERY.hex() for event in events), f"{name}: no NSE query")
                cloud.require(not any("error" in event or "unexpected_query_hex" in event for event in events),
                              f"{name}: fixture error")
                report["cases"].append({"case": name, "status": "pass", "service": dict(service.attrib),
                                        "version_script_count": scan["version_script_count"], "fixture_events": events})
                print(name + ": pass", flush=True)

            for name, arguments in (("invalid-port", ["-p", "0", "127.0.0.1"]),
                                    ("option-target", ["--", "--script=all"])):
                result = execute([sys.executable, RUNNER, "--output", output / name, *arguments],
                                 output, name, environment)
                cloud.require(result.returncode != 0 and not (output / name).exists(), f"{name}: input was accepted")
                report["controls"][name] = "rejected before scanning"
            prior = output / "positive130-ipv4/report.json"
            original_hash = cloud.digest(prior)
            result = execute([sys.executable, RUNNER, "--output", prior.parent, "127.0.0.1"],
                             output, "existing-output", environment)
            cloud.require(result.returncode != 0 and cloud.digest(prior) == original_hash, "Existing results were overwritten")
            report["controls"]["existing_output_preserved"] = True

            shim = output / "incomplete-nmap"
            shim.write_text("#!" + sys.executable + "\nimport os, pathlib, sys\n"
                            "args = sys.argv[1:]\n"
                            "if '--script-help' in args or '--version' in args:\n"
                            "    os.execv(" + repr(nmap) + ", [" + repr(nmap) + ", *args])\n"
                            "pathlib.Path(args[args.index('-oX') + 1]).write_text('<nmaprun/>')\n")
            shim.chmod(0o755)
            folder = output / "incomplete-xml"
            result = execute([sys.executable, RUNNER, "--nmap", shim, "--output", folder, "127.0.0.1"],
                             output, "incomplete-xml", environment)
            incomplete = cloud.load(folder / "report.json")
            cloud.require(result.returncode != 0 and incomplete["status"] == "fail"
                          and incomplete["scan_completed"] is False, "Incomplete XML reported success")
            report["controls"]["incomplete_xml_rejected"] = True

            # NSE failures can coexist with exit 0 and successful runstats in Nmap.
            # Exercise the runner with temporary faulty sources, not its real candidate.
            override = ("import importlib.util, pathlib, sys\n"
                        "runner, candidate, *args = sys.argv[1:]\n"
                        "spec = importlib.util.spec_from_file_location('scan_control', runner)\n"
                        "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
                        "module.CANDIDATE = pathlib.Path(candidate)\n"
                        "sys.argv = [runner, *args]\n"
                        "raise SystemExit(module.main())\n")
            short_timeout = output / "short-timeout-nmap"
            short_timeout.write_text("#!" + sys.executable + "\nimport json, os, pathlib, sys\n"
                                     "args = sys.argv[1:]\n"
                                     "if '--script-timeout' in args:\n"
                                     "    args[args.index('--script-timeout') + 1] = '1s'\n"
                                     "    pathlib.Path(" + repr(str(output / "timeout-actual.command.json"))
                                     + ").write_text(json.dumps([" + repr(nmap) + ", *args], indent=2))\n"
                                     "os.execv(" + repr(nmap) + ", [" + repr(nmap) + ", *args])\n")
            short_timeout.chmod(0o755)
            for name, action, executable in (
                    ("action-error", 'error("deliberate integration failure")', nmap),
                    ("action-timeout", 'stdnse.sleep(30)', str(short_timeout))):
                source_folder = output / (name + "-source")
                source_folder.mkdir()
                mutant = source_folder / "netbus-version.nse"
                mutant.write_text(CANDIDATE.read_text() + "\naction = function() " + action + " end\n")
                folder = output / name
                with fixture(**sources["positive131"]) as (host, port, events):
                    command = [sys.executable, "-c", override, RUNNER, mutant, "--nmap", executable,
                               "--output", folder, "-p", port, host]
                    result = execute(command, output, name, environment)
                fault = cloud.load(folder / "report.json")
                cloud.require(result.returncode != 0 and fault["status"] == "fail"
                              and fault["nmap_exit_code"] == 0 and fault["scan_completed"] is False,
                              f"{name}: NSE failure was not distinguished from successful Nmap exit")
                report["controls"][name + "_rejected"] = True
            cloud.require({p.name: cloud.digest(p) for p in installed.iterdir()} == installed_hashes,
                          "Installed script or database was modified")
            report["controls"]["installation_unchanged"] = True
        cloud.require(cloud.digest(CANDIDATE) == report["source_sha256"], "Candidate changed during scan tests")
        cloud.require(cloud.digest(RUNNER) == report["scan_runner_sha256"], "Scan runner changed during scan tests")
        report["status"] = "pass"
    except Exception as error:
        report["status"] = "fail"
        report["error"] = str(error)
    report["scans"] = len(report["cases"])
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("--output must be a new directory")
    output.mkdir(parents=True)
    report = run(output)
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}, indent=2))
    return int(report["status"] != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
