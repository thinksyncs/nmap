#!/usr/bin/env python3
"""Check the Lua camouflage adapter against a stateful HTTP application.

Only loopback port 8081 is scanned. A successful test run includes an expected
negative efficacy result for a recognizable BaseHTTP frontend. Neither that
result nor a detector failure is reported as successful camouflage.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "camouflage"))
from adapter import AdapterServer  # noqa: E402
from reference_app import ReferenceServer  # noqa: E402
from test_camouflage import PROBES_SHA256, parse_scan  # noqa: E402

PORT = 8081
ORIGIN = "https://client.example.test"
STREAM = bytes(range(256)) * 1024
SIP = (b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\n"
       b"From: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\n"
       b"Call-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\n"
       b"Content-Length: 0\r\nContact: <sip:nm@nm>\r\n"
       b"Accept: application/sdp\r\n\r\n")
SIGNAL = (b"HTTP/1.0 200 OK\r\nAllow: OPTIONS, GET, HEAD, POST\r\n"
          b"Content-Length: 0\r\nConnection: close\r\n\r\n")
STATE = {"message": "retained-日本語", "items": [1, 2, 3]}
SOURCE_FILES = [
    "camouflage/adapter.py", "camouflage/reference_app.py",
    "camouflage/lua/dionaea_sip.lua", "camouflage/lua/decide.lua",
    "camouflage/tests/test_profile.lua",
    "tools/codex-cloud/test_http_camouflage.py",
    "tools/codex-cloud/test_camouflage.py",
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def snapshot(nmap, lua, data):
    paths = {name: ROOT / name for name in SOURCE_FILES}
    paths.update(nmap=nmap, lua=lua, probe_database=data / "nmap-service-probes",
                 script_index=data / "scripts/script.db")
    return {key: {"path": str(path), "sha256": digest(path.read_bytes())}
            for key, path in paths.items()}


def bytes_record(data, directory, name):
    record = {"bytes": len(data), "sha256": digest(data)}
    if len(data) <= 4096:
        record["base64"] = base64.b64encode(data).decode("ascii")
    else:
        path = directory / (name + ".bin")
        path.write_bytes(data)
        record["file"] = path.name
    return record


def normalized_headers(headers):
    result = []
    for name, value in headers:
        key = name.lower()
        if key == "date":
            value = "<date>"
        elif key == "set-cookie":
            cookie = SimpleCookie()
            cookie.load(value)
            require(set(cookie) == {"session"}, "Unexpected session cookie schema")
            prefix, separator, attributes = value.partition(";")
            require(separator and prefix.startswith("session="), "Malformed session cookie")
            value = "session=<opaque>;" + attributes
        result.append([key, value])
    return result


def exchange(request, *, chunks=None, half_close=False, timeout=5):
    with socket.create_connection(("127.0.0.1", PORT), timeout=timeout) as connection:
        connection.settimeout(timeout)
        if chunks:
            offset = 0
            for size in chunks:
                connection.sendall(request[offset:offset + size])
                offset += size
                time.sleep(0.02)
            connection.sendall(request[offset:])
        else:
            connection.sendall(request)
        if half_close:
            connection.shutdown(socket.SHUT_WR)
        data = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= 2 * 1024 * 1024, "Raw response exceeds test bound")
        return bytes(data)


def parse_raw_responses(data):
    responses = []
    while data:
        header, separator, data = data.partition(b"\r\n\r\n")
        require(separator, "Incomplete raw response headers")
        lines = header.split(b"\r\n")
        words = lines[0].split(b" ", 2)
        require(len(words) == 3 and words[0] in (b"HTTP/1.0", b"HTTP/1.1"),
                "Invalid raw HTTP status")
        headers = []
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            require(separator, "Invalid raw response header")
            headers.append((name.decode("ascii"), value.strip().decode("latin1")))
        lengths = [value for name, value in headers if name.lower() == "content-length"]
        status = int(words[1])
        if status == 204 or 100 <= status < 200:
            require(not lengths, "Bodyless response must not add Content-Length")
            length = 0
        else:
            require(len(lengths) == 1 and lengths[0].isdigit(), "Raw control needs one Content-Length")
            length = int(lengths[0])
        require(len(data) >= length, "Truncated raw response body")
        body, data = data[:length], data[length:]
        responses.append({"version": words[0].decode(), "status": status,
                          "headers": normalized_headers(headers),
                          "body_bytes": len(body), "body_sha256": digest(body)})
    return responses


def application_checks(directory, phase, initial_value):
    output = directory / phase
    output.mkdir()
    records = []
    canonical = []
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)

    def request(name, method, path, *, body=None, headers=None, status=200,
                expected=None, fresh=False):
        client = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5) if fresh else connection
        raw_body = body if isinstance(body, bytes) else (
            json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
            if body is not None else b"")
        request_headers = dict(headers or {})
        if body is not None and not isinstance(body, bytes):
            request_headers.setdefault("Content-Type", "application/json")
        try:
            client.request(method, path, body=raw_body, headers=request_headers)
            response = client.getresponse()
            response_headers = response.getheaders()
            response_body = response.read()
            record = {"name": name, "method": method, "path": path,
                      "request_headers": request_headers,
                      "request_body": bytes_record(raw_body, output, name + "-request"),
                      "status": response.status, "version": response.version,
                      "response_headers": response_headers,
                      "response_body": bytes_record(response_body, output, name + "-response")}
            records.append(record)
            require(response.status == status, f"{name}: expected {status}, got {response.status}")
            require(sum(key.lower() == "date" for key, _ in response_headers) == 1,
                    f"{name}: application response must retain a Date header")
            if expected is not None:
                require(response_body == expected, f"{name}: response bytes changed")
            canonical.append({"name": name, "status": response.status,
                              "version": response.version,
                              "headers": normalized_headers(response_headers),
                              "body_bytes": len(response_body),
                              "body_sha256": digest(response_body)})
            return response_body, dict((key.lower(), value) for key, value in response_headers)
        finally:
            if fresh:
                client.close()

    def json_state(name, *, method="GET", value=None, cookie=None, origin=None, status=200):
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if origin:
            headers["Origin"] = origin
        body, response_headers = request(name, method, "/state", headers=headers,
                                         body={"value": value} if method == "PUT" else None,
                                         status=status)
        return (json.loads(body) if status == 200 else body), response_headers

    try:
        request("root", "GET", "/", expected=b"Reference application is running.\n")
        request("health", "GET", "/health", expected=b"ok\n")
        _, head_headers = request("head", "HEAD", "/", expected=b"")
        require(head_headers.get("content-length") == "34", "HEAD does not describe root GET")
        request("missing", "GET", "/missing", status=404)
        request("error", "GET", "/error", status=500)
        json_state("unauthenticated_read", status=401)
        json_state("unauthenticated_write", method="PUT", value="forbidden", status=401)
        request("bad_login", "POST", "/login", body={"username": "alice", "password": "wrong"}, status=401)
        _, headers = request("login", "POST", "/login",
                             body={"username": "alice", "password": "local-test-password"})
        parsed = SimpleCookie()
        parsed.load(headers.get("set-cookie", ""))
        require("session" in parsed and bool(parsed["session"].value), "Login omitted session")
        require(bool(parsed["session"]["httponly"])
                and parsed["session"]["samesite"].lower() == "lax"
                and parsed["session"]["path"] == "/", "Session cookie attributes changed")
        cookie = "session=" + parsed["session"].value
        state, _ = json_state("initial_authenticated_read", cookie=cookie)
        require(state == {"value": initial_value}, "Initial or scan-retained state changed")
        state, _ = json_state("authenticated_write", method="PUT", value=STATE, cookie=cookie)
        require(state == {"value": STATE}, "Write did not return stored value")
        state, _ = json_state("authenticated_read", cookie=cookie)
        require(state == {"value": STATE}, "Read did not observe authenticated write")
        _, headers = request("cors_preflight", "OPTIONS", "/state", status=204, fresh=True,
                             headers={"Origin": ORIGIN, "Access-Control-Request-Method": "PUT",
                                      "Access-Control-Request-Headers": "Content-Type"}, expected=b"")
        require(headers.get("access-control-allow-origin") == ORIGIN
                and headers.get("access-control-allow-credentials") == "true"
                and "PUT" in headers.get("access-control-allow-methods", "")
                and "content-type" in headers.get("access-control-allow-headers", "").lower()
                and "origin" in headers.get("vary", "").lower(), "CORS preflight contract changed")
        _, headers = request("cors_denied", "OPTIONS", "/state", status=403, fresh=True,
                             headers={"Origin": "https://denied.example.test",
                                      "Access-Control-Request-Method": "PUT"})
        require("access-control-allow-origin" not in headers, "Rejected origin was authorized")
        json_state("cors_write_denied", method="PUT", value="forbidden-origin", cookie=cookie,
                   origin="https://denied.example.test", status=403)
        state, headers = json_state("cors_allowed_read", cookie=cookie, origin=ORIGIN)
        require(state == {"value": STATE} and headers.get("access-control-allow-origin") == ORIGIN,
                "Denied origin changed state or allowed read lost CORS")
        request("http_options", "OPTIONS", "/", status=204, fresh=True, expected=b"")
        echo = b"body-prefix\x00\xff\n" + SIP + bytes(range(256)) * 1024
        request("binary_echo", "POST", "/echo", body=echo,
                headers={"Cookie": cookie, "Content-Type": "application/octet-stream"},
                expected=echo, fresh=True)
        _, headers = request("chunked_stream", "GET", "/stream", expected=STREAM, fresh=True)
        require(headers.get("transfer-encoding") == "chunked", "HTTP/1.1 stream lost chunked framing")
        request("large_header", "GET", "/health", headers={"X-Padding": "a" * 16000},
                expected=b"ok\n", fresh=True)
        request("oversized_line_bypass", "OPTIONS", "sip:" + "x" * 9000, status=404, fresh=True)

        expect_body = b"continue-body\x00" + SIP
        expect_request = ("POST /echo HTTP/1.1\r\nHost: localhost\r\nCookie: " + cookie
                          + "\r\nExpect: 100-continue\r\nContent-Type: application/octet-stream\r\n"
                          + f"Content-Length: {len(expect_body)}\r\nConnection: close\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", PORT), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(expect_request)
            interim = bytearray()
            while not interim.endswith(b"\r\n\r\n"):
                byte = sock.recv(1)
                require(byte, "No 100 Continue response")
                interim.extend(byte)
                require(len(interim) <= 4096, "Oversized interim response")
            require(bytes(interim) == b"HTTP/1.1 100 Continue\r\n\r\n", "Expect handshake changed")
            sock.sendall(expect_body)
            raw = bytearray()
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= 65536, "Expect response exceeds bound")
        responses = parse_raw_responses(bytes(raw))
        require(len(responses) == 1 and responses[0]["status"] == 200
                and responses[0]["body_sha256"] == digest(expect_body), "Expect body changed")
        records.append({"name": "expect_continue", "interim": bytes_record(bytes(interim), output, "interim"),
                        "response": bytes_record(bytes(raw), output, "expect-response")})
        canonical.append({"name": "expect_continue", "responses": responses})

        pipeline = (b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        controls = [
            ("segmented_pipeline", pipeline, [1, 2, 5, 3], False,
             [b"Reference application is running.\n", b"ok\n"]),
            ("half_close", b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n", None, True, [b"ok\n"]),
            ("http10_options", b"OPTIONS / HTTP/1.0\r\nHost: localhost\r\n\r\n", None, False, [b""]),
        ]
        for name, raw_request, chunks, half_close, bodies in controls:
            raw_response = exchange(raw_request, chunks=chunks, half_close=half_close)
            responses = parse_raw_responses(raw_response)
            expected_status = 204 if name == "http10_options" else 200
            require(len(responses) == len(bodies), f"{name}: missing response")
            require(all(response["status"] == expected_status and response["body_sha256"] == digest(body)
                        for response, body in zip(responses, bodies)), f"{name}: application response changed")
            records.append({"name": name, "request": bytes_record(raw_request, output, name + "-request"),
                            "response": bytes_record(raw_response, output, name + "-response")})
            canonical.append({"name": name, "responses": responses})

        request("logout", "POST", "/logout", headers={"Cookie": cookie})
        json_state("revoked_session", cookie=cookie, status=401)
    finally:
        connection.close()
        write_json(output / "http-records.json", records)
        write_json(output / "canonical.json", canonical)
    return {"checks": len(records), "canonical": canonical,
            "canonical_sha256": digest(json.dumps(canonical, sort_keys=True).encode()),
            "normalized_fields": ["Date value", "opaque session value in Set-Cookie"],
            "state_after": STATE}


def start_server(stack, server):
    stack.enter_context(server)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()

    def stop():
        server.shutdown()
        thread.join(timeout=5)
        require(not thread.is_alive(), "Server did not stop")
    stack.callback(stop)
    return server


def run_scan(nmap, data, env, directory, timeout):
    command = [str(nmap), "--datadir", str(data), "--unprivileged", "-sT", "-Pn", "-n",
               "-sV", "--version-intensity", "7", "--version-trace", "-d1", "-p", str(PORT),
               "-oA", str(directory / "scan"), "127.0.0.1"]
    write_json(directory / "command.json", command)
    with (directory / "stdout.log").open("wb") as out, (directory / "stderr.log").open("wb") as err:
        result = subprocess.run(command, cwd=directory, env=env, stdout=out, stderr=err,
                                timeout=timeout, check=False)
    scan = parse_scan(directory / "scan.xml", (directory / "stdout.log").read_text(errors="replace"),
                      (directory / "stderr.log").read_text(errors="replace"), result.returncode)
    scan.update(command=command, exit_code=result.returncode)
    return scan


def run_case(nmap, lua, data, env, output, name, presentation, mode, timeout):
    directory = output / name
    directory.mkdir()
    result = {"name": name, "presentation": presentation, "mode": mode, "status": "fail"}
    start = time.monotonic()
    print(f"Starting {name}", flush=True)
    try:
        with ExitStack() as stack:
            app = start_server(stack, ReferenceServer(port=PORT if mode == "direct" else 0,
                                                     presentation=presentation))
            adapter = None
            if mode != "direct":
                adapter = start_server(stack, AdapterServer(listen_port=PORT,
                                       backend_port=app.server_address[1], mode=mode, lua=lua))
            result["application_before"] = application_checks(directory, "before", "initial")
            result["metrics_before_scan"] = adapter.metrics_snapshot() if adapter else None
            result["scan"] = run_scan(nmap, data, env, directory, timeout)
            result["metrics_after_scan"] = adapter.metrics_snapshot() if adapter else None
            result["application_after"] = application_checks(directory, "after", STATE)
            scan = result["scan"]
            identity = scan["service_identity"]
            positive = (identity.get("name") == "honeypot"
                        and identity.get("product") == "Dionaea Honeypot httpd"
                        and identity.get("method") == "probed")
            result["honeypot_classification"] = positive
            expected_positive = presentation == "generic" and mode == "dionaea-sip"
            require(positive == expected_positive, "Ordinary scan classification differs from acceptance condition")
            if positive:
                require(any("Probe SIPOptions matched with SIPOptions" in line for line in scan["hard_matches"]),
                        "Positive label lacks SIPOptions evidence")
                result["camouflage_efficacy"] = "demonstrated_for_this_fixture"
            elif presentation == "basehttp":
                require(identity.get("product") == "BaseHTTPServer" and identity.get("method") == "probed",
                        "Recognized-frontend control did not identify real BaseHTTPServer")
                require(any("Probe GetRequest matched" in line for line in scan["hard_matches"]),
                        "Recognized frontend lacks early GetRequest hard match")
                require(not any("sending probe SIPOptions " in line for line in scan["sent_probes"]),
                        "Recognized-frontend probe ordering differs")
                result["camouflage_efficacy"] = "not_effective_early_hard_match" if mode == "dionaea-sip" else "off_control"
            else:
                require(any("sending probe GetRequest " in line for line in scan["sent_probes"])
                        and any("sending probe SIPOptions " in line for line in scan["sent_probes"]),
                        "Generic off control did not reach the relevant probes")
                require(not any(word in json.dumps(identity).lower() for word in ["honeypot", "dionaea", "honeyd"]),
                        "Off control has a honeypot identity")
                result["camouflage_efficacy"] = "off_control"

            # This separate wire check is not used to substitute for the ordinary scan.
            raw = exchange(SIP, chunks=[1, 6, 8, 2])
            result["explicit_sip_wire"] = bytes_record(raw, directory, "explicit-sip-response")
            require((raw == SIGNAL) == (mode == "dionaea-sip"), "Explicit SIP interception differs from configured mode")
            result["metrics_final"] = adapter.metrics_snapshot() if adapter else None
            if adapter:
                require(not result["metrics_final"].get("policy_errors", 0), "Lua execution failed during experiment")
            result["status"] = "pass"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        (directory / "exception.txt").write_text(traceback.format_exc())
    result["elapsed_seconds"] = round(time.monotonic() - start, 3)
    write_json(directory / "result.json", result)
    print(f"{name}: {result['status']} ({result['elapsed_seconds']}s) {result.get('error', '')}", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nmap", type=Path, default=ROOT / ".codex-cache/runtime/bin/nmap")
    parser.add_argument("--lua", type=Path, default=ROOT / ".codex-cache/runtime/bin/lua")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / ".codex-cache" /
                        ("http-camouflage-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be 1..600 seconds")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "fail", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "Lua reference adapter on plaintext IPv4 loopback HTTP; not a production release",
              "deterrence": "not_tested", "cases": [], "python_version": sys.version}
    try:
        nmap, lua = args.nmap.resolve(strict=True), args.lua.resolve(strict=True)
        data = (args.data_dir or nmap.parent.parent / "share/nmap").resolve(strict=True)
        report["inputs_before"] = snapshot(nmap, lua, data)
        require(report["inputs_before"]["probe_database"]["sha256"] == PROBES_SHA256,
                "Service-probe database differs from fixed baseline")
        env = os.environ.copy()
        env.pop("NMAP_PRIVILEGED", None)
        env["NMAPDIR"], env["TZ"] = str(data), "UTC"
        report["environment"] = {"NMAPDIR": str(data), "TZ": "UTC"}
        for label, command in [("nmap", [str(nmap), "--version"]), ("lua", [str(lua), "-E", "-v"]),
                               ("profile_tests", [str(lua), "-E", str(ROOT / "camouflage/tests/test_profile.lua")])]:
            completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                       text=True, timeout=30, check=False)
            (output / (label + ".log")).write_text(completed.stdout + completed.stderr)
            report[label] = {"command": command, "exit_code": completed.returncode,
                             "stdout": completed.stdout, "stderr": completed.stderr}
            require(completed.returncode == 0, f"{label} did not complete")
        for presentation in ["generic", "basehttp"]:
            for suffix, mode in [("a-direct", "direct"), ("b-passthrough", "passthrough"),
                                 ("c-active", "dionaea-sip"), ("a-restored", "direct")]:
                result = run_case(nmap, lua, data, env, output, presentation + "-" + suffix,
                                  presentation, mode, args.timeout)
                report["cases"].append(result)
                write_json(output / "summary.json", report)
                require(result["status"] == "pass", "Case failed; see retained raw evidence")
        comparisons = []
        for presentation in ["generic", "basehttp"]:
            cases = [case for case in report["cases"] if case["presentation"] == presentation]
            reference = cases[0]
            for case in cases[1:]:
                for phase in ["application_before", "application_after"]:
                    equal = case[phase]["canonical"] == reference[phase]["canonical"]
                    comparisons.append({"presentation": presentation, "reference": reference["name"],
                                        "case": case["name"], "phase": phase, "equal": equal})
                    require(equal, f"Application difference in {case['name']} {phase}")
            require(reference["scan"]["service_identity"] == cases[-1]["scan"]["service_identity"],
                    "Disabling adapter did not restore classification")
        report["application_comparisons"] = comparisons
        report["http_compatibility"] = "pass_within_declared_reference_application_scope"
        report["generic_camouflage"] = "demonstrated"
        report["recognized_basehttp_camouflage"] = "not_effective_early_hard_match"
        report["inputs_after"] = snapshot(nmap, lua, data)
        require(report["inputs_before"] == report["inputs_after"], "Experiment source/runtime changed during run")
        report["inputs_unchanged"] = True
        report["status"] = "pass"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        (output / "exception.txt").write_text(traceback.format_exc())
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_json(output / "summary.json", report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]),
                      "http_compatibility": report.get("http_compatibility", "not_established"),
                      "generic_camouflage": report.get("generic_camouflage", "not_established"),
                      "recognized_basehttp_camouflage": report.get("recognized_basehttp_camouflage", "not_established"),
                      "summary": str(output / "summary.json"), "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
