#!/usr/bin/env python3
"""Stateful loopback HTTP application for camouflage compatibility experiments.

This is a reference application, not a production authentication service. The
published test account is alice / local-test-password. Each server starts with
value="initial" and an empty session store. Session tokens are random.

HTTP/1.1 keep-alive, pipelining and Expect: 100-continue use Python's HTTP parser.
Request bodies use Content-Length and are bounded; chunked request bodies are
explicitly rejected. GET /stream exercises chunked HTTP/1.1 responses, falling
back to Content-Length for HTTP/1.0 clients. Both presentation modes use exactly
the same application code. "basehttp" exposes the real stdlib Server/Date
headers, whereas "generic" omits the Server banner while retaining Date.
"""

from __future__ import annotations

import argparse
import hmac
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import select
import socket
import sys
import threading


ALLOWED_ORIGIN = "https://client.example.test"
MAX_BODY = 1024 * 1024
MAX_ECHO = 512 * 1024
STREAM_BODY = bytes(range(256)) * 1024
ROOT_BODY = b"Reference application is running.\n"
ROUTES = {
    "/": ("GET", "HEAD", "OPTIONS"),
    "/health": ("GET", "HEAD", "OPTIONS"),
    "/state": ("GET", "HEAD", "PUT", "OPTIONS"),
    "/login": ("POST", "OPTIONS"),
    "/logout": ("POST", "OPTIONS"),
    "/echo": ("POST", "OPTIONS"),
    "/error": ("GET", "HEAD", "OPTIONS"),
    "/stream": ("GET", "HEAD", "OPTIONS"),
}


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


class ReferenceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 2

    def setup(self):
        super().setup()
        self._first_request = True

    def handle_one_request(self):
        if self._first_request:
            self._first_request = False
            # A normal initial idle allowance also lets Nmap's NULL probe finish.
            # Once bytes arrive, normal reads/keep-alive use the 2-second timeout.
            if not select.select([self.connection], [], [], 10)[0]:
                self.close_connection = True
                return
        super().handle_one_request()

    def log_message(self, format, *args):
        # HTTP request and cookie contents are not written to the console.
        pass

    def send_response(self, code, message=None):
        if self.server.presentation == "basehttp":
            super().send_response(code, message)
        else:
            self.send_response_only(code, message)
            self.send_header("Date", self.date_time_string())

    def send_error(self, code, message=None, explain=None):
        # Keep malformed-protocol responses deterministic and avoid the stdlib
        # HTML error template revealing a different presentation in generic mode.
        self.close_connection = True
        if self.request_version not in ("HTTP/1.0", "HTTP/1.1"):
            self.request_version = "HTTP/1.0"
        reason = HTTPStatus(code).phrase if code in HTTPStatus._value2member_map_ else "Error"
        self._send(code, (reason.lower() + "\n").encode("ascii"))

    def _cors_headers(self):
        if getattr(self, "headers", None) is not None and self.headers.get("Origin") == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Vary", "Origin")

    def _send(self, status, body=b"", content_type="text/plain; charset=utf-8", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if status != 204:
            self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self._cors_headers()
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if getattr(self, "command", None) != "HEAD" and body:
            self.wfile.write(body)

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin != ALLOWED_ORIGIN:
            self.close_connection = True
            self._send(403, b"origin not allowed\n")
            return False
        return True

    def _read_body(self, *, required=False, limit=MAX_BODY):
        if self.headers.get_all("Transfer-Encoding"):
            self.close_connection = True
            self._send(501, b"chunked request bodies are not supported\n")
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            if required:
                self.close_connection = True
                self._send(411, b"content-length required\n")
                return None
            return b""
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self.close_connection = True
            self._send(400, b"invalid content-length\n")
            return None
        if len(lengths[0]) > 8 or int(lengths[0]) > limit:
            self.close_connection = True
            self._send(413, b"request body too large\n")
            return None
        size = int(lengths[0])
        body = self.rfile.read(size)
        if len(body) != size:
            self.close_connection = True
            self._send(400, b"incomplete request body\n")
            return None
        return body

    def _json_body(self, body):
        if self.headers.get_content_type() != "application/json":
            self._send(415, b"application/json required\n")
            return None
        try:
            value = json.loads(body)
            # Validate values before storing them: reject non-finite numbers or
            # unpaired Unicode surrogates that cannot form our JSON response.
            json_bytes(value)
        except (ValueError, UnicodeError, RecursionError):
            self._send(400, b"invalid json\n")
            return None
        if not isinstance(value, dict):
            self._send(400, b"json object required\n")
            return None
        return value

    def _session(self):
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            item = cookie.get("session")
            token = item.value if item is not None else None
        except CookieError:
            return None
        with self.server.state_lock:
            return token if token in self.server.sessions else None

    def _authenticated(self):
        token = self._session()
        if token is None:
            self._send(401, b"authentication required\n",
                       headers=(("WWW-Authenticate", 'Session realm="reference"'),))
        return token

    def _not_found_or_method(self):
        methods = ROUTES.get(self.path)
        if methods is None:
            self._send(404, b"not found\n")
        else:
            self._send(405, b"method not allowed\n", headers=(("Allow", ", ".join(methods)),))

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._origin_ok() or self._read_body() is None:
            return
        if self.path == "/":
            self._send(200, ROOT_BODY)
        elif self.path == "/health":
            self._send(200, b"ok\n")
        elif self.path == "/state":
            if self._authenticated() is not None:
                with self.server.state_lock:
                    body = json_bytes({"value": self.server.value})
                self._send(200, body, "application/json")
        elif self.path == "/error":
            self._send(500, b"intentional application error\n")
        elif self.path == "/stream":
            self._stream()
        else:
            self._not_found_or_method()

    def _stream(self):
        if self.request_version != "HTTP/1.1":
            self._send(200, STREAM_BODY, "application/octet-stream")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Transfer-Encoding", "chunked")
        if self.close_connection:
            self.send_header("Connection", "close")
        self._cors_headers()
        self.end_headers()
        if self.command == "HEAD":
            return
        for offset in range(0, len(STREAM_BODY), 8192):
            chunk = STREAM_BODY[offset:offset + 8192]
            self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def do_OPTIONS(self):
        if not self._origin_ok() or self._read_body() is None:
            return
        methods = ROUTES.get(self.path)
        if methods is None:
            self._send(404, b"not found\n")
            return
        requested = self.headers.get("Access-Control-Request-Method")
        requested_headers = {part.strip().lower() for part in
                             self.headers.get("Access-Control-Request-Headers", "").split(",") if part.strip()}
        if (requested is not None and requested not in methods) or requested_headers - {"content-type"}:
            self._send(403, b"preflight not allowed\n")
            return
        allowed = ", ".join(methods)
        headers = [("Allow", allowed)]
        if self.headers.get("Origin") == ALLOWED_ORIGIN:
            headers += [("Access-Control-Allow-Methods", allowed),
                        ("Access-Control-Allow-Headers", "Content-Type")]
        self._send(204, headers=headers)

    def do_POST(self):
        if not self._origin_ok():
            return
        body = self._read_body(required=self.path != "/logout",
                               limit=MAX_ECHO if self.path == "/echo" else MAX_BODY)
        if body is None:
            return
        if self.path == "/login":
            value = self._json_body(body)
            if value is None:
                return
            user, password = value.get("username"), value.get("password")
            if not (isinstance(user, str) and isinstance(password, str)
                    and hmac.compare_digest(user.encode(), b"alice")
                    and hmac.compare_digest(password.encode(), b"local-test-password")):
                self._send(401, b"invalid credentials\n")
                return
            token = secrets.token_urlsafe(32)
            with self.server.state_lock:
                full = len(self.server.sessions) >= 256
                if not full:
                    self.server.sessions.add(token)
            if full:
                self._send(503, b"test session capacity reached\n")
                return
            self._send(200, json_bytes({"authenticated": True}), "application/json",
                       (("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Lax"),))
        elif self.path == "/logout":
            token = self._authenticated()
            if token is not None:
                with self.server.state_lock:
                    self.server.sessions.discard(token)
                self._send(200, json_bytes({"authenticated": False}), "application/json",
                           (("Set-Cookie", "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),))
        elif self.path == "/echo":
            if self._authenticated() is not None:
                self._send(200, body, "application/octet-stream")
        else:
            self._not_found_or_method()

    def do_PUT(self):
        if not self._origin_ok():
            return
        body = self._read_body(required=True)
        if body is None:
            return
        if self.path != "/state":
            self._not_found_or_method()
            return
        if self._authenticated() is None:
            return
        value = self._json_body(body)
        if value is None:
            return
        if set(value) != {"value"}:
            self._send(400, b"exactly one value field required\n")
            return
        with self.server.state_lock:
            self.server.value = value["value"]
            response = json_bytes({"value": self.server.value})
        self._send(200, response, "application/json")


class ReferenceServer(ThreadingHTTPServer):
    """Loopback-only reference application; start serve_forever in a thread."""

    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False

    def __init__(self, port=0, presentation="generic"):
        if presentation not in ("generic", "basehttp"):
            raise ValueError("presentation must be generic or basehttp")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("port must be an integer in 0..65535")
        self.presentation = presentation
        self.value = "initial"
        self.sessions = set()
        self.state_lock = threading.Lock()
        self._clients = set()
        self._clients_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), ReferenceHandler)

    def get_request(self):
        client, address = super().get_request()
        with self._clients_lock:
            self._clients.add(client)
        return client, address

    def close_request(self, request):
        with self._clients_lock:
            self._clients.discard(request)
        super().close_request(request)

    def server_close(self):
        with self._clients_lock:
            clients = tuple(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        super().server_close()

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            super().handle_error(request, client_address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--presentation", choices=("generic", "basehttp"), default="generic")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be 0..65535")
    with ReferenceServer(args.port, args.presentation) as server:
        print(f"Reference app ({args.presentation}): 127.0.0.1:{server.server_address[1]}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
