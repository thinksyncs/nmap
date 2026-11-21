#!/usr/bin/env python3
"""Loopback reference adapter for a Lua honeypot presentation profile.

The first connection request line is the only classification boundary. After a
pass decision, all bytes flow unchanged in both directions, including later
HTTP requests, bodies, chunk framing, and connection upgrades. This adapter is
not an HTTP parser, TLS terminator, or production proxy. Limits and idle expiry
are explicit parts of its local experimental scope.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
DRIVER = Path(__file__).resolve().parent / "lua" / "decide.lua"
DEFAULT_LUA = ROOT / ".codex-cache" / "runtime" / "bin" / "lua"
CANDIDATES = (b"OPTIONS sip:", b"OPTIONS sips:")
RELAY_BUFFER_LIMIT = 65536
POLICY_RESPONSE_LIMIT = 1024


class AdapterServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """One optional profile in front of an existing IPv4 loopback service.

    Use serve_forever() in a worker thread, then shutdown() and server_close()
    (or the context manager). Policy failures bypass to the original backend and
    increment policy_errors. A successful classification experiment must check
    that counter; ordinary application availability is preserved on that path.
    """

    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False
    request_queue_size = 32

    def __init__(self, *, listen_port=8081, backend_port=18081,
                 mode="dionaea-sip", lua=None, prefix_limit=8192,
                 prefix_timeout=10.0, idle_timeout=30.0, policy_timeout=1.0,
                 backend_timeout=3.0, max_connections=32):
        if not isinstance(listen_port, int) or not 0 <= listen_port <= 65535:
            raise ValueError("listen_port must be 0..65535")
        if not isinstance(backend_port, int) or not 1 <= backend_port <= 65535:
            raise ValueError("backend_port must be 1..65535")
        if mode not in ("passthrough", "dionaea-sip"):
            raise ValueError("mode must be passthrough or dionaea-sip")
        if not isinstance(prefix_limit, int) or not 32 <= prefix_limit <= 8192:
            raise ValueError("prefix_limit must be 32..8192 bytes")
        for name, value in (("prefix_timeout", prefix_timeout),
                            ("idle_timeout", idle_timeout),
                            ("policy_timeout", policy_timeout),
                            ("backend_timeout", backend_timeout)):
            if not 0 < value <= 300:
                raise ValueError(f"{name} must be greater than 0 and at most 300 seconds")
        if not isinstance(max_connections, int) or not 1 <= max_connections <= 128:
            raise ValueError("max_connections must be 1..128")
        self.backend_address = ("127.0.0.1", backend_port)
        self.mode = mode
        self.lua = Path(lua or DEFAULT_LUA).resolve()
        if mode == "dionaea-sip" and not (self.lua.is_file() and os.access(self.lua, os.X_OK)):
            raise ValueError("A working Lua executable is required for dionaea-sip mode")
        self.prefix_limit = prefix_limit
        self.prefix_timeout = float(prefix_timeout)
        self.idle_timeout = float(idle_timeout)
        self.policy_timeout = float(policy_timeout)
        self.backend_timeout = float(backend_timeout)
        self._slots = threading.BoundedSemaphore(max_connections)
        self._lock = threading.Lock()
        self._metrics = Counter()
        self._sockets = set()
        self._closing = threading.Event()
        super().__init__(("127.0.0.1", listen_port), _Handler)
        if self.server_address == self.backend_address:
            self.server_close()
            raise ValueError("Listener and backend must use different ports")

    def count(self, name, amount=1):
        with self._lock:
            self._metrics[name] += amount

    def metrics_snapshot(self):
        with self._lock:
            values = dict(self._metrics)
            values.setdefault("policy_errors", 0)
            values.setdefault("replies", 0)
            values.setdefault("active_connections", 0)
            return values

    def track(self, connection):
        with self._lock:
            self._sockets.add(connection)

    def untrack(self, connection):
        with self._lock:
            self._sockets.discard(connection)

    def process_request(self, request, client_address):
        if self._closing.is_set() or not self._slots.acquire(blocking=False):
            self.count("rejected_connections")
            self.shutdown_request(request)
            return
        self.track(request)
        self.count("connections")
        self.count("active_connections")
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.untrack(request)
            self.count("active_connections", -1)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.untrack(request)
            self.count("active_connections", -1)
            self._slots.release()

    def server_close(self):
        self._closing.set()
        with self._lock:
            connections = list(self._sockets)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        super().server_close()

    def decide(self, line):
        if self.mode == "passthrough":
            return None
        try:
            result = subprocess.run(
                [str(self.lua), "-E", str(DRIVER)], input=line, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=self.policy_timeout, check=False,
            )
            # The trusted fixed driver emits either PASS or a constant short
            # response. Request data can never select executable Lua code.
            if result.returncode != 0 or result.stderr:
                raise ValueError("Lua policy execution failed")
            if result.stdout == b"PASS\n":
                return None
            if (result.stdout.startswith(b"REPLY\n")
                    and 0 < len(result.stdout) - 6 <= POLICY_RESPONSE_LIMIT):
                return result.stdout[6:]
            raise ValueError("Invalid Lua policy output")
        except (OSError, ValueError, subprocess.SubprocessError):
            self.count("policy_errors")
            return None


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        try:
            prefix, complete, client_eof = self._read_prefix()
            if not prefix and client_eof:
                server.count("empty_connections")
                return
            if complete:
                line_end = prefix.index(b"\r\n") + 2
                response = server.decide(prefix[:line_end])
                if response is not None:
                    self._reply(response, prefix)
                    server.count("replies")
                    return
            server.count("passthrough_connections")
            try:
                backend = socket.create_connection(server.backend_address,
                                                   timeout=server.backend_timeout)
            except OSError:
                server.count("backend_errors")
                return
            with backend:
                server.track(backend)
                try:
                    self._relay(backend, prefix, client_eof)
                finally:
                    server.untrack(backend)
        except OSError:
            if not server._closing.is_set():
                server.count("connection_errors")

    def _read_prefix(self):
        """Buffer only while the first line could be a profile candidate.

        A recv may include bytes after that line. They are never classified and
        are forwarded verbatim on a pass decision. Non-candidate traffic takes
        the same early pass path in both modes. Expiry or a full buffer bypasses
        the profile without discarding bytes.
        """
        prefix = bytearray()
        deadline = time.monotonic() + self.server.prefix_timeout
        while not self.server._closing.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.server.count("prefix_timeout_bypasses")
                return bytes(prefix), False, False
            self.request.settimeout(min(remaining, 1.0))
            try:
                chunk = self.request.recv(min(4096, self.server.prefix_limit - len(prefix)))
            except socket.timeout:
                continue
            if not chunk:
                return bytes(prefix), False, True
            prefix.extend(chunk)
            if not any(prefix.startswith(candidate) or candidate.startswith(prefix)
                       for candidate in CANDIDATES):
                return bytes(prefix), False, False
            if b"\r\n" in prefix:
                return bytes(prefix), True, False
            if len(prefix) >= self.server.prefix_limit:
                self.server.count("prefix_limit_bypasses")
                return bytes(prefix), False, False
        return bytes(prefix), False, True

    def _reply(self, response, prefix):
        self.request.settimeout(self.server.backend_timeout)
        self.request.sendall(response)
        # A write half-close exposes the complete response even if a segmented
        # SIP client has not sent the rest of its headers yet. Drain only the
        # bounded header tail to avoid resetting an ordinary split probe.
        self.request.shutdown(socket.SHUT_WR)
        if b"\r\n\r\n" in prefix:
            return
        remaining = self.server.prefix_limit - len(prefix)
        tail = prefix[-3:]
        deadline = time.monotonic() + min(self.server.prefix_timeout, 1.0)
        while remaining > 0 and not self.server._closing.is_set():
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
            self.request.settimeout(timeout)
            try:
                chunk = self.request.recv(min(4096, remaining))
            except socket.timeout:
                break
            if not chunk:
                break
            remaining -= len(chunk)
            if b"\r\n\r\n" in tail + chunk:
                break
            tail = chunk[-3:]

    def _relay(self, backend, prefix, client_eof):
        client = self.request
        peers = {client: backend, backend: client}
        buffers = {client: bytearray(), backend: bytearray(prefix)}
        reading = {client: not client_eof, backend: True}
        write_closed = {client: False, backend: False}
        for connection in peers:
            connection.setblocking(False)
        last_activity = time.monotonic()
        while not self.server._closing.is_set():
            for source, destination in peers.items():
                if not reading[source] and not buffers[destination] and not write_closed[destination]:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    write_closed[destination] = True
            if not any(reading.values()) and not any(buffers.values()):
                return
            remaining = self.server.idle_timeout - (time.monotonic() - last_activity)
            if remaining <= 0:
                self.server.count("relay_idle_timeouts")
                return
            readers = [source for source, destination in peers.items()
                       if reading[source] and len(buffers[destination]) < RELAY_BUFFER_LIMIT]
            writers = [destination for destination in peers if buffers[destination]]
            try:
                readable, writable, _ = select.select(readers, writers, [], min(remaining, 1.0))
            except ValueError:
                # server_close() can close a descriptor between the loop's
                # closing check and select's descriptor validation.
                if self.server._closing.is_set():
                    return
                raise
            for destination in writable:
                try:
                    size = destination.send(buffers[destination])
                except (BlockingIOError, InterruptedError):
                    continue
                if size == 0:
                    raise ConnectionError("Socket stopped accepting relay bytes")
                del buffers[destination][:size]
                last_activity = time.monotonic()
                self.server.count("bytes_to_backend" if destination is backend else "bytes_to_client", size)
            for source in readable:
                destination = peers[source]
                available = RELAY_BUFFER_LIMIT - len(buffers[destination])
                try:
                    chunk = source.recv(min(16384, available))
                except (BlockingIOError, InterruptedError):
                    continue
                if chunk:
                    buffers[destination].extend(chunk)
                    last_activity = time.monotonic()
                else:
                    reading[source] = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, default=8081)
    parser.add_argument("--backend-port", type=int, default=18081)
    parser.add_argument("--mode", choices=("passthrough", "dionaea-sip"), default="dionaea-sip")
    parser.add_argument("--lua", type=Path, default=DEFAULT_LUA)
    args = parser.parse_args()
    try:
        server = AdapterServer(listen_port=args.listen_port, backend_port=args.backend_port,
                               mode=args.mode, lua=args.lua)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    with server:
        print(json.dumps({"listen": server.server_address, "backend": server.backend_address,
                          "mode": server.mode, "scope": "loopback reference adapter"}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    print(json.dumps({"metrics": server.metrics_snapshot()}), flush=True)


if __name__ == "__main__":
    main()
