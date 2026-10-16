from __future__ import annotations

import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tlsforge import Client, RequestFailed


class _BinaryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = bytes([0x89, 0x50, 0x4E, 0x47, 0xFF, 0xD8, 0xFF])
        self.send_response(200)
        self.send_header("set-cookie", "a=1")
        self.send_header("set-cookie", "b=2")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def test_python_decodes_bytes_emitted_by_the_real_go_daemon() -> None:
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _BinaryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with Client(binary=binary) as client:
            response = client.get(f"http://127.0.0.1:{server.server_port}/binary")
        assert response.content == bytes([0x89, 0x50, 0x4E, 0x47, 0xFF, 0xD8, 0xFF])
        assert response.headers["set-cookie"] == ("a=1", "b=2")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_a_request_the_real_go_daemon_cannot_make_raises_request_failed() -> None:
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    # A port that was listening a moment ago and is not any more: refused at
    # once, on every platform, without reaching anything outside this machine.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    with Client(binary=binary) as client:
        with pytest.raises(RequestFailed, match="(?i)refused"):
            client.get(f"http://127.0.0.1:{port}/")
