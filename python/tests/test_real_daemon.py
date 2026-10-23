from __future__ import annotations

import base64
import json
import os
import socket
import socketserver
import subprocess
import threading
import zlib
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tlsforge import MAX_REQUEST_BYTES, Client, Hello, RequestFailed, TransportError


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


_PAGE = "a page worth compressing. " * 50


class _DeflateHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = zlib.compress(_PAGE.encode())
        self.send_response(200)
        self.send_header("content-encoding", "deflate")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def test_a_deflate_page_arrives_decoded_with_fields_that_describe_it() -> None:
    """deflate in the zlib form the name means: the transport used to hang on
    it until the request's deadline."""
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _DeflateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with Client(binary=binary, timeout=10) as client:
            response = client.get(f"http://127.0.0.1:{server.server_port}/page")
        assert response.body == _PAGE
        assert "content-encoding" not in response.headers
        assert "content-length" not in response.headers
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _ChainHandler(BaseHTTPRequestHandler):
    """/chain/N redirects to /chain/N-1, and /chain/0 is a page; the server
    counts what it was asked."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        counts = self.server.counts  # type: ignore[attr-defined]
        counts["requests"] += 1
        left = int(self.path.removeprefix("/chain/"))
        if left == 0:
            counts["ends"] += 1
            body = b"landed"
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(302)
        self.send_header("location", f"/chain/{left - 1}")
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def test_the_real_go_daemon_follows_nineteen_redirects_and_stops_at_the_twentieth() -> None:
    """Navigation follows nineteen redirects; the twentieth is refused."""
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChainHandler)
    server.counts = {"requests": 0, "ends": 0}  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with Client(binary=binary, timeout=10) as client:
            for redirects, landed in ((19, True), (20, False), (21, False)):
                server.counts.update(requests=0, ends=0)  # type: ignore[attr-defined]
                url = f"http://127.0.0.1:{server.server_port}/chain/{redirects}"
                if landed:
                    assert client.get(url).body == "landed"
                else:
                    with pytest.raises(RequestFailed, match="the 20th redirect was not followed"):
                        client.get(url)
                assert server.counts == {"requests": 20, "ends": int(landed)}  # type: ignore[attr-defined]
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


class _PageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = b"through the proxy"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class _Tunnelling(socketserver.ThreadingTCPServer):
    """A proxy that opens a tunnel for a CONNECT that says who it is with the
    right password, and turns away any other, as a paid proxy does. It keeps
    where each tunnel went."""

    daemon_threads = True

    def __init__(self, user: str, password: str) -> None:
        self.expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.tunnels: list[str] = []
        super().__init__(("127.0.0.1", 0), _TunnelHandler)
        self.url = f"http://{user}:{password}@127.0.0.1:{self.server_address[1]}"


class _TunnelHandler(socketserver.StreamRequestHandler):
    server: _Tunnelling

    def handle(self) -> None:
        method, target, _ = self.rfile.readline().decode("latin-1").split(" ", 2)
        headers: dict[str, str] = {}
        while (line := self.rfile.readline().decode("latin-1").strip()) != "":
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if headers.get("proxy-authorization") != self.server.expected:
            self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        if method == "CONNECT":
            authority = target
            path = ""
        else:
            parsed = urlsplit(target)
            assert parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
            authority = parsed.netloc
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        self.server.tunnels.append(authority)
        host, port = authority.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=5) as upstream:
            if method == "CONNECT":
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                headers.pop("proxy-authorization", None)
                headers.pop("proxy-connection", None)
                headers["connection"] = "close"
                head = f"{method} {path} HTTP/1.1\r\n"
                head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                upstream.sendall((head + "\r\n").encode("latin-1"))
            back = threading.Thread(target=_pipe, args=(upstream, self.connection), daemon=True)
            back.start()
            _pipe(self.connection, upstream)
            back.join(timeout=5)


def _pipe(source: socket.socket, sink: socket.socket) -> None:
    try:
        while chunk := source.recv(65536):
            sink.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _serving(server: socketserver.BaseServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_the_real_go_daemon_goes_through_the_proxy_its_input_names() -> None:
    """The URL, password and all, reaches the daemon on the first line of its
    input, the init line --proxy-stdin asks for: a daemon that did not read it
    would go to the site directly, and the proxy would see no tunnel."""
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
    proxy = _Tunnelling("alice", "s3cret")
    threads = [_serving(origin), _serving(proxy)]
    try:
        with Client(binary=binary, proxy=proxy.url, timeout=10) as client:
            response = client.get(f"http://127.0.0.1:{origin.server_port}/")
        assert response.body == "through the proxy"
        assert proxy.tunnels == [f"127.0.0.1:{origin.server_port}"]
    finally:
        for server in (origin, proxy):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_a_proxy_the_real_go_daemon_turns_down_says_why_without_its_password() -> None:
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    secret = "s3cret-never-shown"
    origin = ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
    proxy = _Tunnelling("alice", "s3cret")
    threads = [_serving(origin), _serving(proxy)]
    try:
        for url in (
            # One that will not parse: quoted back whole by whatever read it.
            f"http://alice:{secret}@[bad",
            # One that answers 407 to a password it does not know.
            f"http://alice:{secret}@127.0.0.1:{proxy.server_address[1]}",
        ):
            with Client(binary=binary, proxy=url, timeout=10) as client:
                with pytest.raises((RequestFailed, TransportError)) as failed:
                    client.get(f"http://127.0.0.1:{origin.server_port}/")
            assert secret not in str(failed.value)
        assert proxy.tunnels == []
    finally:
        for server in (origin, proxy):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)

    # What the daemon itself says of the one it cannot read, as the client
    # starts it: its answer to the init line and its last words, read here to
    # the end.
    started = subprocess.run(
        [binary, "daemon", "--proxy-stdin"],
        input=json.dumps({"id": 1, "engine_major": 7, "control": "init", "proxy": f"http://alice:{secret}@[bad"}) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert started.returncode == 1, started.stderr
    assert "[redacted]@[bad" in started.stderr
    answer = json.loads(started.stdout)
    assert answer["id"] == 1 and "[redacted]@[bad" in answer["error"]
    assert secret not in started.stderr + started.stdout


class _SessionHandler(BaseHTTPRequestHandler):
    seen: dict[str, object] = {}

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/set":
            self._answer(b"set", ("set-cookie", "visitor=42; Path=/"))
            return
        type(self).seen = {"cookie": self.headers.get("cookie", ""), "length": 0}
        self._answer(b"seen")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length", "0"))
        self.rfile.read(length)
        type(self).seen = {"cookie": self.headers.get("cookie", ""), "length": length}
        self._answer(b"seen")

    def _answer(self, body: bytes, *headers: tuple[str, str]) -> None:
        self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def test_the_real_go_daemon_reads_a_request_as_long_as_the_limit() -> None:
    """The limit this client refuses a request at has to be the daemon's, to
    the byte: one byte under it, and the daemon would end, its session with it."""
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _SessionHandler)
    thread = _serving(origin)
    try:
        base = f"http://127.0.0.1:{origin.server_port}"
        with Client(binary=binary, timeout=60) as client:
            client.get(f"{base}/set")
            url = f"{base}/echo"
            overhead = len(
                json.dumps({"id": 3, "method": "POST", "url": url, "body": "", "engine_major": 7}, separators=(",", ":")) + "\n"
            )
            body = "x" * (MAX_REQUEST_BYTES - overhead)
            client.post(url, body)
            assert _SessionHandler.seen == {"cookie": "visitor=42", "length": len(body)}

            with pytest.raises(ValueError, match="more than"):
                client.post(url, body + "x")
            client.get(url)
            assert _SessionHandler.seen == {"cookie": "visitor=42", "length": 0}
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=2)


def test_the_real_go_daemon_keeps_no_cookie_of_an_answer_to_a_request_without_credentials() -> None:
    # fetch() with credentials omit carries no cookies and keeps none its
    # answer sets, as Chrome's; one with the page's own credentials keeps them.
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    class _Setting(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Set-Cookie", f"{self.path[1:]}=1; Path=/")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Setting)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        page = f"{base}/page"
        with Client(binary=binary) as client:
            omitted = client.get(
                f"{base}/omitted", browser_context={"kind": "fetch", "initiator": page, "credentials": "omit"}
            )
            assert omitted.cookies == ()
            kept = client.get(f"{base}/kept", browser_context={"kind": "fetch", "initiator": page})
            assert kept.cookies == ("kept=1",)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_the_real_go_daemon_applies_a_browser_context_cors_and_all() -> None:
    binary = os.environ.get("TLSFORGE_REAL_BIN")
    if not binary:
        pytest.skip("run through make wrapper-smoke")

    def serving(status: int) -> tuple[ThreadingHTTPServer, list]:
        seen: list = []

        class _Keeping(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                seen.append((self.command, self.path, dict(self.headers)))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = do_OPTIONS = _answer  # noqa: N815 - BaseHTTPRequestHandler API

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        return ThreadingHTTPServer(("127.0.0.1", 0), _Keeping), seen

    page, page_seen = serving(200)
    other, other_seen = serving(403)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (page, other)]
    for thread in threads:
        thread.start()
    try:
        base = f"http://127.0.0.1:{page.server_port}"
        elsewhere = f"http://127.0.0.1:{other.server_port}"
        initiator = f"{base}/page"
        with Client(binary=binary) as client:
            assert client.hello() == Hello(3, ("browser_context", "engine_major"), 7, "7.0.0")
            answer = client.get(f"{base}/api", browser_context={"kind": "fetch", "initiator": initiator})
            assert answer.status == 200
            method, path, headers = page_seen[0]
            lowered = {name.lower(): value for name, value in headers.items()}
            assert (method, path) == ("GET", "/api")
            assert lowered["sec-fetch-mode"] == "cors" and lowered["sec-fetch-site"] == "same-origin"
            assert lowered["accept"] == "*/*" and lowered["referer"] == initiator
            assert "upgrade-insecure-requests" not in lowered

            # JSON to the other origin asks first, is refused, and nothing more goes.
            with pytest.raises(RequestFailed, match="CORS: the preflight of POST .* refused it: it was answered 403"):
                client.post(
                    f"{elsewhere}/cart",
                    "{}",
                    headers={"content-type": "application/json"},
                    browser_context={"kind": "fetch", "initiator": initiator},
                )
            assert [hit[0] for hit in other_seen] == ["OPTIONS"]

            # A context the daemon cannot send is refused, and nothing is sent;
            # a key there is none of is refused before it is asked.
            with pytest.raises(RequestFailed, match='kind "websocket" is not navigation, form, fetch or xhr'):
                client.get(f"{base}/x", browser_context={"kind": "websocket", "initiator": initiator})
            with pytest.raises(TypeError, match="browser_context has no key 'frame'"):
                client.get(f"{base}/x", browser_context={"kind": "fetch", "initiator": initiator, "frame": "top"})
            assert len(page_seen) == 1
    finally:
        for server, thread in zip((page, other), threads):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
