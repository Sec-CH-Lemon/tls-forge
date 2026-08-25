"""tls-forge — an HTTP client for Python whose TLS fingerprint is a real browser's.

Python cannot do this on its own. Its TLS comes from OpenSSL, which exposes no
control over extension order, GREASE values or the extension set — and those are
precisely what JA3 and JA4 hash. Chrome uses BoringSSL. So the socket moves out
of Python into a small Go process, and Python keeps the orchestration, which is
the part it is good at.

One Client is one long-lived process, and that is deliberate: it means one TLS
fingerprint, one cookie jar and one exit IP for the whole session. Reconnecting
per request is itself a signal — no browser does it.
"""

from __future__ import annotations

import json
import math
import os
import queue
import subprocess
import threading
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from ._binary import resolve_binary
from ._errors import RequestFailed, Timeout, TransportError

DEFAULT_TIMEOUT = 45.0

#: How much longer the transport's own deadline is than ours.
#:
#: If they were equal, a request timing out would race: both sides would decide
#: it had failed, and the process would be killed while writing the answer.
_TRANSPORT_GRACE = 15.0

#: How long a transport gets to notice end of input before it is signalled.
#:
#: Short because the daemon has nothing to flush on the way out and exits on
#: EOF at once. It is a grace rather than nothing so that a transport which
#: later does have something to write gets the chance.
_SHUTDOWN_GRACE = 0.25

#: Put on the queue by a reader when its stream ends, which is how a waiting
#: request learns the process is gone without polling for it.
_EOF = object()


@dataclass(frozen=True)
class Response:
    """What came back."""

    status: int
    url: str
    """The final URL, after redirects."""
    body: str
    headers: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    """Header values in wire order. Values stay separate because folding
    `set-cookie`, among others, changes its meaning."""
    cookies: tuple[str, ...] = ()
    """What the jar holds for this URL afterwards."""

    @property
    def ok(self) -> bool:
        """Did the server answer with a 2xx?"""
        return 200 <= self.status < 300

    def json(self, **kwargs: Any) -> Any:
        """The body parsed as JSON. Raises `json.JSONDecodeError` if it is not."""
        return json.loads(self.body, **kwargs)


class Client:
    """One browser identity: one fingerprint, one cookie jar, one exit IP.

    A client serialises: the protocol underneath is one request at a time, so
    calls from several threads queue rather than overlap. That is not a
    limitation to work around — it is what one session is. Scrape in parallel
    with a pool of clients, one per proxy, which is also how the identities stay
    separate.

    Close it when done, or use it as a context manager. Closing is final: a
    client is one identity, and once it has been given up there is no identity
    left to make requests with.
    """

    def __init__(
        self,
        *,
        profile: str | None = None,
        proxy: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        binary: str | os.PathLike[str] | None = None,
        insecure: bool = False,
        cookie_file: str | os.PathLike[str] | None = None,
        cookie_set: str | None = None,
        on_stderr: Callable[[str], None] | None = None,
    ) -> None:
        """
        :param profile: which browser to impersonate, e.g. ``"chrome"``.
        :param proxy: an ``http://`` or ``socks5://`` URL.
        :param timeout: per-request deadline, in seconds.
        :param binary: path to the tls-forge binary, ahead of every other source.
        :param insecure: skip certificate verification.
        :param cookie_file: a file of warmed cookies to start from (``--cookies``).
        :param cookie_set: which set in that file; one at random when not named.
        :param on_stderr: receives the transport's stderr, a line at a time.
        :raises BinaryNotFound: when there is no binary to run.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("tlsforge: timeout must be a positive finite number")
        if on_stderr is not None and not callable(on_stderr):
            raise TypeError("tlsforge: on_stderr must be callable")
        if cookie_set and not cookie_file:
            raise ValueError("tlsforge: cookie_set requires cookie_file")

        self._binary = resolve_binary(binary)
        self._timeout = float(timeout)
        self._on_stderr = on_stderr or _ignore
        self._args = _build_args(
            profile=profile,
            proxy=proxy,
            insecure=insecure,
            cookie_file=cookie_file,
            cookie_set=cookie_set,
            transport_timeout=self._timeout + _TRANSPORT_GRACE,
        )

        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[Any] = queue.Queue()

        # Never reset, not even across a restart. An id must never name two
        # different requests on one client, or a late answer from the process we
        # killed can match the request that replaced it — the exact crossing the
        # id exists to prevent.
        self._sequence = 0
        self._closed = False

        # A Popen that is merely garbage collected is not killed: CPython reaps
        # it later and warns, and the daemon goes on running. A scraper that
        # builds a client per site would leave one process behind per site. The
        # list is what the finalizer reaches, rather than self, because a
        # finalizer holding self would keep self alive and never run.
        self._live: list[subprocess.Popen[str]] = []
        weakref.finalize(self, _kill_all, self._live)

    # --- the public surface ------------------------------------------------

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        order: Sequence[str] | None = None,
        cookies: Iterable[str] | None = None,
    ) -> Response:
        """GET a URL."""
        return self.request(url, method="GET", headers=headers, order=order, cookies=cookies)

    def post(
        self,
        url: str,
        body: str = "",
        *,
        headers: Mapping[str, str] | None = None,
        order: Sequence[str] | None = None,
        cookies: Iterable[str] | None = None,
    ) -> Response:
        """POST a body."""
        return self.request(
            url, method="POST", body=body, headers=headers, order=order, cookies=cookies
        )

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        order: Sequence[str] | None = None,
        body: str | None = None,
        cookies: Iterable[str] | None = None,
    ) -> Response:
        """Make a request.

        :param headers: layered over the profile's. A name the profile already
            sends keeps the browser's position and takes your value; one it does
            not send is appended after the rest.
        :param order: the order of the headers *you* send. Without it they go
            last, sorted.
        :param cookies: ``name=value`` pairs added to the jar before the request.
        :raises RequestFailed: the request ran and failed — refused, DNS, TLS.
        :raises TransportError: the transport would not start, died, or spoke
            nonsense. The client stays usable.
        :raises Timeout: the deadline passed with no answer.
        """
        if not url:
            raise ValueError("tlsforge: request needs a url")

        with self._lock:
            if self._closed:
                raise TransportError(
                    "tlsforge: this client was closed and will not respawn; construct a new one"
                )
            self._sequence += 1
            payload: dict[str, Any] = {"id": self._sequence, "method": method, "url": url}
            if headers:
                payload["headers"] = dict(headers)
            if order:
                payload["order"] = list(order)
            if body is not None:
                payload["body"] = body
            if cookies:
                payload["setCookie"] = list(cookies)
            line = _encode_request(payload)
            return _to_response(self._exchange(payload["id"], line))

    def close(self) -> None:
        """Stop the transport. Idempotent, and final.

        Waits for a request in flight, so that a session is never given up
        halfway through one.
        """
        with self._lock:
            self._closed = True
            self._stop()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- the transport -----------------------------------------------------

    def _exchange(self, request_id: int, line: str) -> dict[str, Any]:
        """Send one request and wait for the answer with that id."""
        deadline = time.monotonic() + self._timeout
        self._ensure_started()
        self._write(line)

        while True:
            try:
                line = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                # The transport is still working on this request — its own
                # deadline is longer — so an answer is not merely possible, it
                # is expected. Stopping it at the source is what keeps the
                # answer from arriving in the middle of the next request.
                self._stop()
                raise Timeout(f"tlsforge: request timed out after {self._timeout}s") from None

            if line is _EOF:
                # Stopped first, then asked: reaping is what makes the exit code
                # readable, and reading it before would report "still running"
                # for a process whose stdout has already ended.
                stopped = self._stop()
                assert stopped is not None  # started above, and the lock is ours
                raise TransportError(f"tlsforge: transport exited (code {stopped.returncode})")

            response = _decode(line)
            if response.get("id") != request_id:
                # Not an error: this is an abandoned answer arriving, the normal
                # aftermath of a timeout, and dropping it is the whole reason
                # every response carries an id.
                _report_stderr(
                    self._on_stderr,
                    f"dropping answer for request {response.get('id', '(none)')}, "
                    f"waiting on {request_id}"
                )
                continue
            return response

    def _ensure_started(self) -> None:
        if self._process is not None:
            return
        try:
            process = subprocess.Popen(  # noqa: S603 - the argv is this package's own
                [self._binary, *self._args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                # The transport emits JSON, which is UTF-8 by construction, so
                # this only fires in a world where raising would be worse than
                # a damaged line the decoder will reject anyway.
                errors="replace",
                bufsize=1,
            )
        except OSError as err:
            # A binary without its exec bit, a Linux binary in a macOS checkout,
            # a directory mounted noexec: ordinary, and one failed request
            # rather than a dead program.
            raise TransportError(
                f"tlsforge: transport failed to start ({self._binary}): {err}"
            ) from err

        self._process = process
        self._live.append(process)
        # A fresh queue per process, so that lines the previous one had already
        # written go nowhere: killing a process does not stop the bytes it wrote
        # from arriving, and one request's page resolving another's is the
        # failure this whole design is arranged around.
        self._lines = queue.Queue()
        _pump(process.stdout, self._lines, _EOF)
        _pump(process.stderr, None, None, self._on_stderr)

    def _write(self, line: str) -> None:
        assert self._process is not None and self._process.stdin is not None
        try:
            self._process.stdin.write(line)
            self._process.stdin.flush()
        except OSError as err:
            # The process can die between starting it and the bytes landing, and
            # a pipe whose reader is gone raises rather than returning short.
            self._stop()
            raise TransportError(f"tlsforge: write failed: {err}") from err

    def _stop(self) -> subprocess.Popen[str] | None:
        """End the process, if any, and hand it back reaped.

        The next request starts a fresh one. Returning it rather than dropping
        it is what lets a caller report the exit code, which only exists once
        the process has been waited on.
        """
        process, self._process = self._process, None
        if process is None:
            return None
        _kill(process)
        self._live.clear()
        return process


# --- module-level helpers, kept out of the class so a finalizer can hold them --


def _ignore(_line: str) -> None:
    """The default stderr sink: the transport's commentary is not everyone's."""


def _report_stderr(callback: Callable[[str], None], line: str) -> None:
    """Keep a diagnostic callback from taking down a reader or request."""
    try:
        callback(line)
    except Exception:
        pass


def _build_args(
    *,
    profile: str | None,
    proxy: str | None,
    insecure: bool,
    cookie_file: str | os.PathLike[str] | None,
    cookie_set: str | None,
    transport_timeout: float,
) -> list[str]:
    args = ["daemon"]
    for flag, value in (
        ("--profile", profile),
        ("--proxy", proxy),
        ("--cookies", cookie_file),
        ("--cookie-set", cookie_set),
    ):
        if value:
            args += [flag, os.fspath(value) if isinstance(value, (str, Path, os.PathLike)) else value]
    if insecure:
        args.append("--insecure")
    args += ["--timeout", f"{math.ceil(transport_timeout)}s"]
    return args


def _pump(
    stream: Any,
    sink: queue.Queue[Any] | None,
    sentinel: Any,
    callback: Callable[[str], None] | None = None,
) -> None:
    """Read a stream to its end on a thread of its own.

    A thread rather than a select loop because a pipe is not selectable on
    Windows, and this has to work there.
    """

    def read() -> None:
        # The stream is this thread's to close, because this thread is the one
        # that can be parked inside it. See _kill.
        with stream:
            for line in stream:
                if sink is not None:
                    sink.put(line)
                else:
                    _report_stderr(callback, line.rstrip("\r\n"))  # type: ignore[arg-type]
        if sink is not None:
            sink.put(sentinel)

    # Daemon threads: a stream that never ends must not be able to keep the
    # interpreter from exiting.
    threading.Thread(target=read, daemon=True).start()


def _kill(process: subprocess.Popen[str]) -> None:
    """End a transport process.

    Closing stdin is the transport's own shutdown signal: it reads the protocol
    until end of input and returns, which lets it finish whatever it does on the
    way out. The short grace is for that and no longer, since it holds nothing
    that needs flushing today; a signal is the fallback for a transport that
    does not take the hint, and SIGKILL the fallback for one that ignores that.

    stdout and stderr are deliberately NOT closed here. They belong to their
    reader threads, which close them when the stream ends, and closing one from
    here would block: close() wants the buffer's lock and a thread parked in
    read() is holding it — for as long as anything still holds the write end,
    which may be something the transport left behind. Measured: a grandchild
    outliving its parent turned close() into a thirty-second wait.
    """
    assert process.stdin is not None  # always a pipe: this module opened it
    try:
        process.stdin.close()
    except OSError:
        # close() flushes, and flushing into a pipe whose reader has gone raises
        # rather than returning short. The process is being ended anyway.
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=_SHUTDOWN_GRACE)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _kill_all(live: list[subprocess.Popen[str]]) -> None:
    """The finalizer: whatever this client still had running, stop it."""
    while live:
        _kill(live.pop())


def _decode(line: str) -> dict[str, Any]:
    """One line of the protocol, or an explanation of why it is not one."""
    try:
        response = json.loads(line)
    except ValueError as err:
        # A line that is not a response cannot be attributed to anything: the id
        # lives inside the thing that failed to parse. The request in flight
        # pays for it, and the process is kept — the id on every response means
        # a stream that rights itself is not mistaken for one that has not.
        raise TransportError(f"tlsforge: bad response: {err}") from err
    if not isinstance(response, dict):
        # `null`, `7` and `[]` are all valid JSON and none can carry an id.
        raise TransportError(f"tlsforge: bad response: expected an object, got {line[:40]!r}")
    return response


def _encode_request(payload: dict[str, Any]) -> str:
    """Encode before a request reaches the process or the in-flight state."""
    try:
        return json.dumps(payload, separators=(",", ":")) + "\n"
    except (TypeError, ValueError) as err:
        # Circular values and objects JSON does not support are caller errors.
        # They must not stop the daemon and discard the warmed session.
        raise ValueError(f"tlsforge: request cannot be encoded as JSON: {err}") from err


def _to_response(payload: dict[str, Any]) -> Response:
    error = payload.get("error")
    if error is not None and not isinstance(error, str):
        raise TransportError('tlsforge: bad response: field "error" must be a string')
    if error:
        raise RequestFailed(error)

    status = payload.get("status")
    url = payload.get("url")
    body = payload.get("body")
    raw_headers = payload.get("headers")
    raw_cookies = payload.get("cookies")

    status = 0 if status is None else status
    url = "" if url is None else url
    body = "" if body is None else body
    raw_headers = {} if raw_headers is None else raw_headers
    raw_cookies = [] if raw_cookies is None else raw_cookies

    if type(status) is not int:
        raise TransportError('tlsforge: bad response: field "status" must be an integer')
    if not isinstance(url, str):
        raise TransportError('tlsforge: bad response: field "url" must be a string')
    if not isinstance(body, str):
        raise TransportError('tlsforge: bad response: field "body" must be a string')
    if not isinstance(raw_headers, dict):
        raise TransportError('tlsforge: bad response: field "headers" must be an object')
    if not isinstance(raw_cookies, list) or not all(
        isinstance(cookie, str) for cookie in raw_cookies
    ):
        raise TransportError(
            'tlsforge: bad response: field "cookies" must be an array of strings'
        )

    headers: dict[str, tuple[str, ...]] = {}
    for name, values in raw_headers.items():
        # Accept one release of the old scalar protocol during upgrades while
        # exposing the lossless tuple shape consistently.
        if isinstance(values, str):
            headers[str(name)] = (values,)
        elif isinstance(values, list) and all(isinstance(value, str) for value in values):
            headers[str(name)] = tuple(values)
        else:
            raise TransportError(
                f'tlsforge: bad response: header "{name}" must be a string '
                "or an array of strings"
            )

    return Response(
        status=status,
        url=url,
        body=body,
        headers=headers,
        cookies=tuple(raw_cookies),
    )
