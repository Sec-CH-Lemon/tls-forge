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

import base64
import binascii
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
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence, TypedDict

from ._binary import resolve_binary
from ._errors import RequestFailed, SessionReset, Timeout, TransportError, Unsupported

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

#: What a request made after close() is told, and one close() ended.
_CLOSED = "tlsforge: this client was closed and will not respawn; construct a new one"
_CLOSED_IN_FLIGHT = "tlsforge: client closed"

#: The most a request can be as the transport reads it: one line of JSON, its
#: newline included, in UTF-8. A longer one would end the transport, and the
#: session in it, so it is refused before it is sent.
MAX_REQUEST_BYTES = 16 * 1024 * 1024


class _BrowserContextKind(TypedDict):
    kind: Literal["navigation", "form", "fetch", "xhr"]
    """What sends the request."""


class BrowserContext(_BrowserContextKind, total=False):
    """What in a browser a request stands for: it goes out as Chrome sends that
    kind, CORS and all. See GO.md, «Browser contexts».

    The keys are this package's names for the daemon's fields, which the client
    sends as the daemon names them: ``referrer_policy`` is its
    ``referrerPolicy``. A key there is none of is a TypeError.
    """

    initiator: str
    """The URL of the page that sends it. A form, fetch() and an XHR need one;
    a navigation without one is typed into the address bar."""
    referrer_policy: Literal[
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ]
    """That page's referrer policy; strict-origin-when-cross-origin when
    omitted."""
    mode: Literal["cors", "no-cors", "same-origin"]
    """fetch()'s request mode; cors when omitted. Only for fetch()."""
    credentials: Literal["same-origin", "include", "omit"]
    """fetch()'s credentials mode; same-origin when omitted. An XHR takes
    same-origin or include, which is withCredentials."""


#: Each key of a browser context, and the daemon's name for it.
_CONTEXT_FIELDS = {
    "kind": "kind",
    "initiator": "initiator",
    "referrer_policy": "referrerPolicy",
    "mode": "mode",
    "credentials": "credentials",
}


def _wire_context(context: Mapping[str, Any]) -> dict[str, Any]:
    """A browser context as the daemon names its fields.

    One that is no mapping, or has a key there is none of, the daemon's own
    spelling of one included, is a mistake in the call, said before anything
    is asked.
    """
    if not isinstance(context, Mapping):
        raise TypeError(f"tlsforge: browser_context must be a mapping, not {type(context).__name__}")
    for key in context:
        if key not in _CONTEXT_FIELDS:
            raise TypeError(
                f"tlsforge: browser_context has no key {key!r}; it takes {', '.join(_CONTEXT_FIELDS)}"
            )
    return {_CONTEXT_FIELDS[key]: value for key, value in context.items()}


@dataclass(frozen=True)
class Response:
    """What came back."""

    status: int
    url: str
    """The final URL, after redirects."""
    body: str
    """The response as text. Bytes that are not valid UTF-8 appear as U+FFFD;
    use `content` when the response is not text."""
    content: bytes = b""
    """The response as bytes, exactly as they arrived. This is the one to use
    for images, archives, or any body that is not text."""
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


@dataclass(frozen=True)
class Hello:
    """What a transport is, as it says when asked: the protocol it speaks, and
    what it can do that a client has to ask about before relying on it. One
    older than the question speaks protocol 1 and can do nothing it is asked
    about."""

    protocol: int
    capabilities: tuple[str, ...]


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
        self._proxy = proxy or None
        self._args = _build_args(
            profile=profile,
            proxy=proxy,
            insecure=insecure,
            cookie_file=cookie_file,
            cookie_set=cookie_set,
            transport_timeout=self._timeout + _TRANSPORT_GRACE,
        )

        # One request at a time holds the lock, for as long as it takes. The
        # state lock is held only for a moment, by whatever starts, stops or
        # writes to the process, so that close() never waits for a request.
        self._lock = threading.Lock()
        self._state = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[Any] = queue.Queue()
        # The thread writing a request now, if one is: a write stuck on a pipe
        # the transport stopped reading holds the stream until the process is
        # stopped, so whoever stops it has to know to stop it first.
        self._writer: threading.Thread | None = None

        # Never reset, not even across a restart. An id must never name two
        # different requests on one client, or a late answer from the process we
        # killed can match the request that replaced it — the exact crossing the
        # id exists to prevent.
        self._sequence = 0
        self._closed = False

        # How many transports with a session in them have gone, and why the
        # last did. A request notes the count when it is made, so that every
        # one waiting for the lock when a session goes is told with
        # SessionReset; untold says nobody has been, so the next one made is.
        self._losses = 0
        self._why = ""
        self._untold = False

        # The transport's answer to hello, asked once: what a binary is does
        # not change between its processes.
        self._hello: Hello | None = None

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
        browser_context: BrowserContext | None = None,
    ) -> Response:
        """GET a URL."""
        return self.request(
            url, method="GET", headers=headers, order=order, cookies=cookies,
            browser_context=browser_context,
        )

    def post(
        self,
        url: str,
        body: str | bytes = "",
        *,
        headers: Mapping[str, str] | None = None,
        order: Sequence[str] | None = None,
        cookies: Iterable[str] | None = None,
        browser_context: BrowserContext | None = None,
    ) -> Response:
        """POST a body."""
        return self.request(
            url, method="POST", body=body, headers=headers, order=order, cookies=cookies,
            browser_context=browser_context,
        )

    def hello(self) -> Hello:
        """What the transport is: the protocol it speaks and what it can do,
        asked without a connection, and once. One older than the question speaks
        protocol 1, and can do nothing a client has to ask about.

        :raises TransportError: the transport would not start, died, or spoke
            nonsense; asked again next time.
        :raises Timeout: the deadline passed with no answer; asked again next
            time.
        """
        if self._hello is not None:
            return self._hello
        deadline = time.monotonic() + self._timeout
        if not self._lock.acquire(timeout=self._timeout):
            raise Timeout(
                f"tlsforge: hello timed out after {self._timeout}s waiting for the request before it, "
                "and was not asked"
            )
        try:
            self._reap()
            self._sequence += 1
            asked = self._sequence
            self._hello = _hello_of(
                self._exchange(asked, _encode_request({"id": asked, "control": "hello"}), deadline)
            )
        finally:
            self._lock.release()
        return self._hello

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        order: Sequence[str] | None = None,
        body: str | bytes | None = None,
        cookies: Iterable[str] | None = None,
        browser_context: BrowserContext | None = None,
    ) -> Response:
        """Make a request.

        :param headers: layered over the profile's. A name the profile already
            sends keeps the browser's position and takes your value; one it does
            not send is appended after the rest.
        :param order: the order of the headers *you* send. Without it they go
            last, sorted.
        :param cookies: ``name=value`` pairs added to the jar before the request.
        :param browser_context: the browser context the request is made in, by
            this package's names (:class:`BrowserContext`), sent only to a
            transport that says, when asked with :meth:`hello`, that it applies
            one.
        :raises RequestFailed: the request ran and failed — refused, DNS, TLS.
        :raises TransportError: the transport would not start, died, or spoke
            nonsense. The client stays usable.
        :raises Timeout: the deadline passed with no answer.
        :raises Unsupported: a browser context, to a transport that does not
            apply one; the request was not sent.
        :raises TypeError: a browser context that is no mapping, or has a key
            there is none of; nothing was asked.
        """
        if not url:
            raise ValueError("tlsforge: request needs a url")
        context = None if browser_context is None else _wire_context(browser_context)
        if context is not None:
            hello = self.hello()
            if "browser_context" not in hello.capabilities:
                raise Unsupported(
                    f"tlsforge: the tls-forge at {self._binary} speaks protocol {hello.protocol} "
                    "and does not apply browser contexts; the request was not sent"
                )

        # The call's deadline, from now: the time a request waits for the one
        # before it is part of it.
        deadline = time.monotonic() + self._timeout
        made_in = self._losses
        if not self._lock.acquire(timeout=self._timeout):
            raise Timeout(
                f"tlsforge: request timed out after {self._timeout}s waiting for the one before it, "
                "and was not sent"
            )
        try:
            return self._request(
                made_in, deadline, url, method, headers, order, body, cookies, context
            )
        finally:
            self._lock.release()

    def _reap(self) -> None:
        """Note, with the lock held, a transport that went while nobody was
        asking it anything: it took the session with it, and the next request
        is told rather than written to a pipe nobody reads."""
        with self._state:
            if self._closed:
                raise TransportError(_CLOSED)
            gone = self._process if self._process is not None and self._process.poll() is not None else None
            if gone is not None:
                self._process = None
                self._live.clear()
        if gone is not None:
            _kill(gone)
            self._lose(f"it exited (code {gone.returncode})")

    def _request(
        self,
        made_in: int,
        deadline: float,
        url: str,
        method: str,
        headers: Mapping[str, str] | None,
        order: Sequence[str] | None,
        body: str | bytes | None,
        cookies: Iterable[str] | None,
        context: dict[str, Any] | None,
    ) -> Response:
        """The request, made with the lock held: its browser context, if any, as
        the daemon names its fields."""
        self._reap()
        self._sequence += 1
        payload: dict[str, Any] = {"id": self._sequence, "method": method, "url": url}
        if headers:
            payload["headers"] = dict(headers)
        if order:
            payload["order"] = list(order)
        if body is not None:
            # Bytes travel as base64: a JSON string cannot hold arbitrary
            # bytes, and the transport would replace every one that is not
            # valid UTF-8 with U+FFFD rather than report a problem.
            if isinstance(body, (bytes, bytearray)):
                payload["body"] = base64.b64encode(bytes(body)).decode("ascii")
                payload["bodyEncoding"] = "base64"
            else:
                payload["body"] = body
        if cookies:
            payload["setCookie"] = list(cookies)
        if context is not None:
            payload["browser"] = context
        line = _encode_request(payload)
        if self._untold or made_in != self._losses:
            # Told, and not sent: made in a session that has gone, it would
            # not be what the caller asked for in a new one.
            self._untold = False
            raise SessionReset(
                f"tlsforge: the transport this client's session was in has gone ({self._why}), "
                "and with it its cookies, TLS sessions and connections; this request was not "
                "sent, and the next one starts a new session"
            )
        return _to_response(self._exchange(payload["id"], line, deadline))

    def close(self) -> None:
        """Stop the transport. Idempotent, and final.

        At once: a request in flight, or one waiting for it, is not waited for,
        and raises TransportError. A write stuck on a pipe the transport has
        stopped reading is ended by stopping the transport first.
        """
        with self._state:
            self._closed = True
        self._stop()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- the transport -----------------------------------------------------

    def _exchange(self, request_id: int, line: str, deadline: float) -> dict[str, Any]:
        """Send one request and wait, until the deadline, for the answer with that id."""
        if self._process is None and self._proxy is not None:
            self._init(deadline)
        self._write(line, deadline)
        return self._answer(request_id, deadline)

    def _init(self, deadline: float) -> None:
        """Start a transport and tell it its proxy, on the first line of its
        input. Until it answers that it takes requests there is no session:
        whatever keeps it from saying so stops it, and loses none, and the
        next request starts another, told its proxy first."""
        self._sequence += 1
        init_id = self._sequence
        ready = False
        try:
            line = _encode_request({"id": init_id, "control": "init", "proxy": self._proxy})
            self._write(line, deadline, session=False)
            error = self._answer(init_id, deadline, session=False).get("error")
            if error is not None:
                raise TransportError(f"tlsforge: the transport did not take its proxy: {error}")
            ready = True
        finally:
            if not ready:
                # Refused, timed out, garbled, gone, or the caller interrupted
                # it: a transport half started is not one to send a request to.
                self._stop()

    def _answer(self, request_id: int, deadline: float, session: bool = True) -> dict[str, Any]:
        """Wait, until the deadline, for the answer with request_id: in a
        session, which a transport that ends loses, unless it is the init line,
        before any."""
        while True:
            try:
                line = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                # The transport is still working on this request — its own
                # deadline is longer — so an answer is not merely possible, it
                # is expected. Stopping it at the source is what keeps the
                # answer from arriving in the middle of the next request.
                self._stop()
                if session:
                    self._lose("a request timed out, and it was stopped")
                raise Timeout(f"tlsforge: request timed out after {self._timeout}s") from None

            if line is _EOF:
                # Stopped first, then asked: reaping is what makes the exit code
                # readable, and reading it before would report "still running"
                # for a process whose stdout has already ended.
                stopped = self._stop()
                if stopped is None:
                    # close() stopped it, while this request waited.
                    raise TransportError(_CLOSED_IN_FLIGHT)
                if stopped.returncode == 2:
                    raise TransportError(_refused_arguments(self._binary, self._proxy is not None))
                if session:
                    self._lose(f"it exited (code {stopped.returncode})")
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

    def _start(self) -> None:
        """Start a process, with the state lock held."""
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

    def _write(self, line: str, deadline: float, session: bool = True) -> None:
        """Write a request to the process, giving up on it at the deadline: in a
        session, which a write that fails loses, unless it is the init line,
        before any.

        On a thread of its own. A write blocks for as long as the pipe is full,
        which is for as long as the process does not read it, and a deadline
        that did not cover the write was one a process that stopped reading
        could hold a caller past for as long as it lived.
        """
        failed: list[BaseException] = []
        with self._state:
            if self._closed:
                # close() came after this request was made, and before now.
                raise TransportError(_CLOSED_IN_FLIGHT)
            if self._process is None:
                self._start()
            assert self._process is not None and self._process.stdin is not None
            stream = self._process.stdin

            def write() -> None:
                try:
                    stream.write(line)
                    stream.flush()
                except (OSError, ValueError) as err:
                    # A pipe whose reader is gone raises rather than returning
                    # short, and one closed under the write says it is closed.
                    failed.append(err)

            writer = threading.Thread(target=write, daemon=True)
            self._writer = writer
            writer.start()

        writer.join(max(0.0, deadline - time.monotonic()))
        if writer.is_alive():
            # Still writing at the deadline: the process has stopped reading,
            # and is stopped, which ends the write.
            self._stop()
            if session:
                self._lose("a request timed out, and it was stopped")
            raise Timeout(f"tlsforge: request timed out after {self._timeout}s")
        with self._state:
            if self._writer is writer:
                self._writer = None
            closed = self._closed
        if failed:
            if closed:
                raise TransportError(_CLOSED_IN_FLIGHT) from failed[0]
            # The process can die between starting it and the bytes landing.
            self._stop()
            if session:
                self._lose(f"a request could not be written to it: {failed[0]}")
            raise TransportError(f"tlsforge: write failed: {failed[0]}") from failed[0]

    def _lose(self, why: str) -> None:
        """Note that the transport the session was in has gone, and why."""
        self._losses += 1
        self._why = why
        self._untold = True

    def _stop(self) -> subprocess.Popen[str] | None:
        """End the process, if any, and hand it back reaped.

        The next request starts a fresh one. Returning it rather than dropping
        it is what lets a caller report the exit code, which only exists once
        the process has been waited on.
        """
        with self._state:
            process, self._process = self._process, None
            writer, self._writer = self._writer, None
            self._live.clear()
        if process is None:
            return None
        _kill(process, writer)
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


def _refused_arguments(binary: str, proxied: bool) -> str:
    """Why a transport that exited at once with a usage error failed.

    With a proxy, that is a tls-forge older than this package, which does not
    know ``--proxy-stdin``; it never got as far as making a request.
    """
    said = f"tlsforge: the transport at {binary} refused its arguments (code 2)"
    if not proxied:
        return said
    return (
        f"{said}: a tls-forge older than this package does not know --proxy-stdin, which keeps "
        "the proxy's password off its command line and out of its environment; use the tls-forge "
        "this package came with"
    )


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
        ("--cookies", cookie_file),
        ("--cookie-set", cookie_set),
    ):
        if value:
            args += [flag, os.fspath(value) if isinstance(value, (str, Path, os.PathLike)) else value]
    if proxy:
        # The proxy goes on the transport's input, in the first line it reads:
        # ``ps`` shows a command line, password and all, to every user of the
        # machine, and the environment is the process's owner's to read.
        args.append("--proxy-stdin")
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


def _kill(process: subprocess.Popen[str], writer: threading.Thread | None = None) -> None:
    """End a transport process.

    A write stuck on a pipe the process stopped reading holds the stream for as
    long as it is stuck, and closing the stream would wait for it: when one is,
    the process is killed first, which ends the write, and then shut down as
    any other.

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
    if writer is not None and writer.is_alive():
        process.kill()
        process.wait()
        writer.join()
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


def _hello_of(response: dict[str, Any]) -> Hello:
    """What a transport is, as its answer to hello says. One older than control
    lines answers it as a request with no url: protocol 1, nothing it can do."""
    if response.get("error") is not None:
        return Hello(1, ())
    protocol = response.get("protocol")
    capabilities = response.get("capabilities", [])
    if (
        not isinstance(protocol, int)
        or protocol < 2
        or not isinstance(capabilities, list)
        or not all(isinstance(name, str) for name in capabilities)
    ):
        said = json.dumps({"protocol": protocol, "capabilities": capabilities}, separators=(",", ":"))
        raise TransportError(
            "tlsforge: bad response: hello must give a protocol from 2 and a list of capabilities, "
            f"not {said}"
        )
    return Hello(protocol, tuple(capabilities))


def _encode_request(payload: dict[str, Any]) -> str:
    """Encode before a request reaches the process or the in-flight state."""
    try:
        line = json.dumps(payload, separators=(",", ":")) + "\n"
    except (TypeError, ValueError) as err:
        # Circular values and objects JSON does not support are caller errors.
        # They must not stop the daemon and discard the warmed session.
        raise ValueError(f"tlsforge: request cannot be encoded as JSON: {err}") from err
    # json.dumps writes ASCII, every other character escaped, so the length of
    # the line is its size in bytes: base64 and the newline included. The
    # transport cannot read a longer line, and stops at one.
    if len(line) > MAX_REQUEST_BYTES:
        raise ValueError(
            f"tlsforge: this request is {len(line)} bytes as the transport reads it, "
            f"more than the {MAX_REQUEST_BYTES} it can: send a smaller body"
        )
    return line


def _to_response(payload: dict[str, Any]) -> Response:
    error = payload.get("error")
    if error is not None and not isinstance(error, str):
        raise TransportError('tlsforge: bad response: field "error" must be a string')
    if error:
        raise RequestFailed(error)

    status = payload.get("status")
    url = payload.get("url")
    body = payload.get("body")
    body_encoding = payload.get("bodyEncoding")
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
    if body_encoding is not None and not isinstance(body_encoding, str):
        raise TransportError(
            'tlsforge: bad response: field "bodyEncoding" must be a string'
        )

    # An absent encoding means the body is the text itself, which is every text
    # response and so the overwhelming majority of them.
    if body_encoding in (None, "", "utf8"):
        content = body.encode("utf-8", "surrogatepass")
    elif body_encoding == "base64":
        try:
            content = base64.b64decode(body, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise TransportError(
                f"tlsforge: bad response: body is not valid base64: {exc}"
            ) from exc
        # The text view stays useful for a body that is mostly text, and lossy
        # by definition for one that is not — which is what `content` is for.
        body = content.decode("utf-8", "replace")
    else:
        raise TransportError(
            f'tlsforge: bad response: unknown bodyEncoding "{body_encoding}"'
        )
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
        content=content,
        headers=headers,
        cookies=tuple(raw_cookies),
    )
