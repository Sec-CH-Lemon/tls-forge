from __future__ import annotations

import dataclasses
import gc
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

import tlsforge
from tlsforge import Client, RequestFailed, Response, Timeout, TransportError
from tlsforge import _client


# --- the ordinary path -----------------------------------------------------


def test_get_returns_the_transport_response(client):
    res = client().get("https://ok/page")
    assert res.status == 200
    assert res.url == "https://ok/page"
    assert res.headers["content-type"] == ("application/json",)
    assert res.headers["set-cookie"] == ("a=1", "b=2")
    assert res.ok


def test_a_response_has_the_fields_it_documents_and_no_other(client):
    # A field a daemon newer than this package adds is passed over, not an error.
    response = client().get("https://newer-fields/x")
    assert [f.name for f in dataclasses.fields(response)] == ["status", "url", "body", "content", "headers", "cookies"]
    assert response.status == 200 and response.url == "https://newer-fields/x"
    assert not hasattr(response, "teleport")


def test_headers_order_and_cookies_reach_the_transport(client):
    res = client().get(
        "https://ok/x",
        headers={"referer": "https://example.com"},
        order=["referer", "user-agent"],
        cookies=["a=1", "b=2"],
    )
    echoed = res.json()
    assert echoed["method"] == "GET"
    assert echoed["headers"] == {"referer": "https://example.com"}
    assert echoed["order"] == ["referer", "user-agent"]
    assert echoed["cookies"] == ["a=1", "b=2"]


def test_post_sends_a_body(client):
    res = client().post("https://ok/submit", "hello=world")
    echoed = res.json()
    assert echoed["method"] == "POST"
    assert echoed["body"] == "hello=world"


def test_an_empty_post_body_is_still_sent(client):
    # "" is a body, and `if body:` would drop it. A POST with no body and a POST
    # with an empty one are different requests to a server that reads
    # content-length.
    assert client().post("https://ok/x").json()["body"] == ""


def test_request_defaults_to_get_and_omits_what_was_not_asked_for(client):
    echoed = client().request("https://ok/x").json()
    assert echoed["method"] == "GET"
    assert echoed["headers"] == {}
    assert echoed["order"] == []
    assert echoed["cookies"] == []
    assert echoed["body"] is None


def test_requests_queue_and_are_answered_in_order(client):
    one = client()
    assert [one.get(f"https://ok/{n}").url for n in range(3)] == [
        "https://ok/0",
        "https://ok/1",
        "https://ok/2",
    ]


def test_a_client_is_reused_rather_than_respawned_per_request(client):
    # One process for the whole session is the entire point: one fingerprint,
    # one jar, one exit IP. A client that respawned would have none of them.
    one = client()
    one.get("https://ok/1")
    first = one._process
    one.get("https://ok/2")
    assert one._process is first


def test_null_fields_come_back_as_empty_rather_than_none(client):
    # The transport really does send `"headers": null` on a failure, and a
    # caller reaching into None would get an AttributeError instead of an answer.
    # And every field null.
    for scenario in ("null-fields", "null-values"):
        res = client().get(f"https://{scenario}/x")
        assert res.headers == {}
        assert res.cookies == ()
        assert res.status == 0
        assert res.url == "" and res.body == ""
        assert not res.ok


# --- the options -----------------------------------------------------------


def test_the_options_become_the_transport_argv(client, tmp_path):
    jar = tmp_path / "cookies.json"
    res = client(
        profile="chrome_151",
        proxy="http://user:pass@host:8080",
        insecure=True,
        cookie_file=jar,
        cookie_set="warm-eu",
        timeout=20,
    ).get("https://ok/x")
    argv = res.json()["argv"]
    assert argv[0] == "daemon"
    for flag, value in (
        ("--profile", "chrome_151"),
        ("--cookies", str(jar)),
        ("--cookie-set", "warm-eu"),
    ):
        assert argv[argv.index(flag) + 1] == value
    assert "--insecure" in argv
    # The proxy on the transport's input, and never the URL on its command line.
    assert "--proxy-stdin" in argv
    assert not any("pass" in arg for arg in argv)


def test_a_proxy_reaches_its_own_process_on_its_input(client, monkeypatch):
    # Off the command line, which `ps` shows every user of the machine, and out
    # of the environment, which the process's owner can read: on the first line
    # of the client's own process. Two clients do not get each other's, and
    # this process's environment is left as it was.
    monkeypatch.delenv("TLSFORGE_PROXY", raising=False)
    one = client(proxy="http://alice:s3cret-one@proxy.test:8080").get("https://ok/x").json()
    two = client(proxy="socks5://bob:s3cret-two@proxy.test:1080").get("https://ok/x").json()
    plain = client().get("https://ok/x").json()
    for echoed, proxy in (
        (one, "http://alice:s3cret-one@proxy.test:8080"),
        (two, "socks5://bob:s3cret-two@proxy.test:1080"),
    ):
        assert echoed["proxy"] == proxy
        assert echoed["env"]["TLSFORGE_PROXY"] is None
        assert "--proxy-stdin" in echoed["argv"]
        assert "s3cret" not in " ".join(echoed["argv"])
    assert plain["env"]["TLSFORGE_PROXY"] is None
    assert not any(arg.startswith("--proxy") for arg in plain["argv"])
    assert "TLSFORGE_PROXY" not in os.environ


def test_a_variable_this_process_has_is_not_a_proxy_unless_named(client, monkeypatch):
    # Inherited, it is not named on the command line, and the transport reads
    # the variable only when it is; named, the client's own replaces it.
    monkeypatch.setenv("TLSFORGE_PROXY", "http://someone:else@elsewhere.test:3128")
    inherited = client().get("https://ok/x").json()
    assert not any(arg.startswith("--proxy") for arg in inherited["argv"])
    own = client(proxy="http://mine.test:8080").get("https://ok/x").json()
    assert own["proxy"] == "http://mine.test:8080"
    assert os.environ["TLSFORGE_PROXY"] == "http://someone:else@elsewhere.test:3128"


def test_a_transport_older_than_the_client_is_said_to_be(client, monkeypatch):
    monkeypatch.setenv("TLSFORGE_TEST_REFUSE", "proxy-stdin")
    c = client(proxy="http://alice:s3cret@proxy.test:8080")
    older = (
        r"refused its arguments \(code 2\): a tls-forge older than this package "
        r"does not know --proxy-stdin"
    )
    with pytest.raises(tlsforge.TransportError, match=older) as refused:
        c.get("https://ok/a")
    assert "s3cret" not in str(refused.value)
    # Asked again, it is asked of a new process, which says the same.
    with pytest.raises(tlsforge.TransportError, match=older):
        c.get("https://ok/b")


@pytest.mark.parametrize(
    ("mode", "error", "says"),
    [
        ("refuse", tlsforge.TransportError,
         r"^tlsforge: the transport did not take its proxy: the init line's proxy "
         r"http://alice:\*\*\*@proxy\.test:8080 is no proxy$"),
        ("exit", tlsforge.TransportError, r"^tlsforge: transport exited \(code 3\)$"),
        ("silent", tlsforge.Timeout, r"^tlsforge: request timed out"),
        ("garbage", tlsforge.TransportError, r"^tlsforge: bad response: "),
    ],
)
def test_a_transport_that_will_not_take_its_proxy_starts_no_session(client, monkeypatch, mode, error, says):
    # Refused, unanswered, garbled or gone before it answers the init line:
    # the request fails with why, without the password, and the next is not
    # told a session went. The transport is stopped, so the next request
    # starts another, told the proxy first: one kept would take it unasked.
    monkeypatch.setenv("TLSFORGE_TEST_INIT", mode)
    c = client(proxy="http://alice:s3cret@proxy.test:8080", timeout=0.5)
    for url in ("https://ok/a", "https://ok/b"):
        with pytest.raises(error, match=says) as failed:
            c.get(url)
        assert "s3cret" not in str(failed.value)
        assert not isinstance(failed.value, tlsforge.SessionReset)
        assert c._process is None
    monkeypatch.setenv("TLSFORGE_TEST_INIT", "")
    assert c.get("https://ok/b").json()["proxy"] == "http://alice:s3cret@proxy.test:8080"


#: A proxy longer than a pipe holds, so that its init line waits on a
#: transport that does not read it.
_LONG_PROXY = "http://alice:s3cret@proxy.test:8080/" + "x" * (1 << 20)


@pytest.mark.parametrize(
    ("knob", "value", "error", "says"),
    [
        # Unread until the deadline: the write is given up on.
        ("TLSFORGE_TEST_DEAF_FOR", "10", tlsforge.Timeout, r"^tlsforge: request timed out after 0.5s$"),
        # Its input closed unread: the write fails.
        ("TLSFORGE_TEST_INIT", "deaf", tlsforge.TransportError, r"^tlsforge: write failed: "),
    ],
)
def test_an_init_line_the_transport_does_not_take_starts_no_session(client, monkeypatch, knob, value, error, says):
    monkeypatch.setenv(knob, value)
    c = client(proxy=_LONG_PROXY, timeout=0.5)
    with pytest.raises(error, match=says) as failed:
        c.get("https://ok/a")
    assert "s3cret" not in str(failed.value)
    assert c._process is None
    monkeypatch.delenv(knob)
    assert c.get("https://ok/b").json()["proxy"] == _LONG_PROXY


def test_a_transport_started_again_is_told_its_proxy_again_first(client):
    c = client(proxy="http://alice:s3cret@proxy.test:8080", timeout=0.5)
    first = c.get("https://ok/a").json()
    with pytest.raises(tlsforge.Timeout):
        c.get("https://silent/x")
    with pytest.raises(tlsforge.SessionReset):
        c.get("https://ok/b")
    after = c.get("https://ok/c").json()
    assert after["pid"] != first["pid"] and after["proxy"] == "http://alice:s3cret@proxy.test:8080"
    assert c.hello() == tlsforge.Hello(2, ())


def test_a_transport_that_refuses_its_arguments_without_a_proxy_says_only_that(client, monkeypatch):
    monkeypatch.setenv("TLSFORGE_TEST_REFUSE", "always")
    with pytest.raises(tlsforge.TransportError, match=r"refused its arguments \(code 2\)$"):
        client().get("https://ok/a")


def test_the_transport_gets_a_longer_deadline_than_ours(client):
    # If they were equal, a request timing out would race: both sides would
    # decide it had failed, and the process would be killed mid-answer.
    argv = client(timeout=20).get("https://ok/x").json()["argv"]
    assert argv[argv.index("--timeout") + 1] == "35s"


def test_no_options_means_no_flags_but_the_deadline(client):
    argv = client().get("https://ok/x").json()["argv"]
    assert argv == ["daemon", "--timeout", "60s"]


def test_a_path_option_may_be_a_string_as_well_as_a_path(client, tmp_path):
    argv = client(cookie_file=str(tmp_path / "c.json")).get("https://ok/x").json()["argv"]
    assert argv[argv.index("--cookies") + 1] == str(tmp_path / "c.json")


@pytest.mark.parametrize("bad", [0, -1, -0.5, float("nan"), float("inf")])
def test_a_timeout_that_is_not_positive_is_refused(wrapper, bad):
    # Zero would make every request time out before it was written, which reads
    # as "the network is broken" rather than "the argument is wrong".
    with pytest.raises(ValueError, match="timeout must be a positive finite number"):
        Client(binary=os.fspath(wrapper), timeout=bad)


def test_stderr_callback_must_be_callable(wrapper):
    with pytest.raises(TypeError, match="must be callable"):
        Client(binary=os.fspath(wrapper), on_stderr="log")


def test_cookie_set_requires_a_cookie_file(wrapper):
    with pytest.raises(ValueError, match="cookie_set requires cookie_file"):
        Client(binary=os.fspath(wrapper), cookie_set="warm-eu")


# --- failures --------------------------------------------------------------


def test_an_error_field_becomes_a_request_failure(client):
    with pytest.raises(RequestFailed, match="upstream refused"):
        client().get("https://error/x")


def test_a_request_with_no_url_is_refused_without_spawning_anything(client):
    one = client()
    with pytest.raises(ValueError, match="needs a url"):
        one.get("")
    assert one._process is None


def test_an_unencodable_request_does_not_discard_the_session(client):
    one = client()
    one.get("https://ok/before")
    process = one._process
    circular: dict[str, object] = {}
    circular["self"] = circular

    with pytest.raises(ValueError, match="request cannot be encoded as JSON"):
        one.get("https://ok/bad", headers=circular)  # type: ignore[arg-type]

    assert one._process is process
    assert one.get("https://ok/after").status == 200


def test_a_garbage_line_fails_the_request_rather_than_hanging(client):
    with pytest.raises(TransportError, match="bad response"):
        client().get("https://garbage/x")


def test_a_line_that_is_json_but_not_an_object_is_also_rejected(client):
    # `null`, `7` and `[]` are all valid JSON and none can carry an id.
    with pytest.raises(TransportError, match="bad response"):
        client().get("https://null-line/x")


@pytest.mark.parametrize(
    "behaviour",
    [
        "bad-error",
        "bad-status",
        "bad-url",
        "bad-body",
        "bad-headers",
        "bad-header-scalar",
        "bad-header-list",
        "bad-cookies",
        "bad-cookie-item",
    ],
)
def test_a_malformed_response_is_rejected_without_breaking_the_client(client, behaviour):
    one = client()
    with pytest.raises(TransportError, match="bad response"):
        one.get(f"https://{behaviour}/x")
    assert one.get("https://ok/after").status == 200


def test_the_client_survives_a_garbage_line(client):
    # The process is kept: one bad line does not prove the stream is broken, and
    # killing it would throw away the session. The id is what makes that safe.
    one = client()
    with pytest.raises(TransportError):
        one.get("https://garbage/x")
    assert one.get("https://ok/after").status == 200


def test_an_answer_for_another_id_is_dropped_not_mistaken_for_this_one(client):
    notes: list[str] = []
    res = client(on_stderr=notes.append).get("https://wrong-id/x")
    assert res.json()["method"] == "GET"  # the real answer, not the stray one
    assert any("dropping answer" in note for note in notes)


def test_a_response_with_no_id_at_all_is_dropped(client):
    # A binary older than the code driving it. Dropping it is right: an answer
    # that cannot say what it answers cannot be attributed to anything.
    notes: list[str] = []
    res = client(on_stderr=notes.append).get("https://no-id/x")
    assert res.status == 200
    assert any("(none)" in note for note in notes)


def test_a_request_that_is_never_answered_times_out(client):
    with pytest.raises(Timeout, match="timed out"):
        client(timeout=0.3).get("https://silent/x")


def test_a_timeout_is_also_a_builtin_timeout_error(client):
    # So that code already catching TimeoutError catches this without knowing
    # about this package.
    with pytest.raises(TimeoutError):
        client(timeout=0.3).get("https://silent/x")


def test_the_client_stays_usable_after_a_timeout(client):
    # Stopped, the transport took the session with it: the next request is
    # told, unsent, and the one after starts a new session.
    one = client(timeout=0.3)
    with pytest.raises(Timeout):
        one.get("https://silent/x")
    with pytest.raises(tlsforge.SessionReset, match=r"has gone \(a request timed out, and it was stopped\)"):
        one.get("https://ok/after")
    assert one.get("https://ok/after").status == 200


def test_a_timeout_stops_the_process_so_a_late_answer_cannot_arrive(client):
    # The transport's deadline is longer than ours, so an answer to the
    # abandoned request is not merely possible, it is expected.
    one = client(timeout=0.15)
    with pytest.raises(Timeout):
        one.get("https://slow/x")
    assert one._process is None
    with pytest.raises(tlsforge.SessionReset):
        one.get("https://ok/after")
    assert one.get("https://ok/after").json()["method"] == "GET"


def test_a_transport_that_exits_fails_the_request_in_flight(client):
    # The exit code is in the message, which means the process was reaped before
    # it was asked: reading the code first reports "still running" for something
    # whose stdout has already ended.
    with pytest.raises(TransportError, match=r"transport exited \(code 3\)"):
        client().get("https://exit/x")


def test_the_client_recovers_from_a_transport_that_exited(client):
    one = client()
    with pytest.raises(TransportError):
        one.get("https://exit/x")
    with pytest.raises(tlsforge.SessionReset, match=r"has gone \(it exited \(code 3\)\)"):
        one.get("https://ok/after")
    assert one.get("https://ok/after").status == 200


def test_stderr_is_forwarded_to_the_callback(client):
    notes: list[str] = []
    client(on_stderr=notes.append).get("https://stderr/x")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not any("a note on stderr" in n for n in notes):
        time.sleep(0.01)
    assert any("a note on stderr" in note for note in notes)


def test_an_exception_in_the_stderr_callback_does_not_break_the_client(client):
    def fail(_line: str) -> None:
        raise RuntimeError("callback failed")

    one = client(on_stderr=fail)
    assert one.get("https://stderr/x").status == 200
    assert one.get("https://ok/after").status == 200


def test_stderr_is_discarded_when_nobody_asked_for_it(client):
    # The default sink has to be reached, or a transport that says anything at
    # all would raise from a thread nobody is watching.
    assert client().get("https://stderr/x").status == 200


def test_legacy_scalar_headers_are_normalised(client):
    res = client().get("https://legacy-headers/x")
    assert res.headers == {"content-type": ("application/json",)}


def test_a_binary_that_cannot_be_executed_fails_the_request_not_the_process(tmp_path):
    not_executable = tmp_path / "not-executable"
    not_executable.write_text("not a program")
    not_executable.chmod(0o644)
    one = Client(binary=os.fspath(not_executable))
    with pytest.raises(TransportError, match="failed to start"):
        one.get("https://ok/x")
    one.close()


def test_a_write_into_a_dead_pipe_fails_that_request(deaf):
    # The process is alive but has stopped reading, so the write reaches a pipe
    # with no reader: the liveness check passed and the pipe died before the
    # bytes landed.
    one = Client(binary=os.fspath(deaf), timeout=5)
    assert one.get("https://deaf/first").status == 200
    with pytest.raises(TransportError, match="write failed|exited"):
        one.get("https://deaf/second")
    # The transport is stopped, and the session in it lost: the next request
    # is told so, unsent.
    with pytest.raises(tlsforge.SessionReset, match="could not be written|exited"):
        one.get("https://deaf/third")
    one.close()


def test_requests_waiting_when_the_session_goes_are_told_unsent(client):
    # Every thread waiting for the transport when its session goes is told,
    # and none of their requests is sent; the request after them starts a new
    # session.
    one = client(timeout=0.5)
    before = one.get("https://ok/before").json()["pid"]
    outcomes: dict[str, BaseException | None] = {}
    started = threading.Event()

    def asking(name: str, url: str) -> None:
        if name == "in flight":
            started.set()
        try:
            one.get(url)
            outcomes[name] = None
        except BaseException as err:  # noqa: BLE001 - recorded, and asserted below
            outcomes[name] = err

    first = threading.Thread(target=asking, args=("in flight", "https://silent/x"))
    first.start()
    started.wait()
    time.sleep(0.1)
    waiting = [threading.Thread(target=asking, args=(f"waiting {n}", "https://ok/waiting")) for n in (1, 2)]
    for thread in waiting:
        thread.start()
    for thread in [first, *waiting]:
        thread.join()
    assert isinstance(outcomes["in flight"], Timeout)
    for name in ("waiting 1", "waiting 2"):
        assert isinstance(outcomes[name], tlsforge.SessionReset), outcomes[name]
        assert "was not sent" in str(outcomes[name])
    assert one.get("https://ok/after").json()["pid"] != before


def test_a_transport_that_dies_while_nobody_asks_tells_the_next_request(client):
    one = client()
    first = one.get("https://answer-then-exit/x").json()["pid"]
    time.sleep(0.3)
    with pytest.raises(tlsforge.SessionReset, match=r"it exited \(code 4\)"):
        one.get("https://ok/after")
    assert one.get("https://ok/again").json()["pid"] != first


def _sized(size: int, request_id: int, char: str = "x") -> tuple[str, str]:
    """A POST whose line is exactly size bytes as the transport reads it, made
    as the request_id-th request of its client, its body one character
    repeated: ASCII a byte each, anything else six, escaped."""
    url = "https://ok/sized"
    encoded = lambda body: (  # noqa: E731 - read in two places just below
        json.dumps({"id": request_id, "method": "POST", "url": url, "body": body}, separators=(",", ":")) + "\n"
    )
    overhead = len(encoded(""))
    each = len(encoded(char)) - overhead
    count = (size - overhead) // each
    body = char * count + "x" * (size - overhead - count * each)
    assert len(encoded(body).encode()) == size
    return url, body


def test_a_request_is_measured_as_the_transport_reads_it(client):
    one = client(timeout=30)
    first = one.get("https://ok/first").json()["pid"]
    request_id = 1
    for size, char in ((tlsforge.MAX_REQUEST_BYTES - 1, "x"), (tlsforge.MAX_REQUEST_BYTES, "x"),
                       (tlsforge.MAX_REQUEST_BYTES, "я")):
        request_id += 1
        url, body = _sized(size, request_id, char)
        echoed = one.post(url, body).json()
        assert echoed["bodyLength"] == len(body)
        assert echoed["pid"] == first
    # One byte more, in bytes rather than characters: refused before it is
    # sent, and the session it would have ended is the one the next request is
    # made in.
    for char in ("x", "я"):
        request_id += 1
        url, body = _sized(tlsforge.MAX_REQUEST_BYTES + 1, request_id, char)
        with pytest.raises(ValueError, match=rf"is {tlsforge.MAX_REQUEST_BYTES + 1} bytes .* more than"):
            one.post(url, body)
    # Bytes travel as base64, four characters for every three.
    with pytest.raises(ValueError, match="more than"):
        one.post("https://ok/binary", bytes(tlsforge.MAX_REQUEST_BYTES // 4 * 3))
    assert one.get("https://ok/after").json()["pid"] == first


# --- deadlines -------------------------------------------------------------

#: More than any pipe holds, so that writing it waits for the reader.
_BIG = "x" * (4 * 1024 * 1024)


def _settled(baseline: int) -> bool:
    """Whether the threads a request started have ended, within a while."""
    deadline = time.monotonic() + 3
    while threading.active_count() > baseline and time.monotonic() < deadline:
        time.sleep(0.01)
    return threading.active_count() <= baseline


def test_a_write_the_transport_does_not_read_ends_at_the_deadline(client, monkeypatch):
    # A transport that reads nothing used to hold a request with a deadline of
    # 0.05 s for as long as it lived: the write waited on it, and the deadline
    # did not cover the write.
    monkeypatch.setenv("TLSFORGE_TEST_DEAF_FOR", "10")
    one = client(timeout=0.2)
    baseline = threading.active_count()
    started = time.monotonic()
    with pytest.raises(Timeout, match=r"timed out after 0.2s$"):
        one.post("https://ok/big", _BIG)
    assert time.monotonic() - started < 2
    assert one._process is None
    assert _settled(baseline)
    # The transport stopped had the session in it.
    monkeypatch.delenv("TLSFORGE_TEST_DEAF_FOR")
    with pytest.raises(tlsforge.SessionReset, match="a request timed out, and it was stopped"):
        one.get("https://ok/after")
    assert one.get("https://ok/again").status == 200


def test_a_transport_that_dies_during_a_write_fails_it_at_once(client, monkeypatch):
    monkeypatch.setenv("TLSFORGE_TEST_DEAF_FOR", "0.3")
    one = client(timeout=10)
    started = time.monotonic()
    with pytest.raises(TransportError, match="write failed"):
        one.post("https://ok/big", _BIG)
    assert time.monotonic() - started < 3
    monkeypatch.delenv("TLSFORGE_TEST_DEAF_FOR")
    with pytest.raises(tlsforge.SessionReset, match="could not be written"):
        one.get("https://ok/after")
    assert one.get("https://ok/again").status == 200


def test_a_request_whose_deadline_passes_while_it_waits_is_not_sent(client):
    # Its deadline counts from the call. The one in front of it stops its
    # transport at its own deadline, and takes a while to, since that transport
    # does not notice the end of its input: the one behind runs out first.
    one = client(timeout=0.3)
    outcomes: dict[str, BaseException | None] = {}

    def asking(name: str, url: str) -> None:
        try:
            one.get(url)
            outcomes[name] = None
        except BaseException as err:  # noqa: BLE001 - recorded, and asserted below
            outcomes[name] = err

    first = threading.Thread(target=asking, args=("first", "https://stubborn/x"))
    first.start()
    time.sleep(0.05)
    second = threading.Thread(target=asking, args=("second", "https://ok/x"))
    second.start()
    first.join()
    second.join()
    assert isinstance(outcomes["first"], Timeout)
    assert isinstance(outcomes["second"], Timeout)
    assert str(outcomes["second"]).endswith("waiting for the one before it, and was not sent")


# --- closing ---------------------------------------------------------------


@pytest.mark.parametrize("stuck", ["writing", "waiting for its answer"])
def test_close_does_not_wait_for_a_request_in_flight(client, monkeypatch, stuck):
    # The request is stopped, and says so; close() returns at once, however
    # the request is stuck.
    if stuck == "writing":
        monkeypatch.setenv("TLSFORGE_TEST_DEAF_FOR", "10")
    one = client(timeout=10)
    baseline = threading.active_count()
    outcome: list[BaseException] = []

    def asking() -> None:
        try:
            if stuck == "writing":
                one.post("https://ok/big", _BIG)
            else:
                one.get("https://silent/x")
        except BaseException as err:  # noqa: BLE001 - recorded, and asserted below
            outcome.append(err)

    thread = threading.Thread(target=asking)
    thread.start()
    time.sleep(0.3)
    started = time.monotonic()
    one.close()
    assert time.monotonic() - started < 2
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert isinstance(outcome[0], TransportError) and str(outcome[0]) == "tlsforge: client closed"
    assert _settled(baseline)


def test_close_while_a_request_is_made_stops_it_before_it_is_written(client, monkeypatch):
    # close() between the request's own look at the client and its write, as
    # when it comes while a large body is encoded: nothing is written.
    one = client()
    one.get("https://ok/start")
    encode = _client._encode_request

    def encoding_while_closed(payload: dict) -> str:
        line = encode(payload)
        one.close()
        return line

    monkeypatch.setattr(_client, "_encode_request", encoding_while_closed)
    with pytest.raises(TransportError, match="^tlsforge: client closed$"):
        one.get("https://ok/x")




def test_close_stops_the_transport(client):
    one = client()
    one.get("https://ok/x")
    process = one._process
    one.close()
    assert one._process is None
    assert process.poll() is not None


def test_a_closed_client_refuses_to_respawn(client):
    one = client()
    one.get("https://ok/x")
    one.close()
    with pytest.raises(TransportError, match="closed"):
        one.get("https://ok/y")


def test_close_is_idempotent(client):
    one = client()
    one.get("https://ok/x")
    one.close()
    one.close()


def test_close_without_ever_making_a_request_is_fine(client):
    client().close()


def test_the_client_is_a_context_manager(wrapper):
    with Client(binary=os.fspath(wrapper)) as one:
        assert one.get("https://ok/x").status == 200
    with pytest.raises(TransportError, match="closed"):
        one.get("https://ok/y")


def test_a_forgotten_client_does_not_leave_its_transport_running(wrapper):
    # A Popen that is merely collected is not killed: CPython reaps it later and
    # warns, and the daemon goes on running. A scraper building a client per
    # site would leave one process behind per site.
    one = Client(binary=os.fspath(wrapper))
    one.get("https://ok/x")
    process = one._process
    del one
    gc.collect()
    assert process.poll() is not None


# --- identity and threads --------------------------------------------------


def test_a_client_shared_between_threads_serialises_rather_than_interleaves(client):
    one = client()
    seen: list[str] = []
    lock = threading.Lock()

    def ask(n: int) -> None:
        res = one.get(f"https://ok/{n}")
        with lock:
            seen.append(res.url)

    threads = [threading.Thread(target=ask, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Every request answered, each with its own answer: the ids never crossed.
    assert sorted(seen) == sorted(f"https://ok/{n}" for n in range(8))


def test_ids_never_repeat_across_a_restart(client):
    # An id must never name two different requests, or a late answer from the
    # process that was killed can match the request that replaced it.
    one = client(timeout=0.3)
    with pytest.raises(Timeout):
        one.get("https://silent/x")
    before = one._sequence
    with pytest.raises(tlsforge.SessionReset):
        one.get("https://ok/after")
    one.get("https://ok/after")
    assert one._sequence > before + 1


# --- Response --------------------------------------------------------------


def test_response_ok_covers_the_2xx_range():
    def at(status: int) -> Response:
        return Response(status=status, url="", body="")

    assert not at(199).ok
    assert at(200).ok
    assert at(299).ok
    assert not at(300).ok


def test_response_json_parses_the_body():
    assert Response(status=200, url="", body='{"a": 1}').json() == {"a": 1}


def test_response_json_passes_its_arguments_on():
    got = Response(status=200, url="", body='{"a": 1}').json(
        object_pairs_hook=lambda pairs: pairs
    )
    assert got == [("a", 1)]


def test_response_json_on_a_body_that_is_not_json():
    with pytest.raises(json.JSONDecodeError):
        Response(status=200, url="", body="<html>").json()


def test_a_response_cannot_be_edited_by_accident():
    # Frozen because a response is a record of what happened, and a caller that
    # rewrote one would be describing a request that was never made.
    with pytest.raises(Exception):
        Response(status=200, url="", body="").status = 500


# --- the package surface ---------------------------------------------------


def test_everything_named_in_all_is_importable():
    for name in tlsforge.__all__:
        assert getattr(tlsforge, name) is not None


def test_the_exception_hierarchy_is_catchable_as_one():
    for error in (
        tlsforge.BinaryNotFound,
        tlsforge.TransportError,
        tlsforge.RequestFailed,
        tlsforge.Timeout,
    ):
        assert issubclass(error, tlsforge.TLSForgeError)


def test_the_default_timeout_is_the_documented_one():
    assert tlsforge.DEFAULT_TIMEOUT == 45.0


# --- the pieces that only misbehave when something else has ----------------


def sleeper(tmp_path: Path, wrapper: Path) -> subprocess.Popen:
    if os.environ.get("TLSFORGE_TEST_DAEMON"):
        return subprocess.Popen(
            [os.fspath(wrapper), "--sleep"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    script = tmp_path / "sleeper.sh"
    script.write_text("#!/bin/sh\nsleep 30\n")
    script.chmod(0o755)
    return subprocess.Popen(
        [str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def close_pipes(process: subprocess.Popen) -> None:
    # _kill closes stdin only: stdout and stderr belong to the reader threads,
    # and a bare Popen has none. Whoever opened them closes them.
    for pipe in (process.stdout, process.stderr):
        pipe.close()


@pytest.mark.parametrize(
    "deaf_to, ends_with",
    [
        # Ignores end of input, takes the signal.
        (1, "terminate"),
        # Ignores the signal too, and is killed. Driven by making wait() time
        # out rather than by a process that really ignores SIGTERM, which would
        # cost the full grace period on every run.
        (2, "kill"),
    ],
)
def test_a_transport_is_escalated_until_it_stops(
    tmp_path, wrapper, monkeypatch, deaf_to, ends_with
):
    from tlsforge import _client

    process = sleeper(tmp_path, wrapper)
    real_wait = process.wait
    calls = {"n": 0}
    used: list[str] = []

    def wait(timeout=None):
        calls["n"] += 1
        if calls["n"] <= deaf_to:
            raise subprocess.TimeoutExpired(cmd="sleeper", timeout=timeout or 0)
        return real_wait()

    for name in ("terminate", "kill"):
        real = getattr(process, name)
        monkeypatch.setattr(
            process, name, lambda *_a, _n=name, _r=real: (used.append(_n), _r())[1]
        )
    monkeypatch.setattr(process, "wait", wait)

    try:
        _client._kill(process)
        assert process.poll() is not None
        assert used[-1] == ends_with
    finally:
        close_pipes(process)


def test_a_transport_that_already_stopped_is_not_signalled(tmp_path, wrapper, monkeypatch):
    # Closing stdin is the shutdown signal, and something that took it needs no
    # further encouragement — signalling a reaped process would raise.
    from tlsforge import _client

    process = sleeper(tmp_path, wrapper)
    process.terminate()
    process.wait()
    monkeypatch.setattr(process, "terminate", _refuse("terminate"))
    monkeypatch.setattr(process, "kill", _refuse("kill"))
    try:
        _client._kill(process)
    finally:
        close_pipes(process)


def _refuse(name):
    def refuse(*_args):
        raise AssertionError(f"{name} was called on a process that had already stopped")

    return refuse


def test_a_transport_whose_pipe_broke_is_still_stopped(deaf):
    # Closing stdin flushes it, and flushing into a pipe whose reader has gone
    # raises. Buffered rather than written through: with line buffering, a write
    # without a newline is what stays in the buffer until close.
    from tlsforge import _client

    process = subprocess.Popen([os.fspath(deaf)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, bufsize=1)
    process.stdin.write('{"id":1,"url":"https://deaf/first"}\n')
    process.stdin.flush()
    process.stdout.readline()
    process.stdin.write("left in the buffer")

    try:
        _client._kill(process)
        assert process.poll() is not None
    finally:
        close_pipes(process)


def test_closing_a_pipe_that_is_already_gone_is_not_an_error(client):
    from tlsforge import _client

    one = client()
    one.get("https://ok/x")
    process = one._process
    for pipe in (process.stdin, process.stdout, process.stderr):
        pipe.close()
    # Closing them again is what _kill would do after something else already had.
    _client._kill(process)


def test_the_default_stderr_sink_swallows_a_line():
    from tlsforge import _client

    assert _client._ignore("anything") is None


# --- bodies that are not text ----------------------------------------------


def test_a_binary_body_arrives_as_bytes(client):
    """A JSON string cannot hold arbitrary bytes.

    Before bodyEncoding the transport replaced every byte that is not valid
    UTF-8 with U+FFFD and still reported status 200, so a caller asking for an
    image got back something no decoder would open and nothing said why.
    """
    res = client().get("https://binary/logo.png")
    assert res.content == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF])


def test_a_text_body_has_matching_bytes(client):
    res = client().get("https://ok/page")
    assert res.content == res.body.encode("utf-8")


def test_an_explicit_utf8_encoding_is_accepted(client):
    res = client().get("https://utf8-encoding/")
    assert res.body == "plain text"
    assert res.content == b"plain text"


def test_a_bytes_request_body_arrives_intact(client):
    sent = bytes([0x00, 0xFF, 0xFE, 0x80])
    res = client().post("https://echo-body/", sent)
    assert res.content == sent


def test_a_bytearray_request_body_arrives_intact(client):
    sent = bytearray([0x01, 0xFF, 0x00])
    res = client().post("https://echo-body/", sent)
    assert res.content == bytes(sent)


def test_an_unknown_body_encoding_is_refused(client):
    with pytest.raises(TransportError, match="unknown bodyEncoding"):
        client().get("https://bad-body-encoding/")


def test_a_body_encoding_that_is_not_a_string_is_refused(client):
    with pytest.raises(TransportError, match='"bodyEncoding" must be a string'):
        client().get("https://bad-body-encoding-type/")


def test_a_body_that_claims_base64_and_is_not_is_refused(client):
    with pytest.raises(TransportError, match="not valid base64"):
        client().get("https://bad-base64/")
