from __future__ import annotations

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


# --- the ordinary path -----------------------------------------------------


def test_get_returns_the_transport_response(client):
    res = client().get("https://ok/page")
    assert res.status == 200
    assert res.url == "https://ok/page"
    assert res.headers["content-type"] == "application/json"
    assert res.ok


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
    res = client().get("https://null-fields/x")
    assert res.headers == {}
    assert res.cookies == ()
    assert res.status == 0
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
        ("--proxy", "http://user:pass@host:8080"),
        ("--cookies", str(jar)),
        ("--cookie-set", "warm-eu"),
    ):
        assert argv[argv.index(flag) + 1] == value
    assert "--insecure" in argv


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


@pytest.mark.parametrize("bad", [0, -1, -0.5])
def test_a_timeout_that_is_not_positive_is_refused(wrapper, bad):
    # Zero would make every request time out before it was written, which reads
    # as "the network is broken" rather than "the argument is wrong".
    with pytest.raises(ValueError, match="timeout must be positive"):
        Client(binary=os.fspath(wrapper), timeout=bad)


# --- failures --------------------------------------------------------------


def test_an_error_field_becomes_a_request_failure(client):
    with pytest.raises(RequestFailed, match="upstream refused"):
        client().get("https://error/x")


def test_a_request_with_no_url_is_refused_without_spawning_anything(client):
    one = client()
    with pytest.raises(ValueError, match="needs a url"):
        one.get("")
    assert one._process is None


def test_a_garbage_line_fails_the_request_rather_than_hanging(client):
    with pytest.raises(TransportError, match="bad response"):
        client().get("https://garbage/x")


def test_a_line_that_is_json_but_not_an_object_is_also_rejected(client):
    # `null`, `7` and `[]` are all valid JSON and none can carry an id.
    with pytest.raises(TransportError, match="bad response"):
        client().get("https://null-line/x")


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
    one = client(timeout=0.3)
    with pytest.raises(Timeout):
        one.get("https://silent/x")
    assert one.get("https://ok/after").status == 200


def test_a_timeout_stops_the_process_so_a_late_answer_cannot_arrive(client):
    # The transport's deadline is longer than ours, so an answer to the
    # abandoned request is not merely possible, it is expected.
    one = client(timeout=0.15)
    with pytest.raises(Timeout):
        one.get("https://slow/x")
    assert one._process is None
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
    assert one.get("https://ok/after").status == 200


def test_stderr_is_forwarded_to_the_callback(client):
    notes: list[str] = []
    client(on_stderr=notes.append).get("https://stderr/x")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not any("a note on stderr" in n for n in notes):
        time.sleep(0.01)
    assert any("a note on stderr" in note for note in notes)


def test_stderr_is_discarded_when_nobody_asked_for_it(client):
    # The default sink has to be reached, or a transport that says anything at
    # all would raise from a thread nobody is watching.
    assert client().get("https://stderr/x").status == 200


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
    one.close()


# --- closing ---------------------------------------------------------------


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
    one.get("https://ok/after")
    assert one._sequence > before


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


def sleeper(tmp_path: Path) -> subprocess.Popen:
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
def test_a_transport_is_escalated_until_it_stops(tmp_path, monkeypatch, deaf_to, ends_with):
    from tlsforge import _client

    process = sleeper(tmp_path)
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


def test_a_transport_that_already_stopped_is_not_signalled(tmp_path, monkeypatch):
    # Closing stdin is the shutdown signal, and something that took it needs no
    # further encouragement — signalling a reaped process would raise.
    from tlsforge import _client

    process = sleeper(tmp_path)
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
    process.stdin.write('{"id":1}\n')  # answered, and then it stops reading
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
