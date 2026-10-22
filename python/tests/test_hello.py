"""What a transport is, asked before a request relies on it: hello, and a
browser context sent only to a transport that says it applies one."""

from __future__ import annotations

import json
import os

import pytest

import tlsforge


def seen(client: tlsforge.Client) -> dict:
    """What the transport had read by the time it answered a plain request."""
    return json.loads(client.get("https://ok/").body)


def test_a_transport_says_what_it_is_once(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_CAPABILITIES", "one,two")
    c = client()
    assert c.hello() == tlsforge.Hello(3, ("one", "two"), 1, "1.0.0")
    assert c.hello() is c.hello()
    assert seen(c)["controls"] == 1


def test_a_transport_with_nothing_to_say(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TLSFORGE_TEST_CAPABILITIES", raising=False)
    assert client().hello() == tlsforge.Hello(3, (), 1, "1.0.0")


@pytest.mark.parametrize(
    ("mode", "want"),
    [("1", tlsforge.Hello(1, ())), ("fixture", tlsforge.Hello(3, ("browser_context", "engine_major"), 1, "1.0.0")), ("fixture-old", tlsforge.Hello(1, ()))],
)
def test_older_transports_and_the_committed_answers(client, monkeypatch, mode, want) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_PROTOCOL", mode)
    # Where the native fake, which stands in on Windows, finds the committed answers.
    monkeypatch.setenv(
        "TLSFORGE_PROTOCOL_FIXTURES",
        os.path.join(os.path.dirname(__file__), "..", "..", "testdata", "protocol"),
    )
    assert client().hello() == want


@pytest.mark.parametrize("mode", ["bad", "bool", "bad-capabilities", "no-capabilities", "low"])
def test_an_answer_that_says_nothing_it_can_is_a_bad_response(client, monkeypatch, mode) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_PROTOCOL", mode)
    c = client()
    with pytest.raises(tlsforge.TransportError, match="^tlsforge: bad response: hello must give a protocol from 2"):
        c.hello()
    # Not kept: asked again.
    with pytest.raises(tlsforge.TransportError, match="bad response"):
        c.hello()
    with pytest.raises(tlsforge.TransportError, match="bad response"):
        seen(c)


def test_a_transport_newer_than_this_package_is_read_for_what_it_says_it_can_do(client, monkeypatch) -> None:
    # A protocol after 2, and a capability no package knows yet, are no reason
    # to refuse what both know.
    monkeypatch.setenv("TLSFORGE_TEST_PROTOCOL", "newer")
    c = client()
    assert c.hello() == tlsforge.Hello(7, ("browser_context", "teleport"), 1, "1.0.0")
    context = {"kind": "fetch", "initiator": "https://example.com/"}
    assert json.loads(c.get("https://ok/", browser_context=context).body)["browser"] == context


def test_a_transport_that_does_not_answer_is_asked_again(client, monkeypatch) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_PROTOCOL", "silent")
    c = client(timeout=0.3)
    with pytest.raises(tlsforge.Timeout):
        c.hello()
    # A question was made in no session: it is asked of the next transport,
    # and the next request is the one told its session has gone.
    with pytest.raises(tlsforge.Timeout):
        c.hello()
    with pytest.raises(tlsforge.Timeout):
        c.get("https://ok/")


def test_a_question_asked_after_a_session_went_leaves_the_next_request_to_be_told(client) -> None:
    c = client(timeout=0.3)
    with pytest.raises(tlsforge.Timeout):
        c.get("https://silent/")
    assert c.hello() == tlsforge.Hello(3, (), 1, "1.0.0")
    with pytest.raises(tlsforge.SessionReset):
        c.get("https://ok/")
    assert seen(c)["requests"] == 1


def test_a_transport_that_exits_answering(client, monkeypatch) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_PROTOCOL", "exit")
    with pytest.raises(tlsforge.TransportError, match=r"transport exited \(code 3\)"):
        client().hello()


def test_a_transport_gone_while_idle_is_noticed_by_hello(client, monkeypatch) -> None:
    c = client()
    first = seen(c)
    os.kill(first["pid"], 9)
    c._process.wait()
    # Asked of a new one; the request after it is told its session went.
    assert c.hello() == tlsforge.Hello(3, (), 1, "1.0.0")
    with pytest.raises(tlsforge.SessionReset):
        c.get("https://ok/")
    assert seen(c)["pid"] != first["pid"]


def test_a_closed_client_asks_nothing(client) -> None:
    c = client()
    c.close()
    with pytest.raises(tlsforge.TransportError, match="closed"):
        c.hello()


def test_hello_waits_its_turn(client, monkeypatch) -> None:
    c = client(timeout=0.3)
    c._lock.acquire()
    try:
        with pytest.raises(tlsforge.Timeout, match="waiting for the request before it, and was not asked"):
            c.hello()
    finally:
        c._lock.release()


@pytest.mark.parametrize(("env", "protocol"), [({"TLSFORGE_TEST_CAPABILITIES": "other"}, 3)])
def test_a_browser_context_goes_to_no_transport_that_does_not_apply_one(client, monkeypatch, env, protocol) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    c = client()
    with pytest.raises(tlsforge.Unsupported) as refused:
        c.get("https://ok/", browser_context={"kind": "fetch"})
    assert str(refused.value) == (
        f"tlsforge: the tls-forge at {c._binary} speaks protocol {protocol} and does not apply browser "
        "contexts; the request was not sent"
    )
    assert isinstance(refused.value, tlsforge.TLSForgeError)
    # Asked, and nothing sent: the plain request after it is the first.
    assert seen(c)["requests"] == 1


def test_a_browser_context_goes_to_a_transport_that_applies_one(client, monkeypatch) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_CAPABILITIES", "browser_context")
    c = client()
    context = {"kind": "fetch", "initiator": "https://example.com/"}
    answer = json.loads(c.post("https://ok/", "x", browser_context=context).body)
    # Sent as the protocol names it, and under no other name.
    assert answer["browser"] == context
    assert "browser" in answer["sent"] and "browser_context" not in answer["sent"]
    assert answer["bodyLength"] == 1
    # Without one, nothing more is asked.
    answer = seen(c)
    assert answer["controls"] == 1 and answer["browser"] is None and "browser" not in answer["sent"]


def test_a_browser_context_goes_by_this_packages_names_as_the_daemons(client, monkeypatch) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_CAPABILITIES", "browser_context")
    c = client()
    context: tlsforge.BrowserContext = {
        "kind": "fetch",
        "initiator": "https://shop.example/item/7",
        "referrer_policy": "origin",
        "mode": "cors",
        "credentials": "include",
    }
    sent = json.loads(c.get("https://ok/", browser_context=context).body)["browser"]
    assert sent == {
        "kind": "fetch",
        "initiator": "https://shop.example/item/7",
        "referrerPolicy": "origin",
        "mode": "cors",
        "credentials": "include",
    }


@pytest.mark.parametrize(
    ("context", "says"),
    [
        ("fetch", r"^tlsforge: browser_context must be a mapping, not str$"),
        (["kind", "fetch"], r"^tlsforge: browser_context must be a mapping, not list$"),
        # The daemon's spelling of a key is not this package's.
        (
            {"kind": "fetch", "referrerPolicy": "origin"},
            r"^tlsforge: browser_context has no key 'referrerPolicy'; it takes kind, initiator, "
            r"referrer_policy, mode, credentials$",
        ),
        ({"kind": "fetch", "teleport": True}, r"^tlsforge: browser_context has no key 'teleport'"),
    ],
)
def test_a_browser_context_that_is_no_mapping_or_has_a_key_there_is_none_of_is_a_mistake(
    client, monkeypatch, context, says
) -> None:
    monkeypatch.setenv("TLSFORGE_TEST_CAPABILITIES", "browser_context")
    c = client()
    with pytest.raises(TypeError, match=says) as refused:
        c.get("https://ok/", browser_context=context)
    assert not isinstance(refused.value, tlsforge.TLSForgeError)
    # Said before anything was asked: the plain request after it is the first
    # line the transport read.
    answer = seen(c)
    assert answer["controls"] == 1 and answer["requests"] == 1
