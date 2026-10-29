#!/usr/bin/env python3
"""A stand-in for the Go transport, so the client's protocol handling can be
tested without Go and without a network.

Every behaviour the real transport can exhibit — including the ones that only
happen when something has gone wrong — is reachable by asking for it in the URL.
That is the point: the interesting code in the client is what it does with a
late answer, a garbage line or a dead pipe, and none of those are reproducible
against a healthy server.

The scenarios are the ones testdata/fake-daemon/scenarios.json names, and every
fake answers the same ones: see that file.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import threading
import time
from typing import Callable
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))

#: How many control lines and requests this process has read: what a client
#: sent, which a test of what it did not send reads back.
SEEN = {"controls": 0, "requests": 0}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def raw(line: str) -> None:
    sys.stdout.write(line)
    sys.stdout.flush()


def fixture(name: str) -> dict:
    with open(os.path.join(HERE, "..", "..", "testdata", "protocol", name), encoding="utf-8") as f:
        return json.load(f)


def answer(request: dict, **extra: object) -> dict:
    return {
        "id": request.get("id"),
        "status": 200,
        "url": request.get("url", ""),
        # The body echoes the request, so a test can assert what actually
        # reached the transport rather than what the client meant to send.
        "body": json.dumps(
            {
                "argv": sys.argv[1:],
                "env": {name: os.environ.get(name) for name in ['TLSFORGE_PROXY', 'SSLKEYLOGFILE', 'sslkeylogfile', 'QUIC_GO_DISABLE_ECN', 'QUIC_GO_DISABLE_GSO', 'QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING', 'QUIC_GO_LOG_LEVEL', 'QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING', 'GODEBUG']},
                # The proxy the init line named.
                "proxy": SEEN.get("proxy"),
                # Which process answered, and how much of a body reached it: a
                # request refused before it was sent must leave both as they were.
                "pid": os.getpid(),
                "bodyLength": len(request.get("body") or ""),
                "method": request.get("method"),
                "headers": request.get("headers", {}),
                "order": request.get("order", []),
                "cookies": request.get("setCookie", []),
                "body": request.get("body"),
                # The browser context, as the transport was given it.
                "browser": request.get("browser"),
                "sent": sorted(request),
                **SEEN,
            }
        ),
        "headers": {
            "content-type": ["application/json"],
            "set-cookie": ["a=1", "b=2"],
        },
        "cookies": [],
        **extra,
    }


def later(seconds: float, fn: Callable[[], None]) -> None:
    threading.Timer(seconds, fn).start()


def _no_id(request: dict) -> None:
    emit({"status": 200, "body": "anonymous"})
    later(0.05, lambda: emit(answer(request)))


def _wrong_id(request: dict) -> None:
    emit({"id": request["id"] + 1000, "status": 200, "body": "stray"})
    # …then the right one, so the request still completes and the test can
    # assert the stray line was ignored rather than merely slow.
    later(0.05, lambda: emit(answer(request)))


def _trailing_lines(request: dict) -> None:
    emit(answer(request))

    def after() -> None:
        raw("not json at all\n")
        emit({"status": 200, "body": "orphan"})

    later(0.01, after)


def _stubborn(_request: dict) -> None:
    # Never answers, and reads nothing more: the end of its input is not
    # noticed, and it has to be stopped.
    time.sleep(30)


def _deaf(request: dict) -> None:
    # The answer acknowledges the closed input, then reads nothing more:
    # its client finds a pipe nobody reads rather than a process that exited.
    sys.stdin.close()
    emit(answer(request))
    time.sleep(30)


def _answer_then_exit(request: dict) -> None:
    # Answers, and dies while nobody is asking it anything.
    emit(answer(request))
    later(0.05, lambda: os._exit(4))


def _stderr(request: dict) -> None:
    sys.stderr.write("a note on stderr\n")
    sys.stderr.flush()
    time.sleep(0.05)
    emit(answer(request))


def _stderr_chunks(request: dict) -> None:
    sys.stderr.write("one logical")
    sys.stderr.flush()
    time.sleep(0.005)
    sys.stderr.write(" line\nsecond line\n")
    sys.stderr.flush()
    emit(answer(request))


def _exit(_request: dict) -> None:
    sys.exit(3)


#: The bytes a JSON string cannot hold: PNG magic and a stray 0xff.
_BINARY = base64.b64encode(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF])).decode("ascii")

#: What a request is answered with, by the host of its URL.
SCENARIOS: dict[str, Callable[[dict], None]] = {
    "ok": lambda request: emit(answer(request)),
    "error": lambda request: emit({"id": request["id"], "error": "upstream refused"}),
    # What the transport really sends when a request fails: the shape is whole.
    "null-fields": lambda request: emit(
        {"id": request["id"], "status": 0, "url": "", "body": "", "headers": None, "cookies": None}
    ),
    "null-values": lambda request: emit(
        answer(request, status=None, url=None, body=None, headers=None, cookies=None)
    ),
    "bad-error": lambda request: emit(answer(request, error={})),
    "bad-status": lambda request: emit(answer(request, status="200")),
    "bad-url": lambda request: emit(answer(request, url=7)),
    "bad-body": lambda request: emit(answer(request, body=[])),
    "binary": lambda request: emit(answer(request, body=_BINARY, bodyEncoding="base64")),
    # Hands back what it was sent, so the request direction can be checked.
    "echo-body": lambda request: emit(
        answer(request, body=request.get("body", ""), bodyEncoding=request.get("bodyEncoding", ""))
    ),
    "utf8-encoding": lambda request: emit(answer(request, body="plain text", bodyEncoding="utf8")),
    "bad-body-encoding": lambda request: emit(answer(request, body="x", bodyEncoding="rot13")),
    "bad-body-encoding-type": lambda request: emit(answer(request, body="x", bodyEncoding=7)),
    "bad-base64": lambda request: emit(answer(request, body="!!not base64!!", bodyEncoding="base64")),
    "bad-headers": lambda request: emit(answer(request, headers=[])),
    "bad-header-scalar": lambda request: emit(answer(request, headers={"broken": 7})),
    "bad-header-list": lambda request: emit(answer(request, headers={"broken": [7]})),
    "bad-cookies": lambda request: emit(answer(request, cookies={})),
    "bad-cookie-item": lambda request: emit(answer(request, cookies=[7])),
    "legacy-headers": lambda request: emit(answer(request, headers={"content-type": "application/json"})),
    "null-headers": lambda request: emit(answer(request, headers=None)),
    "newer-fields": lambda request: emit(answer(request, teleport=True)),
    # The committed wire format, replayed verbatim except for the id, which the
    # client matches on. See testdata/protocol/README.md.
    "fixture": lambda request: emit({**fixture("response.json"), "id": request["id"]}),
    "fixture-text": lambda request: emit({**fixture("response-text.json"), "id": request["id"]}),
    "fixture-error": lambda request: emit({**fixture("response-error.json"), "id": request["id"]}),
    "garbage": lambda _request: raw("not json at all\n"),
    "null-line": lambda _request: raw("null\n"),
    "no-id": _no_id,
    "wrong-id": _wrong_id,
    "trailing-lines": _trailing_lines,
    # Never answers. The client's deadline is the only thing that ends this.
    "silent": lambda _request: None,
    "slow": lambda request: later(0.4, lambda: emit(answer(request))),
    "exit": _exit,
    "answer-then-exit": _answer_then_exit,
    "stubborn": _stubborn,
    "deaf": _deaf,
    "stderr": _stderr,
    "stderr-chunks": _stderr_chunks,
}


def _blank(request: dict, **extra: object) -> dict:
    return {"id": request["id"], "status": 0, "url": "", "body": "", "headers": None, "cookies": None, **extra}


def _hello(request: dict) -> None:
    capabilities = [name for name in os.environ.get("TLSFORGE_TEST_CAPABILITIES", "").split(",") if name]
    identity = {"protocol": 3, "version": os.environ.get("TLSFORGE_TEST_ENGINE_VERSION", "1.0.0"), "capabilities": capabilities}
    major = os.environ.get("TLSFORGE_TEST_ENGINE_MAJOR")
    if major != "missing":
        identity["engine_major"] = 1 if major is None else json.loads(major)
    emit(_blank(request, **identity))
    deaf_for = os.environ.get("TLSFORGE_TEST_DEAF_FOR")
    if deaf_for:
        # The public SDK must complete hello before it can write a body.
        time.sleep(float(deaf_for))
        sys.exit(0)


#: What hello is answered with, by TLSFORGE_TEST_PROTOCOL: protocol 2 with
#: TLSFORGE_TEST_CAPABILITIES when it says nothing.
PROTOCOLS: dict[str, Callable[[dict], None]] = {
    "": _hello,
    "1": lambda request: emit(_blank(request, error="bad request: no url")),
    "fixture": lambda request: emit({**fixture("response-hello.json"), "id": request["id"]}),
    "fixture-old": lambda request: emit({**fixture("response-hello-old.json"), "id": request["id"]}),
    "bad": lambda request: emit(_blank(request, protocol="two")),
    "bool": lambda request: emit(_blank(request, protocol=True)),
    "bad-capabilities": lambda request: emit(_blank(request, protocol=2, capabilities=[7])),
    "no-capabilities": lambda request: emit(_blank(request, protocol=2, capabilities="all")),
    "low": lambda request: emit(_blank(request, protocol=1)),
    "newer": lambda request: emit(_blank(request, protocol=7, engine_major=1, version="1.0.0", capabilities=["browser_context", "teleport"])),
    "silent": lambda _request: None,
    "exit": _exit,
}


def control(request: dict) -> None:
    """Answer a control line: "scenarios" with what this fake answers, for the
    suite that holds it to scenarios.json, and hello as TLSFORGE_TEST_PROTOCOL
    says."""
    if request["control"] == "scenarios":
        emit({
            "id": request["id"],
            "requests": sorted(SCENARIOS),
            "protocols": sorted(PROTOCOLS),
            "inits": sorted(INITS),
        })
        return
    mode = os.environ.get("TLSFORGE_TEST_PROTOCOL", "")
    if mode not in PROTOCOLS:
        emit(_blank(request, error=f'unknown protocol mode "{mode}"'))
        return
    PROTOCOLS[mode](request)


def refuses() -> bool:
    """Whether to refuse to start, with code 2, as pflag does: as a tls-forge
    older than the client, which does not know --proxy-stdin, or whatever it is
    started with."""
    refuse = os.environ.get("TLSFORGE_TEST_REFUSE")
    return refuse == "always" or (refuse == "proxy-stdin" and "--proxy-stdin" in sys.argv)


def _refuse_init(request: dict) -> None:
    said = re.sub(r":[^:@/]*@", ":***@", request.get("proxy") or "", count=1)
    emit(_blank(request, error=f"the init line's proxy {said} is no proxy"))
    sys.exit(1)


def _deaf_to_init(_request: dict) -> None:
    # Closes its input before anything has read from it, and stays: the
    # client's write of the init line finds a pipe nobody can read. The
    # descriptor itself, since closing sys.stdin leaves it open.
    os.close(0)
    time.sleep(30)


#: What the init line is answered with, by TLSFORGE_TEST_INIT, for a fake
#: started with --proxy-stdin, which reads it first: without an error when it
#: says nothing. "deaf" is the one acted on before the line is read.
INITS: dict[str, Callable[[dict], None]] = {
    "": lambda request: emit(_blank(request)),
    "refuse": _refuse_init,
    "silent": lambda _request: None,
    "exit": _exit,
    "garbage": lambda _request: raw("not json at all\n"),
    "deaf": _deaf_to_init,
}


def init(request: dict) -> None:
    """Answer the init line as TLSFORGE_TEST_INIT says, keeping the proxy it
    names."""
    SEEN["proxy"] = request.get("proxy")
    mode = os.environ.get("TLSFORGE_TEST_INIT", "")
    if mode not in INITS:
        emit(_blank(request, error=f'unknown init mode "{mode}"'))
        return
    INITS[mode](request)


def main() -> None:
    if refuses():
        sys.stderr.write("tlsforge: bad usage: unknown flag: --proxy-stdin\n")
        sys.exit(2)
    initialised = "--proxy-stdin" not in sys.argv
    if not initialised and os.environ.get("TLSFORGE_TEST_INIT") == "deaf":
        INITS["deaf"]({})
        return
    if not initialised and os.environ.get("TLSFORGE_TEST_DEAF_FOR"):
        time.sleep(float(os.environ["TLSFORGE_TEST_DEAF_FOR"]))
        return
    for line in sys.stdin:
        try:
            if os.environ.get("TLSFORGE_TEST_WIRE_LOG"):
                with open(os.environ["TLSFORGE_TEST_WIRE_LOG"], "a", encoding="utf-8") as wire:
                    wire.write(line)
            request = json.loads(line)
        except ValueError:
            emit({"id": 0, "error": "bad request"})
            continue

        if not initialised:
            if request.get("control") != "init":
                emit(_blank(request, error="the first line is not the init line"))
                sys.exit(1)
            initialised = True
            init(request)
            continue
        if "control" in request:
            SEEN["controls"] += 1
            control(request)
            continue
        SEEN["requests"] += 1

        behaviour = urlsplit(request["url"]).hostname
        if behaviour not in SCENARIOS:
            emit({"id": request["id"], "error": f'unknown scenario "{behaviour}"'})
            continue
        SCENARIOS[behaviour](request)


if __name__ == "__main__":
    main()
