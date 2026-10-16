#!/usr/bin/env python3
"""A stand-in for the Go transport, so the client's protocol handling can be
tested without Go and without a network.

Every behaviour the real transport can exhibit — including the ones that only
happen when something has gone wrong — is reachable by asking for it in the URL.
That is the point: the interesting code in the client is what it does with a
late answer, a garbage line or a dead pipe, and none of those are reproducible
against a healthy server.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
from urllib.parse import urlsplit


#: How many control lines and requests this process has read: what a client
#: sent, which a test of what it did not send reads back.
SEEN = {"controls": 0, "requests": 0}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


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
                "env": {"TLSFORGE_PROXY": os.environ.get("TLSFORGE_PROXY")},
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


def control(request: dict) -> None:
    """Answer a control line with what the transport is: as TLSFORGE_TEST_PROTOCOL
    says, protocol 2 with TLSFORGE_TEST_CAPABILITIES when it says nothing."""
    mode = os.environ.get("TLSFORGE_TEST_PROTOCOL", "")
    if mode == "silent":
        return
    if mode == "exit":
        sys.exit(3)
    blank = {"id": request["id"], "status": 0, "url": "", "body": "", "headers": None, "cookies": None}
    here = os.path.dirname(os.path.abspath(__file__))

    def fixture(name: str) -> dict:
        with open(os.path.join(here, "..", "..", "testdata", "protocol", name), encoding="utf-8") as f:
            return {**json.load(f), "id": request["id"]}

    capabilities = [name for name in os.environ.get("TLSFORGE_TEST_CAPABILITIES", "").split(",") if name]
    replies = {
        "1": lambda: {**blank, "error": "bad request: no url"},
        "fixture": lambda: fixture("response-hello.json"),
        "fixture-old": lambda: fixture("response-hello-old.json"),
        "bad": lambda: {**blank, "protocol": "two"},
        "bool": lambda: {**blank, "protocol": True},
        "bad-capabilities": lambda: {**blank, "protocol": 2, "capabilities": [7]},
        "no-capabilities": lambda: {**blank, "protocol": 2, "capabilities": "all"},
        "low": lambda: {**blank, "protocol": 1},
    }
    default = {**blank, "protocol": 2, **({"capabilities": capabilities} if capabilities else {})}
    emit(replies[mode]() if mode in replies else default)


def refuses() -> bool:
    """Whether to refuse to start, with code 2, as pflag does: as a tls-forge
    older than the client, which does not know --proxy-env, or whatever it is
    started with."""
    refuse = os.environ.get("TLSFORGE_TEST_REFUSE")
    return refuse == "always" or (
        refuse == "proxy-env" and any(arg.startswith("--proxy-env") for arg in sys.argv)
    )


def main() -> None:
    if refuses():
        sys.stderr.write("tlsforge: bad usage: unknown flag: --proxy-env\n")
        sys.exit(2)
    deaf_for = os.environ.get("TLSFORGE_TEST_DEAF_FOR")
    if deaf_for:
        # Reads nothing, for as long as it is told, and then is gone: a write
        # larger than the pipe holds waits on it all that time.
        time.sleep(float(deaf_for))
        return
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            emit({"id": 0, "error": "bad request"})
            continue

        if "control" in request:
            SEEN["controls"] += 1
            control(request)
            continue
        SEEN["requests"] += 1

        behaviour = urlsplit(request["url"]).hostname

        if behaviour == "ok":
            emit(answer(request))
        elif behaviour == "error":
            emit({"id": request["id"], "error": "upstream refused"})
        elif behaviour == "null-fields":
            # What the transport really sends when a request fails: the shape is
            # whole, the fields are null.
            emit({"id": request["id"], "status": 0, "url": "", "body": "",
                  "headers": None, "cookies": None})
        elif behaviour == "bad-error":
            emit(answer(request, error={}))
        elif behaviour == "bad-status":
            emit(answer(request, status="200"))
        elif behaviour == "bad-url":
            emit(answer(request, url=7))
        elif behaviour == "bad-body":
            emit(answer(request, body=[]))
        elif behaviour == "binary":
            # The bytes a JSON string cannot hold: PNG magic and a stray 0xff.
            raw = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF])
            emit(
                answer(
                    request,
                    body=base64.b64encode(raw).decode("ascii"),
                    bodyEncoding="base64",
                )
            )
        elif behaviour == "echo-body":
            # Hands back what it was sent, so the request direction can be checked.
            emit(
                answer(
                    request,
                    body=request.get("body", ""),
                    bodyEncoding=request.get("bodyEncoding", ""),
                )
            )
        elif behaviour == "utf8-encoding":
            emit(answer(request, body="plain text", bodyEncoding="utf8"))
        elif behaviour == "bad-body-encoding":
            emit(answer(request, body="x", bodyEncoding="rot13"))
        elif behaviour == "bad-body-encoding-type":
            emit(answer(request, body="x", bodyEncoding=7))
        elif behaviour == "bad-base64":
            emit(answer(request, body="!!not base64!!", bodyEncoding="base64"))
        elif behaviour == "bad-headers":
            emit(answer(request, headers=[]))
        elif behaviour == "bad-header-scalar":
            emit(answer(request, headers={"broken": 7}))
        elif behaviour == "bad-header-list":
            emit(answer(request, headers={"broken": [7]}))
        elif behaviour == "bad-cookies":
            emit(answer(request, cookies={}))
        elif behaviour == "bad-cookie-item":
            emit(answer(request, cookies=[7]))
        elif behaviour == "garbage":
            sys.stdout.write("not json at all\n")
            sys.stdout.flush()
        elif behaviour == "null-line":
            sys.stdout.write("null\n")
            sys.stdout.flush()
        elif behaviour == "no-id":
            emit({"status": 200, "body": "anonymous"})
            threading.Timer(0.05, lambda: emit(answer(request))).start()
        elif behaviour == "wrong-id":
            emit({"id": request["id"] + 1000, "status": 200, "body": "stray"})
            # …then the right one, so the request still completes and the test
            # can assert the stray line was ignored rather than merely slow.
            threading.Timer(0.05, lambda: emit(answer(request))).start()
        elif behaviour == "silent":
            pass  # Never answers. The client's deadline is the only thing that ends this.
        elif behaviour == "slow":
            threading.Timer(0.4, lambda: emit(answer(request))).start()
        elif behaviour == "exit":
            sys.exit(3)
        elif behaviour == "stubborn":
            # Never answers, and reads nothing more: the end of its input is
            # not noticed, and it has to be stopped.
            time.sleep(30)
        elif behaviour == "answer-then-exit":
            # Answers, and dies while nobody is asking it anything.
            emit(answer(request))
            threading.Timer(0.05, lambda: os._exit(4)).start()
        elif behaviour == "stderr":
            sys.stderr.write("a note on stderr\n")
            sys.stderr.flush()
            time.sleep(0.05)
            emit(answer(request))
        elif behaviour == "legacy-headers":
            emit(answer(request, headers={"content-type": "application/json"}))
        else:
            emit(answer(request, status=404))


if __name__ == "__main__":
    main()
