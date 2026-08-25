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

import json
import sys
import threading
import time
from urllib.parse import urlsplit


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
                "method": request.get("method"),
                "headers": request.get("headers", {}),
                "order": request.get("order", []),
                "cookies": request.get("setCookie", []),
                "body": request.get("body"),
            }
        ),
        "headers": {
            "content-type": ["application/json"],
            "set-cookie": ["a=1", "b=2"],
        },
        "cookies": [],
        **extra,
    }


def main() -> None:
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            emit({"id": 0, "error": "bad request"})
            continue

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
