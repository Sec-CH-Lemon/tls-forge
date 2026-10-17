"""What the package's types promise and what they refuse: checked by mypy in
strict mode, and never run, nor collected by pytest. Each ``# type: ignore``
names the error a call must be refused with; strict mode fails the check when
one is not needed, so a type that accepted the call would fail it."""

from __future__ import annotations

from pathlib import Path

import tlsforge
from tlsforge import BrowserContext, Client, Hello, Response


def contract(client: Client) -> None:
    context: BrowserContext = {
        "kind": "fetch",
        "initiator": "https://shop.example/item/7",
        "referrer_policy": "origin",
        "mode": "cors",
        "credentials": "include",
    }
    response: Response = client.get(
        "https://example.com/",
        headers={"accept": "*/*"},
        order=["accept"],
        cookies=["a=1"],
        browser_context=context,
    )
    status: int = response.status
    content: bytes = response.content
    set_cookie: tuple[str, ...] = response.headers["set-cookie"]
    cookies: tuple[str, ...] = response.cookies
    ok: bool = response.ok
    hello: Hello = client.hello()
    capabilities: tuple[str, ...] = hello.capabilities
    client.post("https://example.com/", b"\x89PNG")
    client.request("https://example.com/", method="PUT", body="text", browser_context={"kind": "navigation"})
    with Client(
        profile="chrome",
        proxy="http://user:pass@proxy.example:8080",
        timeout=30.0,
        binary=Path("bin/tls-forge"),
        insecure=False,
        cookie_file="cookies.json",
        cookie_set="eu",
        on_stderr=print,
    ) as scoped:
        scoped.close()
    try:
        client.get("https://example.com/")
    except tlsforge.SessionReset as reset:
        transport: tlsforge.TransportError = reset
        base: tlsforge.TLSForgeError = transport
        del base
    except tlsforge.Timeout as late:
        builtin: TimeoutError = late
        del builtin
    del status, content, set_cookie, cookies, ok, capabilities

    # A kind Chrome does not send, a context without its kind, and the
    # protocol's spelling of a key, which is not this package's.
    client.get("https://example.com/", browser_context={"kind": "websocket"})  # type: ignore[arg-type]
    client.get("https://example.com/", browser_context={"initiator": "https://a.example/"})  # type: ignore[arg-type]
    client.get(
        "https://example.com/",
        browser_context={"kind": "fetch", "referrerPolicy": "origin"},  # type: ignore[arg-type]
    )
    client.post("https://example.com/", 7)  # type: ignore[arg-type]
    Client(timeout="30s")  # type: ignore[arg-type]
    Client(retries=3)  # type: ignore[call-arg]
    response.id  # type: ignore[attr-defined]
    response.status = 201  # type: ignore[misc]
