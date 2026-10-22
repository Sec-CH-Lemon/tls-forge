"""tls-forge — a scraping HTTP client that sends a real browser's TLS fingerprint.

    import tlsforge

    with tlsforge.Client(profile="chrome") as client:
        res = client.get("https://tls.browserleaks.com/json")
        print(res.status, res.json()["ja4"])

The handshake on the wire is Chrome's: the same JA4, the same HTTP/2 settings,
the same headers in the same order. See the project README for what that is for
and how it is verified.
"""

from __future__ import annotations

__version__ = "1.0.0"

from ._binary import ENV_VAR, bundled_binary, exe_name, resolve_binary
from ._client import DEFAULT_TIMEOUT, MAX_REQUEST_BYTES, BrowserContext, Client, Hello, Response
from ._errors import (
    BinaryNotFound,
    RequestFailed,
    SessionReset,
    TLSForgeError,
    Timeout,
    TransportError,
    Unsupported,
)

__all__ = [
    "Client",
    "BrowserContext",
    "Hello",
    "Response",
    "DEFAULT_TIMEOUT",
    "MAX_REQUEST_BYTES",
    "TLSForgeError",
    "BinaryNotFound",
    "TransportError",
    "SessionReset",
    "RequestFailed",
    "Timeout",
    "Unsupported",
    "resolve_binary",
    "bundled_binary",
    "exe_name",
    "ENV_VAR",
]
