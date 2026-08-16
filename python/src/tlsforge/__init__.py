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

from ._binary import ENV_VAR, bundled_binary, exe_name, resolve_binary
from ._client import DEFAULT_TIMEOUT, Client, Response
from ._errors import (
    BinaryNotFound,
    RequestFailed,
    TLSForgeError,
    Timeout,
    TransportError,
)

__all__ = [
    "Client",
    "Response",
    "DEFAULT_TIMEOUT",
    "TLSForgeError",
    "BinaryNotFound",
    "TransportError",
    "RequestFailed",
    "Timeout",
    "resolve_binary",
    "bundled_binary",
    "exe_name",
    "ENV_VAR",
]

__version__ = "0.0.0.dev0"
