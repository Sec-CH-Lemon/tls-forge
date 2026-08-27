# TLS Forge for Python

`tls-forge` is a typed Python HTTP client whose network fingerprint comes from
a measured browser profile. It controls the TLS ClientHello, HTTP/2 settings and
header order that Python's OpenSSL-based clients cannot reproduce by changing a
`User-Agent`.

The Python package handles application orchestration and communicates with one
long-lived `tls-forge daemon` process. The project overview, CLI and explanation
of TLS fingerprinting are in the
[main README](https://github.com/Sec-CH-Lemon/tls-forge#readme).

It does not execute page JavaScript and does not solve CAPTCHAs or managed
challenges. It addresses rejection caused specifically by TLS and HTTP
fingerprint mismatch.

## Requirements and installation

- Python 3.9 or newer;
- a supported platform wheel or Go 1.25.13+ for a custom transport.

```bash
pip install tls-forge
```

Import the package as `tlsforge`, without the hyphen:

```python
import tlsforge
```

Platform wheels include the transport binary. Installation does not run a
compiler, download an executable through a postinstall hook, or install runtime
Python dependencies.

To use a custom build:

```bash
export TLSFORGE_BIN=/absolute/path/to/tls-forge
```

## Basic use

```python
import tlsforge

with tlsforge.Client(profile="chrome") as client:
    response = client.get("https://tls.browserleaks.com/json")
    print(response.status)
    print(response.json())
```

The transport is resolved during construction and started lazily on the first
request. Prefer the context-manager form so the child process is always closed.

## Constructor options

```python
client = tlsforge.Client(
    profile="chrome_151",
    proxy="http://user:pass@proxy.example:8080",
    timeout=45,
    binary="/absolute/path/to/tls-forge",
    insecure=False,
    cookie_file="cookies.json",
    cookie_set="warm-eu",
    on_stderr=lambda line: print(line),
)
```

| Option | Type and default | Meaning |
|---|---|---|
| `profile` | `str | None`, CLI default | Profile name or JSON profile path passed to `tls-forge daemon --profile`. |
| `proxy` | `str | None`, direct | HTTP, HTTPS or SOCKS proxy URL, optionally with credentials. |
| `timeout` | `float`, `45.0` | Per-request deadline in seconds. It must be positive and finite. The Go transport receives an additional 15-second grace period so both timeout layers do not race. |
| `binary` | `str | os.PathLike | None`, auto | Explicit path to the transport executable. A missing explicit path raises `BinaryNotFound` and does not fall through. |
| `insecure` | `bool`, `False` | Skip upstream certificate verification. Use only for controlled endpoints. |
| `cookie_file` | path or `None` | Load a warmed session from project JSON, browser-export JSON or Netscape cookies.txt. |
| `cookie_set` | `str | None` | Select a named set from a multi-session file; when omitted, the daemon chooses one at random. Requires `cookie_file`; without it, `Client(...)` raises `ValueError`. |
| `on_stderr` | callable or `None` | Receive transport diagnostics one line at a time. Callback exceptions are ignored so diagnostics cannot break the reader thread. |

`tlsforge.DEFAULT_TIMEOUT` contains the default Python-side timeout.

`Client()` without `profile` uses the daemon's default profile: a locally
installed `local` profile when available and otherwise the latest bundled
`chrome` profile.

## Request methods

### `get(url, *, headers=None, order=None, cookies=None)`

```python
response = client.get(
    "https://example.com/page",
    headers={
        "referer": "https://example.com/",
        "accept-language": "en-GB,en;q=0.9",
    },
    order=["referer", "accept-language"],
    cookies=["session=abc"],
)
```

### `post(url, body="", *, headers=None, order=None, cookies=None)`

```python
response = client.post(
    "https://example.com/api",
    '{"hello":"world"}',
    headers={"content-type": "application/json"},
    order=["content-type"],
)
```

### `request(url, *, method="GET", headers=None, order=None, body=None, cookies=None)`

```python
response = client.request(
    "https://example.com/resource",
    method="DELETE",
    headers={"authorization": "Bearer token"},
    order=["authorization"],
    cookies=["session=abc"],
)
```

| Request argument | Type and default | Meaning |
|---|---|---|
| `url` | `str`, required | Absolute HTTP or HTTPS URL. |
| `method` | `str`, `"GET"` | HTTP method. `get()` and `post()` set it automatically. |
| `headers` | `Mapping[str, str] | None` | Headers layered over the profile. Existing profile names retain their browser position. |
| `order` | `Sequence[str] | None` | Order for caller-supplied headers. Unnamed caller headers follow in sorted order. To control the complete sequence, include every header in both `headers` and `order`. |
| `body` | `str | bytes | None` | Request body. `bytes` is sent as base64 so it arrives intact; `None` omits the field. |
| `cookies` | `Iterable[str] | None` | `name=value` pairs added to the daemon's jar before the request. |

Do not manually set the `cookie` header unless replacing the jar's complete
output is intentional. `cookies` preserves values received earlier in the
session.

## Response

Requests return an immutable `tlsforge.Response`:

```python
Response(
    status=200,
    url="https://example.com/final",
    body="<html>...</html>",
    headers={
        "content-type": ("text/html; charset=utf-8",),
        "set-cookie": ("a=1", "b=2"),
    },
    cookies=("a=1", "b=2"),
)
```

| Field or method | Meaning |
|---|---|
| `status` | HTTP status code. Non-2xx responses are still returned normally. |
| `url` | Final URL after redirects. |
| `body` | Decompressed response body as `str`. Bytes that are not valid UTF-8 appear as U+FFFD. |
| `content` | The same body as `bytes`, exactly as it arrived. Use this for images, archives, or anything that is not text. |
| `headers` | Header names mapped to tuples of field values. Repeated `set-cookie` fields remain separate. |
| `cookies` | Tuple of `name=value` pairs held for the final URL. |
| `ok` | `True` for status codes from 200 through 299. |
| `json(**kwargs)` | Parse `body` with `json.loads` and return its result. |

The SDK accepts the old daemon protocol where a header value was a scalar
string, but always normalises the public result to `tuple[str, ...]`.

`Response.json()` raises the standard `json.JSONDecodeError` when the body is
not JSON.

## Exceptions

All package-specific errors inherit from `tlsforge.TLSForgeError`.

```python
try:
    response = client.get(url)
except tlsforge.BinaryNotFound:
    # Fix the installation or binary path.
    ...
except tlsforge.Timeout:
    # Retry or increase the deadline.
    ...
except tlsforge.RequestFailed:
    # DNS, connection, proxy or TLS request failure.
    ...
except tlsforge.TransportError:
    # Process startup, exit, pipe or protocol failure.
    ...
```

| Exception | Meaning |
|---|---|
| `TLSForgeError` | Base class for package errors. |
| `BinaryNotFound` | No usable transport binary was found, or an explicit path was missing. |
| `RequestFailed` | The daemon ran, but the HTTP request failed. |
| `Timeout` | The Python deadline passed. Also inherits from built-in `TimeoutError`. |
| `TransportError` | The daemon could not start, exited, could not be written to, or returned invalid protocol data. |

Invalid caller values such as an empty URL, non-positive timeout or non-callable
`on_stderr` raise standard `ValueError` or `TypeError`.

The client remains usable after a request timeout or transport failure. The next
request starts a fresh daemon while monotonically increasing request ids prevent
a late response from being attached to the wrong call.

## Identity, threads and close

One `Client` is one browser identity:

- one transport process;
- one TLS and HTTP profile;
- one cookie jar;
- one proxy and exit IP.

The client is thread-safe but serialises requests with a lock. Calls from
multiple threads queue instead of overlapping. Use a pool of clients for
parallel scraping, normally one per proxy:

```python
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from itertools import cycle

import tlsforge

with ExitStack() as stack:
    clients = [
        stack.enter_context(tlsforge.Client(proxy=proxy))
        for proxy in proxies
    ]
    turns = cycle(clients)
    with ThreadPoolExecutor(max_workers=len(clients)) as pool:
        pages = list(pool.map(lambda url: next(turns).get(url), urls))
```

`close()` is idempotent and final. It waits for the current request, stops and
reaps the daemon, and prevents later requests from silently creating a new
identity. A finalizer also cleans up a forgotten client, but deterministic
`with` or `close()` usage is preferred.

## Warmed cookie sessions

`cookie_file` accepts the same formats as the CLI:

- a project JSON file containing multiple named sets;
- a bare JSON array of sets;
- a flat browser-extension cookie export;
- Netscape cookies.txt.

```python
with tlsforge.Client(
    cookie_file="cookies.json",
    cookie_set="warm-eu",
) as client:
    response = client.get("https://example.com/")
```

Expired cookies are removed by the daemon before a set is seeded. Cookie
domain, path, secure, HttpOnly and expiry attributes are retained by the Go
cookie jar.

The Python SDK currently loads but does not write session files. Use the CLI
`fetch --save-cookies` or `batch --save-cookies` when the final jar must be
persisted.

## Binary resolution

The exported `tlsforge.resolve_binary(explicit=None)` function and `Client` use
this order:

1. constructor `binary` option;
2. `TLSFORGE_BIN` environment variable;
3. binary bundled in the platform wheel;
4. `bin/tls-forge` from a surrounding source checkout;
5. `tls-forge` on `PATH`.

```python
import tlsforge

print(tlsforge.resolve_binary())
print(tlsforge.bundled_binary())
print(tlsforge.exe_name())
```

An explicit path that does not exist raises `BinaryNotFound` rather than
silently selecting a different version.

## Development and typing

The package includes `py.typed`, so its annotations are available to static
type checkers.

From the repository root:

```bash
make python-test
```

The suite uses a stand-in daemon and requires 100% statement and branch
coverage. It does not need a Go build or network access.

The project is licensed under Apache-2.0; see
[`LICENSE`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/LICENSE),
[`NOTICE`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/NOTICE) and
[`THIRD-PARTY-NOTICES.txt`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/THIRD-PARTY-NOTICES.txt).
