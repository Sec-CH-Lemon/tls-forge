# TLS Forge for Python

## Engine/profile compatibility (1.0.0)

The compiled engine version is **1.0.0**, independently of the browser build and
profile format **schema 4**. Every executable profile must declare the exact,
non-negative integer `engine_major: 1`. Engines reject profiles from both older
and newer majors, including files with no declaration. Schema, filename, browser
name, User-Agent and catalogue fallback cannot supply compatibility implicitly.
The check runs before request-related DNS, proxy, TCP, TLS or QUIC I/O.

```json
{"schema": 4, "engine_major": 1, "name": "my-browser"}
```

This illustrates metadata only; a complete profile still needs captured TLS/HTTP
data and the explicit `behavior` object. Browser values and selections stay in
JSON. Major selection is anchored to the latest published stable release:
`latest_released_major + 1` for an engine change, once for the whole next release.
The current candidate is **unreleased1.0.0** after0.2.2. Further runtime changes
before1.0.0 is published stay in major1; after publication, the next engine change
targets2.0.0. Existing primitives can be configured by JSON without an engine bump. Versioned CLI, daemon and SDK identity
must agree; `engine/version.json` is the compiled authority. Release builds refuse
a different version stamp. Go v1 uses the unsuffixed module path; `/v2` starts with major2. The release anchor and pending status are recorded in `engine/version.json`.

`profile.Load` is the execution loader. `profile.Inspect` reads an archive offline
without declaring it compatible. `Save` and `Clone` preserve the original
`engine_major`, including absence; they never retag an old profile. Explicit
migration creates a candidate while preserving original capture provenance:

```go
old, err := profile.Inspect(originalJSON) // offline; handle err
candidate, err := old.Migrate("my-browser-engine-1") // handle err
migratedJSON, err := candidate.Save() // save to a separate destination
```

Preserve the original file. Migration is not browser equivalence acceptance;
repeat the relevant actual browser/wire checks before relying on its behavior.
The 15 shipped profiles and all backend catalogue policies have explicit unreleased engine-1
migration provenance; older captured browser builds are not new measurements.
A bare catalogue preset still supplies no browser headers.

For a new programmatically created Go profile, explicitly set
`EngineMajor: profile.Major(tlsforge.EngineMajor())`. Never use this assignment to
silently accept an imported file. `tlsforge.Version()` and `tlsforge.EngineMajor()`
report the compiled identity. Client constructors, transport adapters, the
registry and `Fresh` enforce it; client/profile clones own their major value.

Daemon protocol **3** reports `engine_major` and `version` on `hello`. Every
request and proxy `init` line must carry `engine_major: 1`; missing or mismatched
metadata is rejected before client execution. Offline `hello` can omit the field.
Node/Python validate the actual daemon identity before every first request,
including plain requests, and revalidate a replacement process. An old executable
from PATH is rejected rather than used silently. Update the SDK and binary
together; no compatibility flag disables the gate.



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
- a supported platform wheel or Go 1.26.10+ for a custom transport.

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
| `proxy` | `str | None`, direct | HTTP, HTTPS or SOCKS proxy URL, optionally with credentials. It reaches the daemon on the first line of its input, the init line `--proxy-stdin` asks for, and not on its command line, which `ps` shows every user of the machine, nor in its environment, which its owner can read while it runs. A `tls-forge` older than `--proxy-stdin` raises `TransportError` saying so, before any request. A daemon that does not take the proxy fails the request with why, and the next is not `SessionReset`: there was no session yet. |
| `timeout` | `float`, `45.0` | Per-request deadline in seconds, counted from the call: waiting for another thread's request, writing this one and waiting for its answer are all inside it, and a request whose deadline passes before it is sent raises `Timeout` unsent. It must be positive and finite. The Go transport receives an additional 15-second grace period so both timeout layers do not race. |
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

### `post(url, body="", *, headers=None, order=None, cookies=None, browser_context=None)`

A POST goes in a browser context, as the page's script or form sends it: a
request without one is a navigation typed into the address bar, which posts
nothing, and the transport refuses it (`RequestFailed`, `... needs a browser
context ...`).

```python
response = client.post(
    "https://example.com/api",
    '{"hello":"world"}',
    headers={"content-type": "application/json"},
    browser_context={"kind": "fetch", "initiator": "https://example.com/"},
)
```

### `request(url, *, method="GET", headers=None, order=None, body=None, cookies=None, browser_context=None)`

```python
response = client.request(
    "https://example.com/resource",
    method="DELETE",
    headers={"authorization": "Bearer token"},
    cookies=["session=abc"],
    browser_context={"kind": "fetch", "initiator": "https://example.com/"},
)
```

| Request argument | Type and default | Meaning |
|---|---|---|
| `url` | `str`, required | Absolute HTTP or HTTPS URL. |
| `method` | `str`, `"GET"` | HTTP method. `get()` and `post()` set it automatically. |
| `headers` | `Mapping[str, str] | None` | The request's own fields. Without a `browser_context` each goes where Chrome writes that field, in place of Chrome's own, and one Chrome has no place for after `user-agent`, by the bytes of its name, as Chrome driven by automation writes it; in one, what the page's script gives `fetch()` or an XHR. |
| `order` | `Sequence[str] | None` | Order for caller-only headers, where a profile lays them out as given (not Chrome's profiles, which place every field). |
| `body` | `str | bytes | None` | Request body. `bytes` is sent as base64 so it arrives intact; `None` omits the field. A request without a `browser_context` has none. |
| `cookies` | `Iterable[str] | None` | `name=value` pairs added to the daemon's jar before the request. |

A `cookie` header goes with the jar's cookies: every cookie it names first,
then those the jar holds for the URL, over HTTP/1.1 and HTTP/2 alike; a
redirect's hop carries the jar's alone, as Chrome's does. `cookies` adds values
to the jar instead, where they go on every later request and hop they belong to
and give way to a value the server sets; a name in both would go twice.

## Response

Requests return a frozen `tlsforge.Response` record. Its attributes cannot be
reassigned; treat the `headers` mapping as response data rather than mutating
it:

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
| `SessionReset` | A `TransportError`: the request was not sent, because the session it was made in has gone. |
| `Unsupported` | The request was not sent, because the transport does not do what it needs: a `browser_context`, which a tls-forge older than this one does not apply. |

`client.hello()` returns a `Hello(protocol, capabilities)`: the protocol the
transport speaks and what it can do that a client has to ask about, asked
without a connection and once for the client's life. A tls-forge older than the
question speaks protocol 1, and can do nothing it is asked about. A request with
a `browser_context` is sent only to a transport whose capabilities include
`browser_context`, as the field `browser`, and raises `Unsupported`, unsent,
with any other.

```python
page = "https://shop.example/item/7"
response = client.post(
    "https://api.shop.example/cart",
    '{"item":7}',
    headers={"content-type": "application/json"},
    browser_context={"kind": "fetch", "initiator": page},
)
```

`browser_context` says what in a browser the request stands for, and it goes
out as Chrome sends that. Its keys, which `tlsforge.BrowserContext` types, are
`kind` (`navigation`, `form`, `fetch` or `xhr`), `initiator` (the page it is
sent from), `referrer_policy`, `mode` and `credentials`, as in the Go library,
whose [browser contexts](../GO.md#browser-contexts) say what each does, CORS
and all. The client sends them as the protocol names them, so
`referrer_policy` goes as `referrerPolicy`. A `browser_context` that is no
mapping, or has a key there is none of, the protocol's spelling of one
included, raises `TypeError` before anything is asked. A request a page could
not send, a request CORS stops and one Chrome blocks as mixed content (from a
page over https to plain http on another machine) raise `RequestFailed` with
the transport's reason, and nothing more is sent.

Invalid caller values such as an empty URL, non-positive timeout or non-callable
`on_stderr` raise standard `ValueError` or `TypeError`, and so does a request
longer than `MAX_REQUEST_BYTES`, 16 MiB as the transport reads it: JSON, a
binary body in base64, and the newline. It is refused before it is sent, and
the transport and its session are left as they were.

A timeout or a broken write stops the transport, and a transport can die. The
session in it goes with it: its cookies, TLS sessions and connections. The
request it was working on fails with the reason, and every request waiting for
the client then raises `SessionReset`, without being sent; when none was
waiting, the next request made does. Requests after that start a new session in
a fresh daemon. The client never promises the identity it had before, so a
session that has to be the same one is warmed again, or kept in a cookie file.
Monotonically increasing request ids keep a late response from being attached
to the wrong call.

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

`close()` is idempotent and final. It stops and reaps the daemon at once,
without waiting for a request in flight: that request, and any waiting for it,
raises `TransportError("tlsforge: client closed")`, and a write stuck on a
daemon that stopped reading is ended by stopping the daemon first. Later
requests raise rather than silently create a new identity. A finalizer also
cleans up a forgotten client, but deterministic `with` or `close()` usage is
preferred.

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
`fetch --save-cookies` when the final jar must be persisted.

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
type checkers. `tlsforge.BrowserContext` types a `browser_context`, and
`Response`, `Hello` and the errors are typed as they are at run time.

From the repository root:

```bash
make python-test
make python-typecheck
```

The suite uses a stand-in daemon and requires 100% statement and branch
coverage. It does not need a Go build or network access. `make
python-typecheck` runs mypy in strict mode over the package and over
`tests/typing_contract.py`, a module that is never run: each of its
`# type: ignore` comments is a call the annotations must refuse, and strict
mode fails when one is not needed. mypy needs Python 3.10 or newer.

The project is licensed under Apache-2.0; see
[`LICENSE`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/LICENSE),
[`NOTICE`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/NOTICE) and
[`THIRD-PARTY-NOTICES.txt`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/THIRD-PARTY-NOTICES.txt).
