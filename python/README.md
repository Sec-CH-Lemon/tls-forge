# tls-forge (Python)

**A scraping HTTP client whose TLS fingerprint is a real browser's.** The
handshake on the wire is Chrome's: the same JA4, the same HTTP/2 settings, the
same headers in the same order. The fingerprint check that runs before a page is
ever served has nothing to catch.

Python cannot do this on its own. Its TLS comes from OpenSSL, which exposes no
control over extension order, GREASE values or the extension set — and those are
precisely what JA3 and JA4 hash. Chrome uses BoringSSL. So the socket moves out
of Python into a small Go process, and Python keeps the orchestration.

The project, what it is for and how the impersonation is verified are in the
[main README](../README.md).

## Install

```bash
pip install tls-forge
```

The binary comes with the wheel. Nothing is downloaded during install, no Go is
needed on the machine, and there are no dependencies — the point of this package
is not to be at the mercy of whatever TLS stack a dependency drags in.

Import it as `tlsforge`:

```python
import tlsforge
```

## Use

```python
import tlsforge

with tlsforge.Client(profile="chrome") as client:
    res = client.get("https://tls.browserleaks.com/json")
    print(res.status, res.json()["ja4"])
```

```
200 t13d1516h2_8daaf6152771_806a8c22fdea
```

That address answers with the fingerprint it saw, so the reply is the proof the
impersonation worked. A real Chrome on the same machine reports the same JA4.

`res` is a frozen `Response`:

| | |
|---|---|
| `status` | the HTTP status |
| `url` | the final URL, after redirects |
| `body` | the body, decompressed |
| `headers` | multi-valued names joined with `; ` |
| `cookies` | what the jar holds for this URL afterwards |
| `ok` | `True` for a 2xx |
| `json()` | the body parsed as JSON |

`headers` joins rather than picks: `set-cookie` arrives more than once
routinely, and a caller that only saw the first would lose a session.

### Options

```python
client = tlsforge.Client(
    profile="chrome_151",
    proxy="http://user:pass@host:8080",
    timeout=30,
    cookie_file="cookies.json",
    cookie_set="warm-eu",
)
```

| | |
|---|---|
| `profile` | which browser to impersonate; `tls-forge profiles` lists them |
| `proxy` | an `http://` or `socks5://` URL |
| `timeout` | per-request deadline in **seconds**, default 45 |
| `binary` | path to the tls-forge binary, ahead of every other source |
| `insecure` | skip certificate verification |
| `cookie_file` | a file of warmed cookies to start from |
| `cookie_set` | which set in that file; one at random when not named |
| `on_stderr` | receives the transport's diagnostics, a line at a time |

### Per request

```python
res = client.get(
    "https://example.com/page",
    headers={"referer": "https://example.com/"},
    order=["referer"],
    cookies=["session=abc"],
)

res = client.post("https://example.com/api", '{"a": 1}',
                  headers={"content-type": "application/json"})

res = client.request("https://example.com/x", method="DELETE")
```

`headers` are layered over the profile's: a name the browser already sends keeps
the browser's position and takes your value; one it does not send is appended
after the rest. `order` orders the headers **you** send, not the whole request —
without it they go last, sorted. To dictate the whole sequence, name every
header in `order` and supply every one in `headers`.

Do not set `cookie` by hand. The transport writes it from the jar, and setting
the header replaces what the jar holds, so cookies the server set earlier in the
session would silently vanish from the next request — which no real browser
would do. Use `cookies=` instead, which adds to the jar.

## One client is one identity

A `Client` is one long-lived process: one TLS fingerprint, one cookie jar, one
exit IP for its whole life. Reconnecting per request is itself a signal, and no
browser does it.

`close()` is final. A closed client will not respawn, and a later request raises
rather than quietly minting a new process with a new fingerprint and an empty
jar. Rotating identity means constructing another client.

A client also **serialises**: the protocol underneath is one request at a time,
so calls from several threads queue rather than overlap. That is not a
limitation to work around — it is what one session is. Scrape in parallel with a
pool of clients, one per proxy, which is also how the identities stay separate:

```python
from concurrent.futures import ThreadPoolExecutor
import contextlib, itertools, tlsforge

with contextlib.ExitStack() as stack:
    clients = [stack.enter_context(tlsforge.Client(proxy=p)) for p in proxies]
    turn = itertools.cycle(clients)
    with ThreadPoolExecutor(len(clients)) as pool:
        pages = list(pool.map(lambda u: next(turn).get(u), urls))
```

A jar spread across two exit IPs describes a browser that changed its network
mid-session, which is not a thing that happens. One client per proxy is what
keeps that from happening by construction.

## What can go wrong

```python
try:
    res = client.get(url)
except tlsforge.RequestFailed:   # the request ran and failed: refused, DNS, TLS
    ...
except tlsforge.Timeout:         # the deadline passed; also a builtin TimeoutError
    ...
except tlsforge.TransportError:  # the transport would not start, died, or spoke nonsense
    ...
```

All four, plus `BinaryNotFound`, are `tlsforge.TLSForgeError`, so one `except`
catches the lot. The split is by what to do about it: fix the install, retry, or
fix the call.

The interesting code in this package is what happens when the transport
misbehaves, because those failures are quiet:

* **A request that misses its deadline** raises, and the process is stopped. The
  transport's own deadline is longer than the client's on purpose — if they were
  equal, both sides would decide the request had failed at once and the process
  would be killed while writing the answer.
* **Every request carries an id** and every answer is checked against it. An
  answer whose id does not match is dropped. Without that, a late answer from a
  process that was killed can be handed to whoever asked next: one page filed
  under another page's request, well-formed and wrong.
* **A line that is not a JSON object** fails the request in flight. The process
  is kept — one bad line does not prove the stream is broken, and the id is what
  makes keeping it safe.
* **A forgotten client does not leave its transport running.** A `Popen` that is
  merely garbage collected is not killed; this one is.

Pass `on_stderr` to see the transport's own diagnostics, including dropped
answers.

## Where the binary comes from

In order: the `binary=` argument, `TLSFORGE_BIN`, the binary inside this package,
a `make build` output in a checkout this package is sitting inside, then `PATH`.
An explicit path that does not exist is an error rather than a reason to look
elsewhere — falling through would run a different binary than the one asked for.

## Requirements

Python 3.9+. Nothing else: no dependencies, and the transport ships with the
wheel.

## Development

```bash
make python-test
```

Runs the suite against a stand-in transport — no Go build, no network — and
fails below **100% line and branch coverage**, the way the Go and Node suites do.
