# The daemon protocol

`tls-forge daemon` speaks one JSON object per line on stdin, and answers with one
JSON object per line on stdout. It exists so a program in any language can
borrow a browser's fingerprint without reimplementing one.

An input line is read when it is at most 16 MiB, 16,777,216 bytes, its
newline and an inline request body included. A longer line ends the daemon,
with `daemon: a request line is longer than 16777216 bytes, its newline
included` and exit code 1, after reading no more than that: where the next
request begins could be any distance away, and is not looked for. A client
measures a request before it sends it, as the Node.js and Python packages do
(`MAX_REQUEST_BYTES`), since the session ends with the daemon.

```bash
TLSFORGE_PROXY=http://user:pass@host:8080 tls-forge daemon --profile chrome --proxy-env=TLSFORGE_PROXY
```

The Node.js and Python packages pass a proxy that way, in the daemon's own
environment and named by `--proxy-env`, rather than with `--proxy`: a command
line is what `ps` shows every user of the machine. A daemon older than
`--proxy-env` refuses the flag with exit code 2 before it reads a request, and
the packages say it is older than they are. An `error` field says nothing of
the password of any URL it quotes.

## Request

```json
{
  "id": 7,
  "method": "GET",
  "url": "https://example.com/page",
  "headers": {"referer": "https://example.com/"},
  "order": ["referer"],
  "body": "",
  "setCookie": ["session=abc"]
}
```

| Field | Meaning |
|---|---|
| `id` | caller-assigned, echoed on the response — see below |
| `method` | defaults to `GET` |
| `url` | required |
| `headers` | layered over the profile's; see below |
| `order` | the order of the headers you send; when omitted, the profile's own order is used |
| `body` | request body |
| `bodyEncoding` | how to read `body`: absent or `utf8` for text, `base64` for bytes |
| `setCookie` | `name=value` pairs added to the jar before the request |

JSON objects have no order, which is why `order` exists — but it orders the
headers **you** send, not the whole request. They are then merged into the
profile's list: a name the profile already has keeps the profile's position and
takes your value; a name it does not have is appended after the profile's
headers, in the sequence `order` gives. Anything you send that `order` does not
name goes last, sorted — sorted because a Go map iterates randomly, and a header
set that reordered itself between two otherwise identical requests would be a
fingerprint of its own.

So this request:

```json
{"id": 1, "url": "…", "headers": {"referer": "…", "x-extra": "1"}, "order": ["referer"]}
```

goes out as

```
sec-ch-ua, sec-ch-ua-mobile, …, accept-language, priority, referer, x-extra
```

— the browser's order, with your headers after it — not a request beginning with
`referer`.

There is no way to dictate the whole sequence. Naming every header in `order`
does not do it: the merge keeps the profile's position for every name the
profile already has, and only the names it does not have follow in the order you
gave. That is deliberate — the profile's order is the fingerprint being
impersonated, and a request that could reorder it at will would mostly be used
to break it by accident. A caller who genuinely needs a different order needs a
different profile.

The `cookie` header is written by the transport from the jar and appears in
neither.

## Response

```json
{
  "id": 7,
  "status": 200,
  "url": "https://example.com/page",
  "body": "<html>…",
  "headers": {"content-type": ["text/html"], "set-cookie": ["a=1", "b=2"]},
  "cookies": ["session=abc", "csrf=def"]
}
```

`url` is the final URL after redirects. Every value in `headers` is an array;
values are never folded together because doing that changes the meaning of
headers such as `set-cookie`. `cookies` is what the jar holds for that URL
afterwards: an empty list when it holds nothing, and never `null` on an answer.
`null` is how a failure, below, says it has no cookies to report.

`body` has been decoded from any gzip, deflate, br or zstd it came in, and
`headers` describe it decoded: `content-encoding` and `content-length` are left
out once it is, so a client that passes the headers on with the body never
tells the next reader to decode it again. A body in a coding Chrome does not
know either comes as it came, its `content-encoding` with it.

### Bodies that are not text

A JSON string cannot hold arbitrary bytes: an encoder replaces every byte that
is not valid UTF-8 with U+FFFD, silently, and the response still says `200` with
no error. So a body that is not valid UTF-8 travels as base64 and says so:

```json
{"id": 7, "status": 200, "url": "https://example.com/logo.png",
 "body": "iVBORw0KGgo=", "bodyEncoding": "base64",
 "headers": {"content-type": ["image/png"]}, "cookies": []}
```

`bodyEncoding` is **absent** for a text body rather than spelled `utf8`, so the
overwhelming majority of responses are on the wire they have always been on. A
client must treat an absent value and `utf8` alike, decode `base64` when it sees
it, and reject anything else rather than guess.

The same field works in the other direction: a request carrying bytes sets
`bodyEncoding` to `base64` and base64-encodes `body`.

Response *header* values are still carried as JSON strings. If an upstream
header contains bytes that are not valid UTF-8 — rare, but a latin-1
`content-disposition` filename can do it — the daemon returns an explicit
`error` instead of letting the JSON encoder replace bytes silently. Headers are
not base64-encoded because that would change their public type in every client.

Failures come back on the same shape, with `error` set and the id intact:

```json
{"id": 7, "status": 0, "url": "", "body": "", "headers": null, "cookies": null,
 "error": "tlsforge: dial tcp: connection refused"}
```

A request whose `bodyEncoding` is unknown, or whose `body` does not decode as
the base64 it claims to be, comes back the same way with `error` set.

The daemon does not exit on a bad request. A daemon that died on a malformed URL
would take the session's cookie jar with it.

## One process is one identity

The process is long-lived and holds one client: one TLS fingerprint, one cookie
jar, one exit IP for its whole life. That is not a simplification — a fresh
handshake and an empty jar for every request is itself a signal, and no browser
produces it.

Rotating identity means starting another process, which is cheap.

## Why every response carries an id

The protocol is strictly one request at a time, so an id looks redundant. It is
not, and the failure it prevents is silent.

A caller that gives up on a slow request will typically kill the process and
start another. But the abandoned process can already have a complete answer on
its way up the pipe, and that answer arrives after the caller has moved on to the
next request. Without an id it is indistinguishable from the new request's
answer — and the response URL cannot stand in for one, because it is the
post-redirect URL.

The result is one page filed under another page's request: well-formed,
plausible, and wrong.

So the id is echoed on **every** response, including every error path, and a
caller is expected to drop any line whose id it is not waiting for. A response
with no `id` field at all means a binary older than the code driving it.

A JSON object of the wrong *shape* still keeps its id: `encoding/json` records
the type error and carries on decoding, so the id is already in place by the
time the failure is noticed. A genuine syntax error leaves it at 0, and the
caller lets that request time out — the safe way to lose one.

## Deadlines

Give the daemon a longer deadline than the caller's. If they were equal, a
request timing out would race: both sides would decide it had failed, and the
process would be killed while writing the answer.

```
caller deadline                 30s
tls-forge daemon --timeout 45s
```

## Implementing a client

The Node client in [`node/`](../node/) is a working reference. The parts that
matter:

* one request in flight at a time, the rest queued
* a monotonic id that is **never reset**, not even across a restart — an id must
  never name two different requests, or a late answer from the process you
  killed can match the request that replaced it
* drop any response whose id is not the one in flight
* a line that is not parseable JSON, or is JSON but not an object, fails the
  in-flight request immediately; ids keep a later valid response from being
  assigned to the wrong request
* on timeout, restart the process *and* stop reading its old stdout — killing a
  process does not stop the bytes it already wrote from arriving
* SIGTERM stops the daemon in order: it reads no more requests, cancels the
  one it is making and answers it with an `error` saying so, and exits 0. A
  second SIGTERM ends it at once
* a process that is stopped or dies takes the session with it — cookies, TLS
  sessions, connections — so the packages fail every request waiting for it,
  or the next one made when none was waiting, with `SessionReset`, unsent,
  rather than send it as a new identity nobody asked for
