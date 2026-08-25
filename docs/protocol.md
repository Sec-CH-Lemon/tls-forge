# The daemon protocol

`tls-forge daemon` speaks one JSON object per line on stdin, and answers with one
JSON object per line on stdout. It exists so a program in any language can
borrow a browser's fingerprint without reimplementing one.

Each input line is limited to 16 MiB, including an inline request body. A line
that exceeds the limit ends the daemon with a scanner error because its request
boundary cannot be recovered safely.

```bash
tls-forge daemon --profile chrome --proxy http://user:pass@host:8080
```

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
`referer`. To dictate the whole sequence, name every header in `order` and supply
every one of them in `headers`. The `cookie` header is written by the transport
from the jar and appears in neither.

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
afterwards.

Failures come back on the same shape, with `error` set and the id intact:

```json
{"id": 7, "status": 0, "url": "", "body": "", "headers": null, "cookies": null,
 "error": "tlsforge: dial tcp: connection refused"}
```

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
