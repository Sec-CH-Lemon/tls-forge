# The daemon protocol

## Engine/profile compatibility (6.0.0)

The compiled engine version is **6.0.0**, independently of the browser build and
profile format **schema 4**. Every executable profile must declare the exact,
non-negative integer `engine_major: 6`. Engines reject profiles from both older
and newer majors, including files with no declaration. Schema, filename, browser
name, User-Agent and catalogue fallback cannot supply compatibility implicitly.
The check runs before request-related DNS, proxy, TCP, TLS or QUIC I/O.

```json
{"schema": 4, "engine_major": 6, "name": "my-browser"}
```

This illustrates metadata only; a complete profile still needs captured TLS/HTTP
data and the explicit `behavior` object. Browser values and selections stay in
JSON. Any coordinated change requiring shipped engine/fork runtime code increments
the project major exactly once, even a compatible fix. Existing primitives can be
configured by JSON without an engine bump. Versioned CLI, daemon and SDK identity
must agree; `engine/version.json` is the compiled authority. Release builds refuse
a different version stamp. Crossing to major 2 will also require Go module path
versioning.

`profile.Load` is the execution loader. `profile.Inspect` reads an archive offline
without declaring it compatible. `Save` and `Clone` preserve the original
`engine_major`, including absence; they never retag an old profile. Explicit
migration creates a candidate while preserving original capture provenance:

```go
old, err := profile.Inspect(originalJSON) // offline; handle err
candidate, err := old.Migrate("my-browser-engine-6") // handle err
migratedJSON, err := candidate.Save() // save to a separate destination
```

Preserve the original file. Migration is not browser equivalence acceptance;
repeat the relevant actual browser/wire checks before relying on its behavior.
The 15 shipped profiles and all backend catalogue policies have explicit engine-6
migration provenance; older captured browser builds are not new measurements.
A bare catalogue preset still supplies no browser headers.

For a new programmatically created Go profile, explicitly set
`EngineMajor: profile.Major(tlsforge.EngineMajor())`. Never use this assignment to
silently accept an imported file. `tlsforge.Version()` and `tlsforge.EngineMajor()`
report the compiled identity. Client constructors, transport adapters, the
registry and `Fresh` enforce it; client/profile clones own their major value.

Daemon protocol **3** reports `engine_major` and `version` on `hello`. Every
request and proxy `init` line must carry `engine_major: 6`; missing or mismatched
metadata is rejected before client execution. Offline `hello` can omit the field.
Node/Python validate the actual daemon identity before every first request,
including plain requests, and revalidate a replacement process. An old executable
from PATH is rejected rather than used silently. Update the SDK and binary
together; no compatibility flag disables the gate.



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

An `error` field says nothing of the password of any URL it quotes.

## The init line

A daemon started with `--proxy-stdin` takes its proxy from the first line of
its input, the init line, and from nowhere else:

```json
{"id": 1, "engine_major": 6, "control": "init", "proxy": "http://user:pass@host:8080"}
```

It reads that line before it makes the client that goes through the proxy,
and answers it before it reads another: without an `error` when it takes
requests from then on, or with one, after which it ends with exit code 1.
Blank lines before it are passed over. Each of these is such an error, and
nothing is sent:

- a first line that is not an init line, a request among them, or an init
  line that also names a `url`;
- an init line with no `proxy`, or with one that is not a proxy URL tls-forge
  can use;
- an input that ends first, or a first line longer than a request line may
  be;
- anything else that keeps the daemon from starting, such as a `--cookies`
  file there is none of.

A profile there is none of ends the daemon with exit code 1 before it reads
its input, and the init line goes unanswered. An init line later in the input
is a bad request: answered with why, and passed over. `--proxy-stdin` with
`--proxy` or `--proxy-env` is a usage error, exit code 2, before the input is
read.

The Node.js and Python packages start the daemon this way when a client has a
proxy. A command line is what `ps` shows every user of the machine. The
environment, which `--proxy-env NAME` reads, is what the process's owner and
root can read for as long as it runs. The input is read once, and is gone.

A daemon older than `--proxy-stdin` refuses the flag with exit code 2 before
it reads a request, and the packages say it is older than they are. Until the
init line is answered without an `error` there is no session. An `error`, no
answer within the client's timeout, a line that is not an answer, a write that
fails and a daemon that ends each stop the daemon and fail every request
waiting, with why and without the password, and none is a session that went.
The next request starts another daemon, told its proxy first, as is every
daemon a client starts again.

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
| `url` | required: an http or https URL, sent as Chrome writes it ([GO.md](../GO.md#requests)); one Chrome sends nothing for, such as one on port 6000, fails before anything is sent |
| `headers` | layered over the profile's; see below |
| `order` | the order of the headers you send; when omitted, the profile's own order is used |
| `body` | request body |
| `bodyEncoding` | how to read `body`: absent or `utf8` for text, `base64` for bytes |
| `setCookie` | `name=value` pairs added to the jar before the request |
| `browser` | the browser context the request is made in: `{"kind": "fetch", "initiator": "https://shop.example/item/7"}`, with `referrerPolicy`, `mode` and `credentials` as the Go library's `BrowserContext` has them ([GO.md](../GO.md#browser-contexts)); sent only to a daemon that says `browser_context`, see [Asking what a daemon is](#asking-what-a-daemon-is) |
| `control` | makes the line a question for the daemon instead of a request; see the same |

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

`url` is the final URL after redirects, as Chrome writes it. Every value in
`headers` is an array; values are never folded together because doing that
changes the meaning of headers such as `set-cookie`. `cookies` is what the jar
holds for that URL afterwards: an empty list when it holds nothing, and never
`null` on an answer. `null` is how a failure, below, says it has no cookies to
report.

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

A field of a request line the protocol does not have is passed over, as it
always has been: the Node.js package of 0.2 and before put a caller's whole
request object on the line, so a field it does not name was sent, and
refusing it now would fail a request that worked. What a field added since
says is behind a capability, and read strictly there: `browser` below.

## Asking what a daemon is

A line with `control` instead of `url` is a question for the daemon, answered
without a connection. `hello` asks which protocol it speaks and what it can do
that a client has to ask about before relying on it:

```json
{"id": 10, "control": "hello"}
{"id": 10, "status": 0, "url": "", "body": "", "headers": null, "cookies": null, "protocol": 3, "engine_major": 6, "version": "1.0.0",
 "capabilities": ["browser_context"]}
```

`capabilities`, a list of names, is absent while there are none; a client reads
its absence as none. A daemon older than control lines, protocol 1, answers
`hello` as a request with no url, `"error": "bad request: no url"`, and makes no
connection either: a client reads that as protocol 1 and no capabilities.
`init` is [the init line](#the-init-line), which only the first line of a
daemon started with `--proxy-stdin` is, and is refused anywhere else. Any
other `control` is refused, as is a control line that carries a `url`.

A request that needs a capability is sent only to a daemon that says it has it.
`browser`, the browser context a request is made in, is the first: a daemon
that says `browser_context` sends the request as Chrome sends its kind, CORS
and all, and one that predates the field sends it as though it had none. This
one reads `browser` strictly: a field the protocol does not have, or a value
of the wrong type, is `"error": "bad request: browser: ..."`, and what the
library refuses of the context itself, a request CORS stops, and one Chrome
blocks as mixed content, are an `error` too, with nothing more sent. The Node.js and Python packages ask
`hello` before the first request with a browser context, refuse it with
`Unsupported` when the daemon does not say `browser_context`, and keep the
answer for the client's life: what a binary is does not change between its
processes. A question is made in no session: it is not told that a session has
gone, and the next request is.

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
* with a proxy, `--proxy-stdin` and the init line before anything else, to
  every process started: until it is answered without an `error`, whatever
  goes wrong stops the process and fails what waits, and no session is lost
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
