# TLS Forge for Node.js

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



`tls-forge` is an ESM HTTP client whose network fingerprint comes from a
measured browser profile. It controls the TLS ClientHello, HTTP/2 settings and
header order that Node's OpenSSL-based TLS stack cannot reproduce by changing a
`User-Agent`.

The Node package handles application orchestration and communicates with one
long-lived `tls-forge daemon` process. The project overview, CLI and explanation
of TLS fingerprinting are in the
[main README](https://github.com/Sec-CH-Lemon/tls-forge#readme).

It does not execute page JavaScript and does not solve CAPTCHAs or managed
challenges. It addresses rejection caused specifically by TLS and HTTP
fingerprint mismatch.

## Requirements and installation

- Node.js 20.12 or newer;
- a supported prebuilt transport or Go 1.26.9+ for a local build.

```bash
npm install tls-forge
```

The package ships platform-specific binaries through optional npm dependencies.
No postinstall script or network download is used. Prebuilt transports are
published for:

- macOS arm64 and x86-64;
- Linux arm64 and x86-64;
- Windows x86-64.

Do not install with `--no-optional` unless a transport is supplied separately.
For a custom build:

```bash
export TLSFORGE_BIN=/absolute/path/to/tls-forge
```

## Basic use

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome' });

try {
  const response = await client.get('https://tls.browserleaks.com/json');
  console.log(response.status);
  console.log(JSON.parse(response.body));
} finally {
  client.close();
}
```

Constructing a client resolves the transport path but starts the process lazily
on the first request.

## Constructor options

```js
const client = new Client({
  profile: 'chrome_151',
  proxy: 'http://user:pass@proxy.example:8080',
  timeout: 45_000,
  binary: '/absolute/path/to/tls-forge',
  insecure: false,
  cookieFile: '/absolute/path/to/cookies.json',
  cookieSet: 'warm-eu',
  onStderr: (line) => console.debug(line),
});
```

| Option | Type and default | Meaning |
|---|---|---|
| `profile` | `string`, CLI default | Profile name or JSON profile path passed to `tls-forge daemon --profile`. |
| `proxy` | `string`, direct | HTTP, HTTPS or SOCKS proxy URL, optionally with credentials. It reaches the daemon on the first line of its input, the init line `--proxy-stdin` asks for, and not on its command line, which `ps` shows every user of the machine, nor in its environment, which its owner can read while it runs. A `tls-forge` older than `--proxy-stdin` is refused with an error saying so, before any request. A daemon that does not take the proxy fails the requests waiting with why, and with no `SessionReset`: there was no session yet. |
| `timeout` | `number`, `45000` | Per-request deadline in milliseconds, counted from the call: the time a request waits behind another is inside it. It must be positive and finite. The Go transport receives an additional 15-second grace period so both timeout layers do not race. |
| `binary` | `string`, auto | Explicit path to the `tls-forge` executable. A missing explicit path is an error and does not fall through to another version. |
| `insecure` | `boolean`, `false` | Skip upstream certificate verification. Use only for controlled endpoints. |
| `cookieFile` | `string`, none | Warm the daemon jar from `--cookies`. |
| `cookieSet` | `string`, random | Select a set in `cookieFile`; requires `cookieFile`. |
| `onStderr` | `(line: string) => void`, no-op | Receive transport diagnostics. Exceptions thrown by the callback are ignored so diagnostics cannot crash request handling. |

`new Client()` uses the daemon's default profile, which is a locally installed
`local` profile when available and otherwise the latest bundled `chrome`
profile.

## Request methods

### `get(url, options?)`

```js
const response = await client.get('https://example.com/page', {
  headers: {
    referer: 'https://example.com/',
    'accept-language': 'en-GB,en;q=0.9',
  },
  order: ['referer', 'accept-language'],
  cookies: ['session=abc'],
});
```

### `post(url, body, options?)`

A POST goes in a browser context, as the page's script or form sends it: a
request without one is a navigation typed into the address bar, which posts
nothing, and the transport refuses it (`RequestFailed`, `... needs a browser
context ...`).

```js
const response = await client.post(
  'https://example.com/api',
  JSON.stringify({ hello: 'world' }),
  {
    headers: { 'content-type': 'application/json' },
    browserContext: { kind: 'fetch', initiator: 'https://example.com/' },
  },
);
```

### `request(request)`

```js
const response = await client.request({
  url: 'https://example.com/resource',
  method: 'DELETE',
  headers: { authorization: 'Bearer token' },
  cookies: ['session=abc'],
  browserContext: { kind: 'fetch', initiator: 'https://example.com/' },
});
```

| Request option | Type and default | Meaning |
|---|---|---|
| `url` | `string`, required | Absolute HTTP or HTTPS URL. |
| `method` | `string`, `GET` in `request()` | HTTP method. `get()` and `post()` set it automatically. |
| `headers` | `Record<string, string>`, `{}` | The request's own fields. Without a `browserContext` each goes where Chrome writes that field, in place of Chrome's own, and one Chrome has no place for after `user-agent`, by the bytes of its name, as Chrome driven by automation writes it; in one, what the page's script gives `fetch()` or an XHR. |
| `order` | `string[]`, profile order | Order for caller-only headers, where a profile lays them out as given (not Chrome's profiles, which place every field). |
| `body` | `string \| Buffer \| Uint8Array`, empty | Request body. A `Buffer` or `Uint8Array` is sent as base64 so it arrives intact. A request without a `browserContext` has none. |
| `cookies` | `string[]`, `[]` | `name=value` pairs added to the cookie jar before the request. |

A `cookie` header goes with the jar's cookies: every cookie it names first,
then those the jar holds for the URL, over HTTP/1.1 and HTTP/2 alike; a
redirect's hop carries the jar's alone, as Chrome's does. `cookies` adds values
to the jar instead, where they go on every later request and hop they belong to
and give way to a value the server sets; a name
in both would go twice.

## Response

Every successful request resolves to an object with exactly these fields, in
this order:

```js
{
  status: 200,
  url: 'https://example.com/final',
  body: '<html>...</html>',
  content: <Buffer 3c 68 74 6d 6c 3e ...>,
  headers: {
    'content-type': ['text/html; charset=utf-8'],
    'set-cookie': ['a=1', 'b=2'],
  },
  cookies: ['a=1', 'b=2'],
}
```

What else the daemon's answer carries, such as its `id` and how its body was
encoded, and any field a newer daemon adds, stays in the client.

| Field | Meaning |
|---|---|
| `status` | HTTP status code. Non-2xx responses still resolve normally. |
| `url` | Final URL after redirects. |
| `body` | Decompressed response body as a string. Bytes that are not valid UTF-8 appear as U+FFFD. |
| `content` | The same body as a `Buffer`, exactly as it arrived. Use this for images, archives, or anything that is not text. |
| `headers` | Lower-cased names mapped to arrays of field values. Repeated `set-cookie` fields remain separate. |
| `cookies` | `name=value` pairs the daemon's jar holds for the final URL. |

The SDK also accepts the old daemon protocol where a header value was a scalar
string, but always normalises the public result to `string[]`.

## Identity, queueing and close

One `Client` is one browser identity:

- one transport process;
- one TLS and HTTP profile;
- one cookie jar;
- one proxy and exit IP.

Requests on one client are processed sequentially. Concurrent calls are queued
in call order. Use a pool of clients for parallel scraping, normally one client
per proxy:

```js
const clients = proxies.map((proxy) => new Client({ proxy }));
try {
  const pages = await Promise.all(
    urls.map((url, index) => clients[index % clients.length].get(url)),
  );
} finally {
  for (const client of clients) client.close();
}
```

`close()` is final. It terminates the process, closes all pipe handles and
rejects queued or in-flight requests. Later calls reject instead of silently
creating a new identity. An idle daemon is unreferenced, so forgetting
`close()` no longer keeps Node alive; call it anyway when the identity should
be released immediately rather than at process exit.

## Failures and recovery

The SDK throws and rejects with these classes, exported by the package and
the ones the Python package raises. Each is an `Error` whose `name` is its
class, and one that wraps another error keeps it as `cause`.

| Class | Meaning |
|---|---|
| `TLSForgeError` | The base of every class below. |
| `BinaryNotFound` | No usable transport binary was found, or an explicit path was missing. Thrown by the constructor and `resolveBinary`. |
| `RequestFailed` | The daemon ran, but the HTTP request failed: DNS, proxy, TLS or connection failure, or a request it would not make as asked. |
| `Timeout` | The Node deadline passed: `tlsforge: request timed out`. |
| `TransportError` | The daemon could not start, would not take its arguments or its proxy, exited, could not be written to, was closed, or returned invalid protocol data. |
| `SessionReset` | A `TransportError`: the request was not sent, because the session it was made in has gone. |
| `Unsupported` | The request was not sent, because the transport does not do what it needs: a `browserContext`, which a tls-forge older than this one does not apply. |

A mistake in the call is none of these. It is a `TypeError`, for a request
without a url, a body that is not a string, `Buffer` or `Uint8Array`, a
request JSON cannot hold, an `onStderr` that is not a function, or a
`cookieSet` without a `cookieFile`. It is a `RangeError` for a timeout that is
not a positive finite number, and for a request longer than
`MAX_REQUEST_BYTES`, 16 MiB as the transport reads it: JSON, a binary body in
base64, and the newline. Such a request is refused before it is queued, and
the transport and its session are left as they were.

A timeout or a broken write stops the transport, and a transport can die. The
session in it goes with it: its cookies, TLS sessions and connections. The
request it was working on fails with the reason, and every request waiting
behind it is rejected with `SessionReset`, without being sent; when none was
waiting, the next request made is. Requests after that start a new session in
a new transport. The client never promises the identity it had before, so a
session that has to be the same one is warmed again, or kept in a cookie file.
Each request and response carries a monotonically increasing id, so a late
answer cannot resolve a newer request.

`onStderr` receives diagnostics such as dropped late responses. It is not a
replacement for handling rejected request promises.

## Asking what the transport is

`await client.hello()` resolves to `{ protocol, capabilities }`: the protocol
the transport speaks and what it can do that a client has to ask about,
asked without a connection and once for the client's life. A tls-forge older
than the question speaks protocol 1, and can do nothing it is asked about.

A request with a `browserContext` is sent only to a transport whose
capabilities include `browser_context`, as the field `browser`, and rejected
with `Unsupported`, unsent, by any other. The first such request waits for the
answer to `hello`, so a request made after it may go first.

## Sending a request as a page would

```js
const page = 'https://shop.example/item/7';
const response = await client.request({
  url: 'https://api.shop.example/cart',
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: '{"item":7}',
  browserContext: { kind: 'fetch', initiator: page },
});
```

`browserContext` says what in a browser the request stands for, and it goes
out as Chrome sends that: `kind` is `navigation`, `form`, `fetch` or `xhr`,
`initiator` the page it is sent from, and `referrerPolicy`, `mode` and
`credentials` are as in the Go library, whose
[browser contexts](../GO.md#browser-contexts) say what each does, CORS and
all. A `browserContext` that is no object, or has a key the protocol does not,
is rejected with a `TypeError` before anything is asked, and `null` is none. A
request a page could not send, a request CORS stops and one Chrome blocks as
mixed content (from a page over https to plain http on another machine) are
rejected with the transport's error, a `RequestFailed`, and nothing more is
sent.

## TypeScript

The package ships its types, `index.d.ts`. A TypeScript program needs
`@types/node` beside them, as any Node.js program in TypeScript does. They
declare what the package does at run time and no more: the client, its
options, `Request`, `RequestOptions`, `BrowserContext`, `Response`, `Hello`,
`resolveBinary`, `MAX_REQUEST_BYTES` and the error classes. A browser
context's `kind`, `referrerPolicy`, `mode` and `credentials` are the values
the daemon takes. [`example/typescript/`](../example/typescript/) is checked
against them with TypeScript 5.9 in strict mode, refusals included, and run.

```ts
import { Client, SessionReset, type Response } from 'tls-forge';

const client = new Client({ profile: 'chrome' });
try {
  const response: Response = await client.get('https://example.com/');
  console.log(response.status, response.headers['content-type']);
} catch (err) {
  if (err instanceof SessionReset) console.log('warm the session again');
  else throw err;
} finally {
  client.close();
}
```

## Binary resolution

The exported `resolveBinary(explicit?)` function and `Client` use this order:

1. constructor `binary` option;
2. `TLSFORGE_BIN` environment variable;
3. platform-specific optional npm package;
4. `node/vendor/tls-forge` from `npm run build`;
5. `tls-forge` on `PATH`.

```js
import { resolveBinary } from 'tls-forge';

console.log(resolveBinary());
```

An explicit path that does not exist is rejected instead of silently choosing a
different binary.

## Development

From the repository root:

```bash
make node-test
```

Or inside `node/`:

```bash
npm test
```

The suite uses a stand-in daemon and requires 100% line, function and branch
coverage. To build a local transport into `node/vendor/`:

```bash
npm run build
```

The project is licensed under Apache-2.0; see
[`LICENSE`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/LICENSE),
[`NOTICE`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/NOTICE) and
[`THIRD-PARTY-NOTICES.txt`](https://github.com/Sec-CH-Lemon/tls-forge/blob/main/THIRD-PARTY-NOTICES.txt).
