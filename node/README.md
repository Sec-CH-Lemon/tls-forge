# TLS Forge for Node.js

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
- a supported prebuilt transport or Go 1.25.13+ for a local build.

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
  onStderr: (line) => console.debug(line),
});
```

| Option | Type and default | Meaning |
|---|---|---|
| `profile` | `string`, CLI default | Profile name or JSON profile path passed to `tls-forge daemon --profile`. |
| `proxy` | `string`, direct | HTTP, HTTPS or SOCKS proxy URL, optionally with credentials. |
| `timeout` | `number`, `45000` | Per-request deadline in milliseconds. It must be positive and finite. The Go transport receives an additional 15-second grace period so both timeout layers do not race. |
| `binary` | `string`, auto | Explicit path to the `tls-forge` executable. A missing explicit path is an error and does not fall through to another version. |
| `insecure` | `boolean`, `false` | Skip upstream certificate verification. Use only for controlled endpoints. |
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

```js
const response = await client.post(
  'https://example.com/api',
  JSON.stringify({ hello: 'world' }),
  {
    headers: { 'content-type': 'application/json' },
    order: ['content-type'],
  },
);
```

### `request(request)`

```js
const response = await client.request({
  url: 'https://example.com/resource',
  method: 'DELETE',
  headers: { authorization: 'Bearer token' },
  order: ['authorization'],
  body: '',
  cookies: ['session=abc'],
});
```

| Request option | Type and default | Meaning |
|---|---|---|
| `url` | `string`, required | Absolute HTTP or HTTPS URL. |
| `method` | `string`, `GET` in `request()` | HTTP method. `get()` and `post()` set it automatically. |
| `headers` | `Record<string, string>`, `{}` | Headers layered over the profile. Existing profile names retain their browser position. |
| `order` | `string[]`, profile order | Order for headers supplied by the caller. Unnamed caller headers follow in sorted order. To control the complete sequence, provide every header in both `headers` and `order`. |
| `body` | `string \| Buffer \| Uint8Array`, empty | Request body. A `Buffer` or `Uint8Array` is sent as base64 so it arrives intact. |
| `cookies` | `string[]`, `[]` | `name=value` pairs added to the cookie jar before the request. |

Do not manually set the `cookie` header unless replacing the jar's entire
output is intentional. `cookies` adds values to the jar and preserves cookies
received earlier in the session.

## Response

Every successful request resolves to:

```js
{
  status: 200,
  url: 'https://example.com/final',
  body: '<html>...</html>',
  headers: {
    'content-type': ['text/html; charset=utf-8'],
    'set-cookie': ['a=1', 'b=2'],
  },
  cookies: ['a=1', 'b=2'],
}
```

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
creating a new identity.

## Failures and recovery

The SDK rejects promises with `Error` instances. The message identifies the
failure category:

- `tlsforge: request timed out` — the Node deadline passed;
- `tlsforge: transport failed to start ...` — executable or spawn failure;
- `tlsforge: transport exited ...` — the daemon died;
- `tlsforge: write failed ...` — the daemon pipe closed during a write;
- `tlsforge: bad response ...` — malformed or unexpected transport output;
- a request error returned by the Go transport — DNS, proxy, TLS or connection
  failure.

A timeout or broken write restarts the transport before the next request. Each
request and response carries a monotonically increasing id, so a late answer
cannot resolve a newer request.

`onStderr` receives diagnostics such as dropped late responses. It is not a
replacement for handling rejected request promises.

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
