# tls-forge (Node)

**A scraping HTTP client that gets past TLS fingerprinting.** It sends the
handshake a real Chrome sends, so pages behind Cloudflare and the other
bot-detection front doors return their content instead of a challenge.

Node cannot do this on its own. Its TLS comes from OpenSSL, which offers no
control over extension order, GREASE values or the extension set, and those are
precisely what JA3 and JA4 hash. Chrome uses BoringSSL, and a scraper whose
`User-Agent` says Chrome while its handshake says Node is spotted in the first
packet, before a byte of HTTP is read. So the socket moves out of Node into a
small Go process, and Node keeps the orchestration, which is the part it is good
at.

It runs no JavaScript, so managed challenges and CAPTCHAs are a different
problem. What it removes is the check that fires before the page is ever served.

See the [project README](../README.md) for what is being impersonated and, more
to the point, how the disguise is verified against the browser on your machine.

## Install

```bash
npm install tls-forge
```

No Go, no build step, no download during install. The binary arrives as an
optional dependency: one package per platform, each declaring `os` and `cpu`,
so npm installs the one that matches and skips the other four. It is the
arrangement esbuild and swc use, and it survives `npm ci --ignore-scripts`,
which a postinstall step does not.

Prebuilt for darwin-arm64, darwin-x64, linux-arm64, linux-x64 and win32-x64. On
anything else, or to run a build of your own:

```bash
export TLSFORGE_BIN=/path/to/tls-forge
```

which takes precedence over the shipped binary.

## Use

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome' });

const res = await client.get('https://tls.browserleaks.com/json');
console.log(res.status, res.body.length);

client.close();
```

`res` is `{ status, url, body, headers, cookies }`. `url` is the final URL after
redirects; each header maps to an array of values, so repeated `set-cookie`
fields stay separate.

### Options

```js
new Client({
  profile: 'chrome',                  // profile to impersonate
  proxy: 'http://user:pass@host:8080',
  timeout: 45_000,                    // per-request deadline, ms
  binary: '/path/to/tls-forge',        // overrides TLSFORGE_BIN
  insecure: false,                    // skip certificate verification
  onStderr: (line) => log.debug(line),
});
```

### Per-request

```js
await client.get('https://example.com/page', {
  headers: { referer: 'https://example.com/' },
  order: ['referer'],            // header order; defaults to the profile's
  cookies: ['session=abc'],      // added to the jar, not to a Cookie header
});

await client.post('https://example.com/api', JSON.stringify({ a: 1 }), {
  headers: { 'content-type': 'application/json' },
});
```

Cookies go through the jar rather than through a `Cookie` header on purpose:
setting the header by hand *replaces* whatever the jar holds, so cookies the
server set earlier in the session would silently vanish from the next request,
which no real browser would do.

## One client is one identity

A `Client` is one long-lived process: one TLS fingerprint, one cookie jar, one
exit IP for its whole life. Reconnecting per request is itself a signal, and no
browser does it.

`close()` is final. A client that has been closed will not respawn, and a later
request rejects rather than quietly minting a new process with a new fingerprint
and an empty jar. Rotating identity means constructing another client.

For concurrency, run a pool of clients. Each one is a separate session, which is
usually exactly the granularity you want.

```js
const pool = urls.map(() => new Client({ profile: 'chrome', proxy: nextProxy() }));
```

## Failure modes worth knowing

The interesting code in this package is about what happens when the transport
misbehaves, because the failures are quiet:

* **A request that misses its deadline** rejects, and the process is restarted.
  The old process may still be writing an answer, so its stdout is dropped as
  well. Killing a process does not stop the bytes it already wrote from
  arriving.
* **Every request carries an id** and every answer is checked against it. An
  answer whose id does not match the request in flight is dropped. Without that,
  a late answer from a process you killed can be handed to whoever asked next:
  one page filed under another page's request, well-formed and wrong.
* **A line that is not a JSON object** fails the request in flight. A stream
  that has started producing garbage is desynchronised, and waiting for it to
  right itself is how a client goes quiet forever.

Pass `onStderr` to see the transport's own diagnostics, including dropped
answers.

## Requirements

Node 20.12+. Go 1.25.13+ to build the transport, or a prebuilt binary.
