# tls-forge

An HTTP client whose TLS and HTTP/2 fingerprints are a real browser's — and a
tool that proves it, by measuring the browser on your machine and diffing it
against the library.

```
$ tls-forge compare
────────────────────────────────────────────────────────────────────────
  browser   Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … Chrome/151.0.0.0 …
  profile   chrome_151
────────────────────────────────────────────────────────────────────────
  match   JA4            t13d1516h2_8daaf6152771_806a8c22fdea
  match   HTTP/2         1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  match   header order   sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,…
────────────────────────────────────────────────────────────────────────

The client is indistinguishable from the browser on every field compared.
```

## Why this exists

Go's `crypto/tls` — like Node's OpenSSL binding, like Python's `ssl` — offers no
control over extension order, GREASE values or the extension set. Those are
exactly what JA3 and JA4 hash. Chrome uses BoringSSL and sends something no
stock TLS stack can produce.

So a request that says `Chrome/151` in its `User-Agent` and demonstrably is not
Chrome in its handshake is not a slightly imperfect disguise. It is a
contradiction between two layers of one identity, and it is trivial to detect.

Plenty of libraries will send a Chrome-ish handshake. What is usually missing is
any way to check that the handshake is still Chrome's after Chrome ships an
update — which is the moment it quietly stops being true. This library treats
that check as the main feature:

* **`tls-forge capture`** measures the browser installed on your machine and
  writes a profile from what it actually sent.
* **`tls-forge compare`** measures the browser *and* this library against one
  local instrument, prints the differences, and exits non-zero if there are any
  — so it can gate a release.

Nothing here is transcribed from documentation. The shipped profile is a
recording of a real ClientHello, and you can regenerate it in ten seconds.

## Install

```bash
go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest
```

As a library:

```bash
go get github.com/Sec-CH-Lemon/tls-forge
```

From Node, see [node/](node/) — a thin client over the same binary.

Requires Go 1.24+. A Chromium-based browser (Chrome, Chromium, Edge, Brave) is
needed only for `capture` and `compare`.

> The command, the repository and the npm package are `tls-forge`. The Go
> package is `tlsforge`, without the hyphen, because Go identifiers cannot
> contain one — so imports read `tlsforge.New(…)`. Error strings use the Go
> package name, as Go convention expects.

## Use

```go
client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
if err != nil {
    return err
}
defer client.Close()

res, err := client.Get("https://example.com")
fmt.Println(res.Status, len(res.Body))
```

The profile supplies the browser's own headers, in the browser's own order.
Per-request headers are layered over it: one the browser already sends keeps its
position and takes your value, one it does not send is appended after the rest.

```go
res, err := client.Do(&tlsforge.Request{
    URL:    "https://example.com/page",
    Header: tlsforge.NewHeader("Referer", "https://example.com/"),
})
```

One client is one identity: one TLS fingerprint, one cookie jar, one exit IP.
Rotating any of them means a new client — deliberately, because a jar shared
between two fingerprints describes a browser that changed its TLS stack
mid-session.

```go
client, err := tlsforge.New(
    tlsforge.WithProfile("chrome"),
    tlsforge.WithProxy("http://user:pass@proxy.example:8080"),
    tlsforge.WithTimeout(20*time.Second),
)
```

### Command line

```
tls-forge capture            measure the browser on this machine
tls-forge compare            diff this library against that browser
tls-forge fetch <url>        make a request wearing the fingerprint
tls-forge serve              run the local echo server, point anything at it
tls-forge daemon             JSON lines on stdin/stdout, for other languages
tls-forge profiles           list what can be impersonated
```

```bash
tls-forge fetch -i https://example.com
tls-forge fetch -H "Referer: https://example.com/" https://example.com/page
tls-forge capture -save my-chrome.json
```

## Measuring your own browser

The profile that ships here was measured from Chrome 151 on macOS. Yours is
probably a different build, and the closer the profile is to the browser you
actually have, the better:

```bash
tls-forge capture -save my-chrome.json
```

A browser window opens, shows what it sent, and can be closed. The profile it
writes holds the raw ClientHello, the HTTP/2 settings, the header order and the
user-agent. Use it:

```go
data, _ := os.ReadFile("my-chrome.json")
p, _ := profile.Load(data)
client, _ := tlsforge.New(tlsforge.WithProfileValue(p))
```

Nothing touches your real browser profile — every launch gets a throwaway
user-data directory, which also keeps the `--ignore-certificate-errors` flag
this needs from ever applying to a profile you browse with.

## How the verification works

There is no third-party service in the loop. `tls-forge serve` is a local HTTPS
server that records the raw ClientHello off the wire, decodes the HTTP/2
preamble and the request headers in order, and reports all of it back to
whoever connected — the same JSON for a browser and for this library.

That matters for three reasons. The tests are hermetic. The check keeps working
when someone else's service is down or changes its output. And a mismatch can be
reported as a structural diff — *this extension, that signature algorithm* —
rather than as two hashes that differ for reasons nobody can see:

```
signature_algorithms
    browser: mldsa44, mldsa65, mldsa87, ecdsa_secp256r1_sha256, …
    client:  ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, …
    missing: mldsa44, mldsa65, mldsa87
```

JA3, JA4, JA4_r and the Akamai HTTP/2 fingerprint are computed locally, from the
bytes. The implementation was checked against `tls.peet.ws` for the same browser
before any of it was written: same JA4, same HTTP/2 hash, same header order.

You can point anything else at it too:

```bash
tls-forge serve
curl -k https://localhost:PORT/api/all
```

## Things worth knowing

**JA3 is not usable for Chrome.** Chrome shuffles its extension order on every
connection, so the same browser produces a different JA3 for every request it
makes — three consecutive connections gave three JA3 hashes and one JA4. This
library shuffles too, because not shuffling is itself a signal, and `compare`
deliberately does not compare JA3.

**A resumed connection has a different JA4.** Resumption adds `pre_shared_key`,
one more extension, so the count and the extension hash both move. Real Chrome
151 sends `t13d1516h2_…_806a8c22fdea` cold and `t13d1517h2_…_a87ad97598a9`
resumed. Both are that browser. The echo server refuses to issue tickets by
default, so captures are always the cold handshake — the one a server sees on
first contact.

**Header order is half the problem.** Most HTTP libraries keep headers in a map
and emit them sorted or at random. A client whose TLS is perfect and whose
headers arrive alphabetically has announced itself. `tlsforge.Header` is an
ordered list for that reason, and `Set` replaces in place rather than moving the
header to the end.

**Post-quantum signatures.** Current Chrome advertises ML-DSA (`mldsa44`,
`mldsa65`, `mldsa87`) ahead of the classical signature algorithms. Their absence
was, for a long time, the only difference between a stock impersonation profile
and the real browser — and it is enough to change the JA4.

## From other languages

The `daemon` command speaks one JSON object per line on stdin/stdout, so any
language can borrow the fingerprint without reimplementing one:

```
in : {"id":7,"url":"https://…","headers":{"a":"b"},"order":["a"]}
out: {"id":7,"status":200,"url":"…","body":"…","headers":{…}}
```

The process is long-lived and holds one client, which means one fingerprint, one
jar and one exit IP for its whole life.

The `id` is echoed on every response, including every error, and a caller should
drop any line whose id it is not waiting for. That looks redundant for a protocol
that handles one request at a time, but it is not: a caller that gives up on a
slow request typically kills the process, and the abandoned process can already
have a complete answer on its way up the pipe. Without an id, that answer is
indistinguishable from the next request's — one page filed under another page's
request, well-formed and wrong.

A Node client is in [node/](node/):

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome' });
const res = await client.get('https://example.com');
client.close();
```

## Scope

This is a network-layer tool. It makes a request look like it came from a
browser. It does not run JavaScript, execute challenges or solve CAPTCHAs, and
it is not a way around a site that has told you not to scrape it. Use it where
you are permitted to make the requests you are making — testing your own
anti-bot stack, measuring your own fingerprint surface, building clients for
APIs you are entitled to use.

## Development

```bash
make test        # go test -race ./...
make cover       # fails if any package is below 100%
make node-test   # the Node client's own tests
make lint        # golangci-lint
make build       # ./bin/tls-forge
make check       # everything CI runs
```

Every package is at 100% statement coverage and CI enforces it. That is not
coverage for its own sake: most of the code here is about what happens when
something goes wrong — a truncated ClientHello, a client that hangs up
mid-response, an answer arriving after the caller gave up — and none of it is
reachable by using the library normally. A branch no test can reach is usually
a branch that should not exist.

## Credits

The TLS transport is [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)
and [bogdanfinn/utls](https://github.com/bogdanfinn/utls), a fork of
[refraction-networking/utls](https://github.com/refraction-networking/utls). The
JA4 specification is [FoxIO's](https://github.com/FoxIO-LLC/ja4). What this
project adds is the measurement harness: capture from a real browser, synthesise
a profile from it, and verify the result locally.

## Licence

MIT. See [LICENSE](LICENSE).
