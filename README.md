# tls-forge

**A scraping HTTP client that gets past TLS fingerprinting.** It sends the
handshake a real Chrome sends: the same JA4, the same HTTP/2 settings, the same
header order. The fingerprint check that runs before a page is ever served has
nothing to catch.

And it does not ask you to take that on trust: `tls-forge compare` opens the
browser on your machine, measures it, measures itself, and prints the
difference.

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

## Scraping pages behind Cloudflare

The TLS handshake is on the wire before a single byte of HTTP. That is the
protocol, not a claim about anyone's product, and it is what makes the handshake
worth inspecting. It arrives before the request does, and reading it costs a
defender nothing.

Cloudflare acts on it, and documents doing so: Bot Management exposes the JA3 and
JA4 fingerprint of each request as fields you can write WAF custom rules,
Transform Rules and Workers against, for
[blocking or allowing traffic by fingerprint](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/).

Other vendors are widely said to do the same. This README does not name them,
because their documentation does not say so and this project has not measured
them. A list of plausible names is exactly the kind of claim the rest of this
page exists to avoid.

A scraper written in Go, Node or Python announces itself there. `crypto/tls`,
Node's OpenSSL binding and Python's `ssl` offer no control over extension order,
GREASE values or the extension set, and those are exactly what JA3 and JA4 hash.
Chrome uses BoringSSL and sends something no stock TLS stack can produce. So a
request whose `User-Agent` says `Chrome/151` while its handshake says Go is not
an imperfect disguise; it is a contradiction between two layers of one
identity.

Send the browser's actual handshake and that check has nothing left to fire on.
The same goes one layer up: the HTTP/2 SETTINGS, the connection window update and
the pseudo-header order are what the published HTTP/2 fingerprint format is made
of, and header order is visible to any server that cares to look. A client that
gets the TLS right and then sends its headers alphabetically has moved the tell,
not removed it.

**Where the line is.** This removes the checks that key on *how you connect*. It
does not run JavaScript, so a managed challenge, Turnstile or a CAPTCHA is a
different problem: browser execution rather than fingerprinting. What this
gets you is a request that is not rejected before the page is served. Whether
anything else stands behind that is a property of the site, and worth finding out
before assuming either way.

### The disguise is verified, not asserted

Sending a Chrome-ish handshake is the easy half. The hard half is knowing it is
still Chrome's after Chrome ships an update. That is the moment it quietly stops
being true, and the moment a scraper starts collecting challenge pages instead of
pages. This library treats that check as the main feature:

* **`tls-forge capture`** measures the browser installed on your machine and
  writes a profile from what it actually sent.
* **`tls-forge compare`** measures the browser *and* this library against one
  local instrument, prints the differences, and exits non-zero if there are any,
  so it can gate a release.

Nothing here is transcribed from documentation. The shipped profile is a
recording of a real ClientHello, and you can regenerate it in ten seconds.

## Install

Homebrew, on macOS and Linux:

```bash
brew tap Sec-CH-Lemon/tap
brew trust --formula Sec-CH-Lemon/tap/tls-forge
brew install Sec-CH-Lemon/tap/tls-forge
```

The `brew trust` line is not optional. Homebrew 6 reports that it "is currently
ignoring formulae, casks and commands from these taps because tap trust is
required" for any tap outside its own repositories. It is asking whether you
trust this tap to run code on your machine. That is a fair question, and the
answer is yours.

Prebuilt binaries are also attached to each
[release](https://github.com/Sec-CH-Lemon/tls-forge/releases) as `.tar.gz`, for
macOS and Linux on arm64 and x86-64, and Windows on x86-64.

From Go:

```bash
go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest   # the command
go get github.com/Sec-CH-Lemon/tls-forge                            # the library
```

From Node, see [node/](node/), a thin client over the same binary that needs no
Go.

Building from source needs Go 1.24+. A Chromium-based browser (Chrome, Chromium,
Edge, Brave) is needed only for `capture` and `compare`.

> The command, the repository and the npm package are `tls-forge`. The Go
> package is `tlsforge`, without the hyphen, because Go identifiers cannot
> contain one, so imports read `tlsforge.New(…)`. Error strings use the Go
> package name, as Go convention expects.

## Use

```go
client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
if err != nil {
    return err
}
defer client.Close()

res, err := client.Get("https://shop.example.com/product/12345")
fmt.Println(res.Status, len(res.Body))
```

That is the whole of it: the request goes out with Chrome's handshake, Chrome's
HTTP/2 preamble and Chrome's headers in Chrome's order, and the body comes back
decompressed. Chrome advertises gzip, deflate, br and zstd, and a client that
advertises them has to be able to read them.

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
Rotating any of them means a new client. That is deliberate: a jar shared between
two fingerprints describes a browser that changed its TLS stack mid-session,
which is not a thing that happens.

```go
client, err := tlsforge.New(
    tlsforge.WithProfile("chrome"),
    tlsforge.WithProxy("http://user:pass@proxy.example:8080"),
    tlsforge.WithTimeout(20*time.Second),
)
```

For scraping at any volume that is the shape to build on: a pool of clients, one
per proxy, each keeping its own jar for as long as that identity lasts. A client
is safe for concurrent use, so a pool of them is a pool of sessions rather than a
pool of connections.

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

Nothing touches your real browser profile. Every launch gets a throwaway
user-data directory, which also keeps the `--ignore-certificate-errors` flag this
needs from ever applying to a profile you browse with.

## How the verification works

There is no third-party service in the loop. `tls-forge serve` is a local HTTPS
server that records the raw ClientHello off the wire, decodes the HTTP/2
preamble and the request headers in order, and reports all of it back to
whoever connected, in the same JSON for a browser and for this library.

That matters for three reasons. The tests are hermetic. The check keeps working
when someone else's service is down or changes its output. And a mismatch can be
reported as a structural diff naming *this extension* or *that signature
algorithm*, rather than as two hashes that differ for reasons nobody can see:

```
signature_algorithms
    browser: mldsa44, mldsa65, mldsa87, ecdsa_secp256r1_sha256, …
    client:  ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, …
    missing: mldsa44, mldsa65, mldsa87
```

JA3, JA4, JA4_r and the HTTP/2 fingerprint are computed locally, from the
bytes. The implementation was checked against `tls.peet.ws` for the same browser
before any of it was written: same JA4, same HTTP/2 hash, same header order.

You can point anything else at it too:

```bash
tls-forge serve
curl -k https://localhost:PORT/api/all
```

## Things worth knowing

**JA3 is not usable for Chrome.** Chrome shuffles its extension order per
connection, and JA3 hashes that order. Measured here: one Chrome 151, four cold
connections to the local echo server, **four distinct JA3 hashes and one JA4**.
So two JA3s differing tells you nothing. This library shuffles too. A client that
always sent the same order would differ from Chrome in exactly the way Chrome
does not differ from itself, so `compare` does not compare JA3 at all.

**A resumed connection has a different JA4.** Resumption adds `pre_shared_key`,
one more extension, so the count and the extension hash both move. Real Chrome
151 sends `t13d1516h2_…_806a8c22fdea` cold and `t13d1517h2_…_a87ad97598a9`
resumed. Both are that browser. The echo server refuses to issue tickets by
default, so captures are always the cold handshake, the one a server sees on
first contact.

**Header order is half the problem.** Go's own `net/http` keeps headers in a map
and sorts the names alphabetically before writing them, in `sortedKeyValues`
(`net/http/header.go`). So a client with a perfect handshake whose headers arrive
in alphabetical order has announced itself one layer up. `tlsforge.Header` is an
ordered list for that reason, and `Set` replaces in place rather than moving the
header to the end.

**Post-quantum signatures.** Chrome 151 advertises ML-DSA (`mldsa44`, `mldsa65`,
`mldsa87`) ahead of the classical signature algorithms, and offers
`X25519MLKEM768` as its first supported group. Measured against the stock
`chrome_144` profile from the tls-client catalogue, those three signature entries
are the *only* structural difference from the real browser, and they are enough
to change the JA4.

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
indistinguishable from the next request's: one page filed under another page's
request, well-formed and wrong.

A Node client is in [node/](node/):

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome', proxy: 'http://user:pass@host:8080' });
const res = await client.get('https://shop.example.com/product/12345');
client.close();
```

## Scope

A network-layer tool. It changes what a request looks like on the wire, and that
is all it does: it runs no JavaScript, so managed challenges, Turnstile and
CAPTCHAs are outside it. Nor does it rotate proxies, schedule crawls or parse
HTML. It is the transport a scraper is built on, not the scraper.

The usual limits still apply: robots.txt, whatever terms you agreed to, and a
request rate that does not cost someone else their afternoon. That is the line
every HTTP client sits on. This one simply does not announce itself in the first
packet.

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
something goes wrong: a truncated ClientHello, a client that hangs up
mid-response, an answer arriving after the caller gave up. None of that is
reachable by using the library normally, and a branch no test can reach is
usually a branch that should not exist.

## Credits

The TLS transport is [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)
and [bogdanfinn/utls](https://github.com/bogdanfinn/utls), a fork of
[refraction-networking/utls](https://github.com/refraction-networking/utls). The
JA4 specification is [FoxIO's](https://github.com/FoxIO-LLC/ja4). What this
project adds is the measurement harness: capture from a real browser, synthesise
a profile from it, and verify the result locally.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The binary is statically linked, so every dependency travels inside it, and the
BSD- and MIT-style licences those carry all require their copyright notices to
accompany a binary. Those notices are in
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Regenerate it with `make
notices` whenever the dependency set changes, and keep it alongside any copy you
distribute.
