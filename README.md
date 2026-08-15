# tls-forge

**A scraping HTTP client that gets past TLS fingerprinting.** It sends the
handshake a real Chrome sends: the same JA4, the same HTTP/2 settings, the same
header order. The fingerprint check that runs before a page is ever served has
nothing to catch.

Use it when a scraper written with an ordinary HTTP library collects challenge
pages instead of pages. The TLS handshake is on the wire before a single byte of
HTTP, so it arrives before your `User-Agent` does, and reading it costs a
defender nothing. Cloudflare acts on it and documents doing so: Bot Management
exposes the JA3 and JA4 fingerprint of each request as fields you can write WAF
custom rules, Transform Rules and Workers against, for
[blocking or allowing traffic by fingerprint](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/).
Other vendors are widely said to do the same. This README does not name them,
because their documentation does not say so and this project has not measured
them.

It is a network-layer tool. It runs no JavaScript, so managed challenges and
CAPTCHAs are a different problem. What it removes is the check that fires before
the page is served.

Nothing here is transcribed from documentation. The profile it wears is a
recording of a real ClientHello, and [`compare`](#compare) re-measures the
browser on your machine to prove it still matches.

## Install

A Chromium-based browser (Chrome, Chromium, Edge, Brave) is needed only by
`capture` and `compare`. Everything else runs on its own.

### From source

Go 1.24 or newer, and nothing else. There is no cgo anywhere in the project, no
code generation step, and no build tags to remember.

```bash
git clone https://github.com/Sec-CH-Lemon/tls-forge
cd tls-forge
make build
./bin/tls-forge version
```

`make build` stamps the version from `git describe`, so the binary can say which
commit it came from. Without make:

```bash
go build -o tls-forge ./cmd/tls-forge
./tls-forge version
```

`./cmd/tls-forge` is the source directory handed to the compiler, not something
to run: try it and the shell says `permission denied`, because it is a
directory. What you run is whatever `-o` named, here `./tls-forge`, and
`./bin/tls-forge` when make did the building.

The repository root is the library rather than the command, and building that is
worse than an error: `go build -o tls-forge .` exits 0 and writes a file, but the
file is a compiled package archive instead of a program, and running it gets you
`is not a main package`.

A binary built this way reports its version as `dev`, because the version is set
by the linker rather than read from git.

To put it on your `PATH`:

```bash
go install ./cmd/tls-forge
```

That lands in `$(go env GOPATH)/bin`. From anywhere, without a clone:

```bash
go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest
```

#### The way releases are built

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v0.1.0" \
  -o tls-forge ./cmd/tls-forge

./tls-forge version    # tls-forge v0.1.0
```

| | |
|---|---|
| `CGO_ENABLED=0` | a static binary, which runs on Alpine and in `scratch` |
| `-trimpath` | keeps your local paths out of the binary and makes the build reproducible |
| `-s -w` | drops the symbol table and DWARF |
| `-X main.version=` | what `tls-forge version` prints |

The last two matter more than they look: the same source builds to 15 MB plain
and 11 MB this way.

#### For another platform

Go cross-compiles on its own, so there is nothing to install:

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o tls-forge-linux-arm64 ./cmd/tls-forge
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o tls-forge.exe         ./cmd/tls-forge
```

This works because the project uses no cgo. A project that did would need a
C cross-compiler for every target.

### Homebrew

On macOS and Linux:

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

### Docker

Every release publishes an image for linux/amd64 and linux/arm64:

```bash
docker pull ghcr.io/sec-ch-lemon/tls-forge
docker run --rm ghcr.io/sec-ch-lemon/tls-forge fetch https://example.com
```

Or build it yourself, from the same Dockerfile the release uses:

```bash
docker build -t tls-forge .
docker run --rm tls-forge fetch https://example.com
```

The image is Alpine plus one static binary, about 30 MB, running as a non-root
user. The examples below say `tls-forge` for brevity; substitute the full image
name if you pulled it.

Anything that reads or writes files needs the directory mounted, and the paths
you pass have to be the ones inside the container:

```bash
docker run --rm -v "$PWD:/work" tls-forge fetch -o /work/page.html https://example.com
```

The daemon speaks over stdin and stdout, so it needs the input kept open:

```bash
echo '{"id":1,"url":"https://example.com"}' | docker run --rm -i tls-forge daemon
```

`serve` binds `127.0.0.1` by default, which inside a container means nothing
outside can reach it. Tell it to listen on all interfaces and publish the port:

```bash
docker run --rm -p 8443:8443 tls-forge serve --addr 0.0.0.0:8443
```

On Linux a mounted directory belongs to your user, not to the one inside the
image, so add `--user "$(id -u):$(id -g)"` when the container has to write into
it.

Two commands are missing from the image on purpose. `capture` and `compare`
drive a real browser, and there is no browser in a 30 MB image. Run those on a
machine that has one, commit the profile they produce, and the container will
use it like any other.

## Commands

| | |
|---|---|
| [`fetch`](#fetch) | make one request wearing the fingerprint |
| [`batch`](#batch) | fetch a list of URLs, each through its own proxy |
| [`capture`](#capture) | measure the browser on this machine and save a profile |
| [`compare`](#compare) | diff this library against that browser |
| [`profiles`](#profiles) | list what can be impersonated |
| [`serve`](#serve) | run the local echo server and point anything at it |
| [`daemon`](#daemon) | JSON lines on stdin and stdout, for other languages |
| [`version`](#version) | print the version |

`tls-forge <command> --help` prints the same flags listed below.

**One dash introduces a short flag, two a long one**, as in `-b` and
`--browser`. They are the same flag, so use whichever reads better: short ones
for typing, long ones in scripts, where a reader should not have to remember
what `-k` was. Short flags bundle (`-ik` is `-i -k`) and a long one takes
`--profile=chrome` as well as `--profile chrome`. A few flags that are set once
in a script and never typed twice are long-only, and are shown that way below.

Four flags are shared by every command that makes requests: `--profile`,
`--proxy`, `--timeout` and `--insecure`.

### fetch

One request, with the browser's handshake, HTTP/2 preamble and headers. The body
comes back decompressed.

```bash
tls-forge fetch https://example.com
tls-forge fetch -i https://example.com                       # status and headers first
tls-forge fetch -o page.html https://example.com             # to a file
tls-forge fetch -H "Referer: https://example.com/" https://example.com/page
tls-forge fetch -X POST -d '{"a":1}' \
  -H "content-type: application/json" https://api.example.com/v1
tls-forge fetch -x http://user:pass@proxy.example:8080 https://example.com
tls-forge fetch --profile chrome_151 --timeout 45s https://example.com
```

The short letters are curl's, because this is the command you reach for instead
of curl.

| flag | |
|---|---|
| `-H`, `--header` | extra header, repeatable. The profile wins any name it already defines |
| `-X`, `--method` | HTTP method, `GET` by default |
| `-d`, `--data` | request body |
| `-i`, `--include` | print the status and response headers before the body |
| `-o`, `--output` | write the body to a file instead of stdout |
| `-p`, `--profile` | which profile to wear, `chrome` by default |
| `-x`, `--proxy` | upstream proxy, `http://`, `https://` or `socks5://`, credentials allowed |
| `-t`, `--timeout` | per-request deadline, 30s by default |
| `-k`, `--insecure` | skip certificate verification. For talking to `serve`, not for the internet |

### batch

A list of URLs instead of one, fetched concurrently, **each through its own
proxy**. One line of JSON per URL, so the output can be read as it is produced
and piped into `jq` while the run is still going.

```bash
tls-forge batch -u "https://a.example/,https://b.example/"   # a comma-separated list
tls-forge batch -i urls.json                                 # a file, format from the extension
tls-forge batch -i urls.csv -c 8                             # eight at a time
tls-forge batch -i urls.txt -o results.jsonl -d bodies/      # results and pages to disk
cat urls.txt | tls-forge batch                               # or standard input
```

| flag | |
|---|---|
| `-u`, `--urls` | the list as a comma-separated string, instead of a file |
| `-i`, `--input` | the list as a file. Standard input if neither is given |
| `-F`, `--format` | `auto`, `lines`, `json` or `csv`. `auto` reads the file's extension |
| `-c`, `--concurrency` | how many pages to fetch at once, 4 by default |
| `-o`, `--output` | write the JSON lines here instead of to the terminal |
| `-d`, `--body-dir` | write bodies to this directory and reference them instead of inlining them |
| `--retry` | attempts per URL before giving up, 1 by default |
| `--progress` | `auto`, `always` or `never`. `auto` draws only to a terminal |
| `-R`, `--report` | write an HTML report here. A directory gets `report-<date-time>.html` |
| `--report-ip` | with `--report`, look up each proxy's exit address. On by default |
| `-p`, `--profile` | which profile to wear |
| `-x`, `--proxy` | the proxy for entries that name none of their own |
| `-t`, `--timeout` | per-request deadline |
| `-k`, `--insecure` | skip certificate verification |

**Exits 1 if any URL failed**, so a shell loop can tell a batch that half
worked from one that worked.

#### The three formats

`--format auto` picks by extension: `.json` is JSON, `.csv` is CSV, anything
else is one URL per line. Only the extension is read, never the contents;
guessing from the bytes would be right nearly always and then wrong on someone
real. Name the format yourself when the file is called something else, and for
standard input, which has no name at all.

**JSON** is an array, of objects or of bare strings, or a mixture. A misspelled
key is an error rather than an entry with no URL.

```json
[
  {"url": "https://a.example/page", "proxy": "http://user:pass@eu-1.proxy:8080"},
  {"url": "https://b.example/page", "proxy": "socks5://us-3.proxy:1080"},
  "https://c.example/page"
]
```

**CSV** takes its columns by name when the first row holds a cell reading
`url`, in whatever order they appear, and positionally otherwise. Rows may be
ragged: a list where only some URLs carry a proxy is the normal case.

```csv
url,proxy
https://a.example/page,http://user:pass@eu-1.proxy:8080
https://b.example/page,socks5://us-3.proxy:1080
https://c.example/page,
```

**Lines** is one URL per line, optionally followed by a proxy after a space, so
the plainest format is not the one that cannot express a per-URL proxy. Blank
lines are skipped and `#` starts a comment, so a line can be commented out
rather than deleted.

```
# the ones behind a challenge
https://a.example/page http://user:pass@eu-1.proxy:8080
https://b.example/page socks5://us-3.proxy:1080
https://c.example/page
```

`--urls` is the same list on the command line, comma separated. A URL may
legally contain a comma, in a query string; one that does belongs in a file.

#### Fetching in parallel

`--concurrency` is how many pages are in flight at once. Four by default, which
is polite; raise it for a large list.

```bash
tls-forge batch -i urls.csv -c 16
```

Above the machine's core count the command says so and carries on:

```
WARN: --concurrency 64 is more than the 14 CPU cores on this machine.
      Fetching waits on the network rather than on a core, so this may be what you want.
```

A warning and not a limit, because for this work more workers than cores is
often right: a fetch spends its time waiting on the network, not on a core.
What the number usually means past that point is one typed without thinking,
and the extra workers only queue behind the same connections and the same exit
IP. It goes to standard error, so the JSON lines on standard output stay
readable by whatever is consuming them.

In a container the number counted is the one the container is allowed, read
from the cgroup, rather than the host's:

```
$ docker run --rm --cpus=2 tls-forge batch -c 8 -i /work/urls.csv
WARN: --concurrency 8 is more than the 2 CPUs this process is allowed.
```

`runtime.NumCPU` reports the hardware and knows nothing about cgroups, so on a
64-core host it answers 64 however little of it the container may use, which is
the case where the warning is worth the most. Both cgroup layouts are read, v2
first and then v1; where neither exists, including on every machine that is not
Linux, the hardware count stands. Nothing here changes `GOMAXPROCS`: the number
decides whether to print a sentence.

#### Watching it run

A list of any size takes a while, so there is a status line, redrawn in place:

```
  87/500  8 running  41.2 MB  1m03s elapsed  ~5m58s left  3 failed
```

In order: how many of the list are done, how many are in flight right now, how
much body has come back, how long the run has been going, roughly how much
longer, and how many failed. The estimate appears once there is something to
estimate from and disappears when there is nothing left to estimate.

The volume is the **decompressed** body, because that is what was measured: the
client hands back a decoded page and fewer bytes than that crossed the wire.

It is drawn on **standard error**, never on standard output, which is carrying
one JSON object per URL. Both can still be the same terminal, so the line
erases itself before each result is written and draws again underneath, and
neither stream ends up on top of the other. `--progress auto` draws only when
standard error is a terminal: redirected to a file, a line rewritten five times
a second is thousands of escape sequences nobody asked for. `always` and
`never` say so outright.

When the run ends the final counts stay on screen as a line of their own, which
is the answer to how long it took.

#### What the run came to

Every run ends with a table on standard error:

```
  Ran          500 URLs in 6m12s
  Scraped      471  (94.2%)
  Not 2xx      16  (3.2%)
  No response  13  (2.6%)
  Data         41.2 MB
  Retries      21
  Proxies      8 used, 6 alive, some direct
  Written to   results.jsonl
  dead proxy   http://eu-3.proxy:8080  (61 requests, none came back)
```

Three outcomes rather than two, because a 503 is neither a page nor a dead
connection: something came back and it was not what was asked for. Counting it
as a success answers "did the transport work" when the question was "did I get
the page". The exit code still turns on the last of the three: a batch that
expects some 404s should not fail on them.

A proxy counts as alive when at least one page came back through it. Dead ones
are listed by name and by how many requests went into them, because "6 of 8
alive" does not say which two to replace, and a proxy that carried nothing is
usually the reason a batch of URLs is missing.

#### The detailed report

`--report` writes one self-contained HTML file: the summary as cards, a row per
proxy, and a row per URL with when it started, when it ended, how long it took,
what came back, how much of it, how many attempts it needed, which proxy
carried it, and the address that proxy came out of with its country flag.

```bash
tls-forge batch -i urls.csv -R run.html      # named
tls-forge batch -i urls.csv -R reports/      # report-2026-08-16-01:09:45:123.html
```

Given a directory, the report names itself after the run. The stamp is ordered
largest unit first, so a directory of them sorts into the order they were made,
which the named month used inside the report would not.

On Windows the colons become dashes, `report-2026-08-16-01-09-45-123.html`.
That is not a preference: Windows forbids a colon in a file name, where it
means an alternate data stream, and the file simply would not be created.

No stylesheet, script or font from anywhere else, so it opens on a laptop with
no network and travels as one attachment. The styling is Tailwind, generated
from the template and compiled into the binary rather than fetched: `go build`
still needs nothing but Go, and only editing the template needs anything more
(see [Development](#development)).

Each URL ends in one of the same three states as the summary, and each is shown
with a glyph and a word as well as a colour, so the state never rests on hue
alone. Light and dark are both selected, following the reader's system setting.

The exit address is asked of a third party, because a process cannot see its
own public address and through a proxy the address is the proxy's.
`https://ipinfo.io/json` is asked **once per proxy**, not once per URL, and the
command says so on standard error before it does. `--report-ip=false` turns the
lookup off and the report says the address was not looked up. The country flag
is computed from the two-letter country code rather than looked up: a flag
emoji is those two letters as regional indicator symbols, so no geolocation
database is involved.

Volumes throughout are the decompressed body. Fewer bytes than that crossed the
wire, and calling it traffic would overstate it.

#### One client per proxy

The proxy is the identity, so `batch` opens one client per distinct proxy and
shares it between workers, rather than one per worker. Two pages fetched
through one exit IP sharing a cookie jar is what a browser does. Two pages
sharing a jar across two exit IPs is what none does.

Clients are built on first use, so a list naming twenty proxies of which the
run reaches three opens three. `--proxy` is the default for entries that name
none, so the flag and the column compose instead of one overriding the other.

The whole list is checked before a single request goes out: an entry with no
URL, or one that is not `http` or `https`, is reported with every other problem
in the file at once, so a typo on two lines of a hundred costs one run.

### capture

Opens the browser installed on this machine, measures what it puts on the wire,
and writes a profile from it. This is where profiles come from.

```bash
tls-forge capture                                    # just show me
tls-forge capture -s my-chrome.json                  # and keep it
tls-forge capture -b edge --headless -s edge.json
tls-forge capture -s brave.json -n my_brave          # name it yourself
tls-forge capture -j > raw.json                      # everything measured
```

| flag | |
|---|---|
| `-b`, `--browser` | `chrome`, `chromium`, `edge`, `brave`, or a path. Searches if omitted |
| `--headless` | no window. Measured to send the identical handshake, but headed is the default because a headed browser is the thing being impersonated |
| `-s`, `--save` | write a reusable profile here |
| `-n`, `--name` | name it yourself instead of deriving one from the browser version |
| `-j`, `--json` | print the raw capture rather than a summary |
| `-t`, `--timeout` | how long to wait for the browser, 2m by default |

A browser window opens, shows what it sent, and can be closed. Nothing touches
your real browser profile: every launch gets a throwaway user-data directory,
which also keeps the `--ignore-certificate-errors` flag this needs from ever
applying to a profile you browse with.

### compare

Opens the browser on your machine, measures it, measures this library against
the same local instrument, and prints the two side by side as a diff. Green where they
agree, red where they do not. **Exits 1 when they differ**, so it can gate a
release: a browser update is exactly when an impersonation stops being true, and
it does so without a commit.

```diff
$ tls-forge compare
measuring the browser…
--- browser  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
+++ client   profile chrome_151

TLS
  ja4                    t13d1516h2_8daaf6152771_806a8c22fdea
  cipher_suites          TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_S…
  extensions             alpn, application_settings_old, compress_certificate, ec_point_formats,…
  supported_versions     TLS 1.3, TLS 1.2
  supported_groups       X25519MLKEM768, X25519, P-256, P-384
  signature_algorithms   mldsa44, mldsa65, mldsa87, ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256,…
  key_share_groups       X25519MLKEM768, X25519
  alpn                   h2, http/1.1
  application_settings   h2
  ec_point_formats       0
  psk_key_exchange_modes 1
  compress_certificate   2

HTTP/2
  http2_akamai           1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  http2_settings         HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456, MA…
  http2_window_update    15663105
  pseudo_header_order    m, a, s, p
  header_order           sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-reque…

every field matches; the client is indistinguishable from the browser.
```

```bash
tls-forge compare --headless -p chrome_151           # in CI
tls-forge compare -f                                 # do not trim the matching values
tls-forge compare -c never                           # no colour, whatever the terminal
tls-forge compare -j > report.json                   # both captures and the diff
```

| flag | |
|---|---|
| `-p`, `--profile` | which profile to check, `chrome` by default |
| `-b`, `--browser` | which browser to compare against |
| `--headless` | no window |
| `-c`, `--color` | `auto`, `always` or `never`. `auto` colourises only a terminal, and honours `NO_COLOR` |
| `-f`, `--full` | print the matching values in full. The differing ones always are |
| `-j`, `--json` | print both captures and the diff |
| `-t`, `--timeout` | how long to wait for the browser, 2m by default |

Values that match are trimmed to the terminal width, because you are not reading
them. Values that differ are printed whole, because the difference can sit
anywhere in the line, including past a cut.

### profiles

Lists what can be impersonated: the profiles measured from a real browser and
shipped here, then the tls-client catalogue, which carries a handshake but no
headers of its own.

```bash
tls-forge profiles
```

Takes no flags.

### serve

The measuring instrument, on its own. A local HTTPS server that reports back
what its caller sent: the ClientHello, the HTTP/2 preamble, the header order.
Point a browser, curl, or your own code at it.

```bash
tls-forge serve
tls-forge serve --addr 0.0.0.0:8443                  # reachable from elsewhere
tls-forge serve --session-tickets                    # allow resumption
curl -k https://localhost:PORT/api/all
```

| flag | |
|---|---|
| `-a`, `--addr` | listen address, an ephemeral loopback port by default |
| `--host` | hostname used in the URL and the certificate. Keeps SNI populated, which JA4 records |
| `--session-tickets` | allow resumption. Off by default, because a resumed connection carries `pre_shared_key` and therefore a different JA4 |

Its two endpoints are `/`, a page that measures the browser that opens it, and
`/api/all`, this connection's fingerprint as JSON. The certificate is generated
per run, so clients have to be told to accept it.

### daemon

One JSON object per line in, one per line out, so a program in any language can
borrow the fingerprint without reimplementing one. The process is long lived and
holds one client, which means one fingerprint, one cookie jar and one exit IP for
its whole life.

```bash
echo '{"id":1,"url":"https://example.com"}' | tls-forge daemon
tls-forge daemon -p chrome_151 -x http://user:pass@host:8080
```

| flag | |
|---|---|
| `-p`, `--profile` | which profile to wear |
| `-x`, `--proxy` | upstream proxy |
| `-t`, `--timeout` | per-request deadline. Give it more than the caller's, or a timeout races |
| `-k`, `--insecure` | skip certificate verification |

The protocol is described under [Node.js](#nodejs).

### version

```bash
tls-forge version
```

Prints the version the binary was stamped with at build time. A binary built
without `-ldflags` reports `dev`.

## Add it to your project

> The command, the repository and the npm package are `tls-forge`. The Go
> package is `tlsforge`, without the hyphen, because Go identifiers cannot
> contain one, so imports read `tlsforge.New(…)`. Error strings use the Go
> package name, as Go convention expects.

### Go

```bash
go get github.com/Sec-CH-Lemon/tls-forge
```

```go
import tlsforge "github.com/Sec-CH-Lemon/tls-forge"

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

To wear a profile you measured yourself:

```go
data, _ := os.ReadFile("my-chrome.json")
p, _ := profile.Load(data)
client, _ := tlsforge.New(tlsforge.WithProfileValue(p))
```

### Node.js

```bash
npm install tls-forge
```

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome', proxy: 'http://user:pass@host:8080' });
const res = await client.get('https://shop.example.com/product/12345');
console.log(res.status, res.body.length);
client.close();
```

No Go, no build step, no download during install. The binary arrives as an
optional dependency, one package per platform, each declaring `os` and `cpu`, so
npm installs the one that matches and skips the others. That is the arrangement
esbuild uses, and it survives `npm ci --ignore-scripts`, which a postinstall step
does not. Full documentation is in [node/](node/).

Under it is the `daemon` command, one JSON object per line on stdin and stdout,
so any other language can borrow the fingerprint the same way:

```
in : {"id":7,"url":"https://…","headers":{"a":"b"},"order":["a"]}
out: {"id":7,"status":200,"url":"…","body":"…","headers":{…}}
```

The `id` is echoed on every response, including every error, and a caller should
drop any line whose id it is not waiting for. That looks redundant for a protocol
that handles one request at a time, but it is not: a caller that gives up on a
slow request typically kills the process, and the abandoned process can already
have a complete answer on its way up the pipe. Without an id, that answer is
indistinguishable from the next request's: one page filed under another page's
request, well-formed and wrong.

## How the verification works

There is no third-party service in the loop. `tls-forge serve` is a local HTTPS
server that records the raw ClientHello off the wire, decodes the HTTP/2 preamble and the
request headers in order, and reports all of it back to whoever connected, in
the same JSON for a browser and for this library.

That matters for three reasons. The tests are hermetic. The check keeps working
when someone else's service is down or changes its output. And a mismatch can be
reported as a structural diff naming *this extension* or *that signature
algorithm*, rather than as two hashes that differ for reasons nobody can see.

JA3, JA4, JA4_r and the HTTP/2 fingerprint are computed locally, from the bytes.
The implementation was checked against `tls.peet.ws` for the same browser before
any of it was written: same JA4, same HTTP/2 hash, same header order.

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
make report-css  # regenerate the HTML report's stylesheet
```

`make report-css` is the one target that needs more than Go: it runs Tailwind
over `cmd/tls-forge/report.html` and writes `cmd/tls-forge/report.css`, which is
committed and compiled into the binary. Run it after editing the report
template. Forgetting to is caught by a test rather than by a reader noticing an
unstyled page.

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
JA4 specification is [FoxIO's](https://github.com/FoxIO-LLC/ja4). Command-line
flags are parsed by [spf13/pflag](https://github.com/spf13/pflag). What this
project adds is the measurement harness: capture from a real browser, synthesise
a profile from it, and verify the result.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The binary is statically linked, so every dependency travels inside it, and the
BSD- and MIT-style licences those carry all require their copyright notices to
accompany a binary. Those notices are in
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Regenerate it with `make
notices` whenever the dependency set changes, and keep it alongside any copy you
distribute.
