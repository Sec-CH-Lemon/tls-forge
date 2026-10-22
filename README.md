# TLS Forge

`tls-forge` is an HTTP client and command-line tool for making requests with a
real browser's network fingerprint. A measured profile controls the TLS
ClientHello, JA3/JA4-relevant fields, HTTP/1.1 header casing and order, HTTP/2
settings, pseudo-header order, regular header order and browser headers as one
coherent identity. Profiles created before HTTP/1.1 capture was introduced
remain compatible and use the documented canonical-casing fallback.

Use it when an ordinary Go, Node.js or Python HTTP client is rejected because
its network stack does not match the browser named by its `User-Agent`.
`tls-forge` can be used as:

- a standalone CLI for one request or a list of them;
- an intercepting proxy for an existing program;
- a Go library;
- a Node.js or Python SDK backed by the same Go transport;
- a local measurement tool for capturing and comparing browser fingerprints.

It does not execute page JavaScript and does not solve managed challenges or
CAPTCHAs. It addresses the TLS and HTTP fingerprint checks that happen before,
or alongside, normal HTTP handling.

## Quick start

Install it, here with Homebrew ([Install](#install) has the other ways), and
make one request:

```bash
brew tap Sec-CH-Lemon/tap
brew trust --formula Sec-CH-Lemon/tap/tls-forge
brew install tls-forge

tls-forge fetch --print-body https://tls.browserleaks.com/json
```

What comes back is that site's account of the request, as JSON: the JA3 and
JA4 of the handshake, the HTTP/2 fingerprint and the headers, as the newest
Chrome shipped sends them on this platform. Standard error says which profile
the request wore and where it came out. Without `--print-body` a terminal gets
only the line saying how the request went, while a pipe or a file gets the
page:

```bash
tls-forge fetch https://example.com/ > page.html
```

[A list of URLs](#a-list-of-urls), [a proxy](#through-a-proxy), [cookies across
runs](#cookies-across-runs), [keeping every request](#keeping-every-request)
and the [Go, Node.js and Python libraries](#language-libraries) come after.

## Install

A Chromium-based browser is required only for `capture` and `compare`. Fetching,
proxying and the language SDKs do not require a browser.

### Release binary

Prebuilt binaries are published for macOS and Linux on arm64 and x86-64, and
Windows on x86-64. Download the archive for your platform from
[GitHub Releases](https://github.com/Sec-CH-Lemon/tls-forge/releases), extract
it and place `tls-forge` (or `tls-forge.exe`) on `PATH`.

On Unix-like systems, a user-local installation can look like this:

```bash
mkdir -p ~/.local/bin
install -m 0755 tls-forge ~/.local/bin/tls-forge
tls-forge version
```

Each release after 0.2.2 carries `SHA256SUMS`, and GitHub keeps signed
provenance for every file of it. Check an archive before extracting it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

```bash
gh attestation verify tls-forge_X.Y.Z_linux_amd64.tar.gz --repo Sec-CH-Lemon/tls-forge
```

### Homebrew

On macOS or Linux:

```bash
brew tap Sec-CH-Lemon/tap
brew trust --formula Sec-CH-Lemon/tap/tls-forge
brew install tls-forge
```

Homebrew requires explicit trust for third-party taps. Review the tap before
granting it.

### Go install

With Go 1.26.9 or newer:

```bash
go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest
```

The binary is written to `$(go env GOPATH)/bin` unless `GOBIN` is set.

### Docker

Release images are published for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/sec-ch-lemon/tls-forge
docker run --rm ghcr.io/sec-ch-lemon/tls-forge \
  fetch --print-body https://tls.browserleaks.com/json
```

Mount a directory when a command reads or writes files:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sec-ch-lemon/tls-forge \
  fetch --input /work/urls.csv --output /work/out > results.jsonl
```

The image runs as the user `tlsforge`, not as root, in `/work`, which that
user can write to. A directory mounted there has to be writable by that user
for a command to write into it; `--user "$(id -u):$(id -g)"` runs the command
as you instead.

`capture` and `compare` are intentionally not supported by the small release
image because it does not contain a browser.

### Build from source

Requirements:

- Go 1.26.9 or newer;
- Git and Make for the standard build command;
- no C compiler or cgo.

```bash
git clone https://github.com/Sec-CH-Lemon/tls-forge.git
cd tls-forge
make build
./bin/tls-forge version
```

`make build` writes `bin/tls-forge` and stamps its version from `git describe`.
Without Make:

```bash
go build -o tls-forge ./cmd/tls-forge
./tls-forge version
```

A plain `go build` reports version `dev`, because release versions are supplied
through linker flags. A release-style static build is:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v0.1.0" \
  -o tls-forge ./cmd/tls-forge
```

Go can cross-compile the project without an external toolchain:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o tls-forge-linux-arm64 ./cmd/tls-forge

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -o tls-forge.exe ./cmd/tls-forge
```

To build the container image:

```bash
docker build -t tls-forge .
docker run --rm tls-forge version
```

`make docker-check` builds it and checks what the build was given and what the
image does: no local binary, environment, dependency, run output or profile
measured on this machine in the build, and an image that runs as `tlsforge`,
writes where it works and stops in order when stopped. Its two bases are pinned
by digest, and Dependabot proposes the next ones.

Run all project checks before distributing a build:

```bash
make check
```

## What is a TLS fingerprint?

Before an HTTPS client can send `GET`, headers or a `User-Agent`, it sends a TLS
ClientHello. That message exposes choices made by its networking stack,
including:

- supported TLS versions and cipher suites;
- extensions and their order;
- supported groups, key shares and signature algorithms;
- GREASE values and ALPN protocols;
- session-resumption and application-settings behaviour.

Servers can retain the complete structure or reduce it to identifiers such as
JA3 and JA4. The negotiated HTTP protocol adds more signals: exact HTTP/1.1
header casing and order, or HTTP/2 SETTINGS, window updates, pseudo-header
order, normal header order and values.

Changing only `User-Agent` is therefore insufficient. Node.js and Python
normally use OpenSSL, Go uses `crypto/tls`, while Chrome uses BoringSSL. Their
handshakes differ before the server sees any HTTP header.

Cloudflare uses these signals in its bot-detection products. Cloudflare Bot
Management exposes JA3 and JA4 fingerprints as request fields that can be used
in WAF custom rules, Transform Rules and Workers; see Cloudflare's official
[JA3/JA4 fingerprint documentation](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/).

The profiles in this project are measurements, not hand-written guesses.
`tls-forge compare` measures a real browser and this client against the same
local echo server and reports every difference it finds.

### Verify the fingerprint

If a Chromium-based browser is installed, start with:

```bash
tls-forge compare
```

The command measures the browser and the selected profile locally, then compares
TLS, JA4, HTTP/2 settings, header order and header values. A matching result is
stronger than checking only a JA3 or JA4 hash.

## Recipes

Each of these is one thing to do with `fetch`, the flags it takes and what
comes of them. [Reference](#reference) has every flag of every command.

### A list of URLs

```bash
tls-forge fetch https://example.com/ https://example.org/
tls-forge fetch --input example/urls.csv --concurrency 8
tls-forge fetch --input urls.json --report=reports/ > results.jsonl
cat urls.txt | tls-forge fetch --output pages/ > results.jsonl
```

A list comes from one of `--urls`, `--input` and the URLs on the command line,
or from standard input when it is piped and none of them is given; two of them
are a usage error, rather than one quietly preferred. The whole list is checked
before anything is fetched, and every entry whose URL is not an HTTP or HTTPS
URL with a host, or whose proxy is not an `http`, `https`, `socks4`,
`socks4a`, `socks5` or `socks5h` URL, is reported at once, as a usage error.
Each URL is read as Chrome reads one, and goes out, and is written in every
line, log, trace and report, as Chrome writes it:
`HTTP://Example.COM:80/a/./b/../c d#top` is `http://example.com/a/c%20d`, a
name in another script goes out in Punycode, `http://0x7f.1/` is
`http://127.0.0.1/`, and a fragment is never sent. A URL Chrome sends nothing
for is a usage error too: one it cannot parse, and one on a port it keeps away
from, such as 22 or 6000. So is a path with a percent sign that escapes
nothing, such as `/50%off`, which Chrome sends as it is and tls-forge cannot
yet. A list may begin with a UTF-8 byte order mark, which is taken off;
a line of one, its newline included, is at most 1 MiB. With `--format auto`,
`.json` selects JSON, `.csv` selects CSV and every other name uses one URL per
line:

```text
# lines: URL followed by an optional proxy
https://example.com/ http://user:pass@proxy.example:8080
```

```json
[
  "https://example.com/",
  {"url": "https://example.org/", "proxy": "socks5://proxy.example:1080"}
]
```

```csv
url,proxy
https://example.com/,http://user:pass@proxy.example:8080
https://example.org/,
```

An entry can name its own proxy, and `--proxy` is the proxy of every entry
that names none. There is one client, and one cookie jar, for each distinct
proxy: a proxy is an identity, and two exits do not share a session. The
method, the header fields and the body given with `-X`, `-H` and `-d` are the
request, and every URL in the list is asked for with them.

Four requests run at once unless `--concurrency` says otherwise. Each line of
the output is one request:

```json
{"url":"https://example.com/","status":200,"final_url":"https://example.com/","bytes":559,"body":"<!doctype html>…","started":"2026-08-16T09:18:54.499687+02:00","ended":"2026-08-16T09:18:54.556431+02:00","ms":56,"attempts":1}
```

A request that got no response has `error` in place of `status`, and one that
went through a proxy names it, without its password, as `proxy`. When a body
is not valid UTF-8, `body` is base64 and the line contains
`"body_encoding":"base64"`; `bytes` always remains the original byte count.
With `--output`, the page is in a file instead, and the line names it as
`file`, with the request's log and trace as `log` and `trace`. `-i` adds the
response headers to every line as `headers`.

`fetch` exits 1 when one or more requests got no response. An answer that is
not a 2xx is an answer: it is counted and written with its status, and does not
change the exit code. It exits 2 for what it is given that it cannot run with,
before it empties, opens or makes anything, asks where it comes out or makes a
request: a flag or a value of one it does not take, such as `--progress
sometimes`, an unknown profile, a `--proxy` that is no proxy's URL, a
`--timeout` of nothing, two sources of the list, and a list that does not read
as one or holds an entry that is not a URL or one Chrome sends nothing for.

### Through a proxy

`--proxy` takes an HTTP, HTTPS or SOCKS proxy, with its credentials when it
has any. On the command line a password is one that `ps` shows to every user
of the machine, so `--proxy-env` reads the proxy from a variable it names
instead:

```bash
read -rs TLSFORGE_PROXY    # paste http://user:pass@proxy.example:8080
export TLSFORGE_PROXY
tls-forge fetch --proxy-env TLSFORGE_PROXY https://tls.browserleaks.com/json
```

The variable is read because the flag names it, and for no other reason:
tls-forge reads no `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`, which are how
another program is pointed at [`tls-forge proxy`](#proxy). In a list, each
entry may name a proxy of its own ([A list of URLs](#a-list-of-urls)), and
[Where a request came out](#where-a-request-came-out) says how the address
each request came out of is found.

### Cookies across runs

A run can begin with the cookies another left, and leave its own for the
next:

```bash
tls-forge fetch --save-cookies session.json https://example.com/
tls-forge fetch --cookies session.json --save-cookies session.json https://example.com/account
```

`--cookies` reads a file tls-forge saved, a browser's export or a Netscape
`cookies.txt`, and `-b name=value` adds one cookie by hand. Those are filed
as they are; a server's cookies are kept as Chrome keeps them, a prefix's
rules, `SameSite=None` only with `Secure`, `Secure` only from https or the
machine itself, and at most 4096 bytes ([GO.md](GO.md#cookies-and-sessions)).

Cookie files are treated as credentials and saved with mode `0600`. JSON files
can retain multiple named sessions; Netscape `.txt` files contain one jar and
are compatible with tools such as curl and wget. `--save-cookies` writes down
every cookie the session holds, a redirect's host's as well as those of the
URLs asked for, each as the server set it: its host's alone or its domain's, a
session cookie without an expiry, and its `SameSite`, so a session read back
with `--cookies` goes to the hosts it went to before and to no others. A
cookie lives at most 400 days, as in Chrome. A JSON file written by a
tls-forge older than this did not keep which cookies were their host's alone;
read, each of its cookies goes to its domain's subdomains as well, as it did
then, and the line that says where the session was warmed from says so too.
A Netscape file holds one session, and a run through more than one proxy has
one for each, so `--save-cookies` refuses a `.txt` for such a run before
anything is fetched, and a `.json` keeps each session as a set of its own.

### A site behind HTTP authentication

Credentials in a URL are sent as Chrome sends them: only once the server
answers 401 with a Basic or a Digest challenge, Digest when it offers both,
and then kept for the run, sent unasked to the directory they were answered in
and those under it:

```bash
tls-forge fetch 'https://user:pass@intranet.example/reports/'
```

Digest is answered with MD5 or SHA-256, as the page asks, and answered again
when the page says its nonce is out of date. A page that offers NTLM, or
Negotiate to a profile of Windows, is left with its 401, as is one whose
request has an `Authorization` given with `-H`
([docs/support.md](docs/support.md)).

### Retrying and repeating

```bash
tls-forge fetch --retry 3 https://example.com/
tls-forge fetch --repeat 3 -o out/ https://example.com/
tls-forge fetch --retry 3 --repeat 2 --input urls.csv
```

`--retry` asks again when the answer is not a 2xx, or when no answer comes at
all; with `--wait-for-element` or `--wait-for`, when the answer is without the
element or the text, whatever its status, and not when it has them. The waits
between tries are 250 ms, 500 ms, 1 s and then 2 s. Every try
goes out on a connection of its own, so through a proxy that rotates, a try
turned away from one exit is made again from another; `--reuse-connection`
makes it again on the same connection. When the
tries run out, the last answer is the one that is counted, printed or saved,
whatever its status, and the exit code still depends only on whether a response
arrived, and on whether it had what `--wait-for-element` and `--wait-for` name.
Nothing is asked for again unless `--retry` says so, for a list as
for one URL, and a JSON line's `attempts` counts the tries.

`--repeat` makes the same request several times in one session, so a later run
sends the cookies the runs before it were given. Every run opens a connection
of its own, so through a proxy that hands every connection an address every
run comes out of another; with `--reuse-connection` the runs of a URL go out
on the connection the first one opened, as a reloaded page does, and every
other URL keeps one of its own. One URL is
asked for one run at a time, the way a page is reloaded, unless
`--concurrency` says how many at once. With `-o out/`, each run is kept under
its own number. Without `-o`, the bodies follow one another on standard output.
A list is gone through from top to bottom once per pass, and every line carries
the pass it belongs to as `run`. The count covers all of the runs, and `-v`
adds a line for each as it finishes, and for each try that is made again:

```text
  1/3  200      577 B     29ms       out/example.com-2026-08-16-091854-584-1-response.html
  2/3  200      577 B     11ms       out/example.com-2026-08-16-091854-614-2-response.html
  3/3  200      577 B     10ms       out/example.com-2026-08-16-091854-626-3-response.html
  ████████████████████████████████████████  3/3  100%
  0s elapsed · 1.7 kB

  ✓ 200 OK   3  100%

  Requests      3
  Retries       0
  Success rate  100.0%
  Avg time      16ms
  Saved to      out/
```

`fetch` exits non-zero if any run got no response, or, with
`--wait-for-element` or `--wait-for`, came back without the element or the
text, whatever its status. The two flags combine: `--retry` applies to every
run.

A run of several requests through proxies adds them to what it ends with: how
many were used, how many of them carried anything, and each one nothing came
back through, by name.

```text
  Proxies       8 used, 6 alive, some direct
  dead proxy    http://user@198.51.100.4:8080  (12 requests, none came back)
  dead proxy    socks5://198.51.100.9:1080  (11 requests, none came back)
```

### Sending a request as a page would

```bash
tls-forge fetch --request-kind navigation https://shop.example/item/7
tls-forge fetch --request-kind form --initiator-url https://shop.example/login \
  -X POST -d 'user=a&password=b' https://shop.example/session
tls-forge fetch --request-kind fetch --initiator-url https://shop.example/item/7 \
  -X POST -H 'Content-Type: application/json' -d '{"item":7}' https://api.shop.example/cart
```

In `fetch` and `xhr` contexts, repeated script header names are combined with
`, ` in input order, and fields follow Chrome's renderer header-map order,
including collisions and growth as more names are added. HTTP/1 preserves the
script fields' spelling,including lower case. Ordinary requests
without a browser context retain their raw repeated fields. Measured profiles
also keep ALPS consistent with the final ALPN offer when a transport forces
HTTP/1.1.

`-H`, `NewHeader`, `Header.Set` and `Header.Add` retain the supplied name's
spelling. Lookups remain case-insensitive; HTTP/2 still writes lowercase names.
Fetch/XHR chains follow twenty redirects (twenty-one requests); the next
redirect fails with `the 21st redirect was not followed`. Navigation/form and
low-level requests retain the measured navigation bound: nineteen redirects,
twenty requests,then `the 20th redirect was not followed`. Requested client hints
use the renderer's construction order before its hash
table is iterated, including partial `Accept-CH` grants.


Script-owned Accept-Language/Priority fields occupy their renderer slot once.
HTTP/1.1 retains a script's explicit `Priority`; only the generated network
Priority is omitted. Cookies match the serialized URL path, preserving percent
escapes and their spelling, and use that path for a missing cookie Path.
The browser cache keeps one current representation per URL/partition; a Vary
mismatch replaces it, so returning to the old variant contacts the origin.

Content decoding also applies to `206` responses. With gzip, a complete HTTP
body ending within a valid header or DEFLATE stream returns the bytes decoded
so far, as measured in Chrome. Invalid gzip/DEFLATE data and truncated HTTP
framing still fail. Only the first gzip member is decoded; trailing bytes are
consumed to preserve connection reuse. The decoded-body limit still applies.

Chrome profiles bound HTTP/1 response heads at 262,144 bytes and allow six
active HTTP/1 connections per host pool; queued cancellation can end before
origin contact. An explicit transport-options override replaces these defaults.
HTTP/2 keeps a bounded encoded HPACK literal limit while allowing Huffman
expansion before applying its decoded field-list budget, preserving the
connection after an over-budget decoded field resets its stream.

Chrome cookie parsing and serialization preserve received pair bytes, including
unquoted spaces, quotes, backslashes, UTF-8 and nameless values. Cookie scope,
prefix, Secure, SameSite and lifetime checks still apply. An exact IP Domain is
host-only. Replacing a cookie with the same value preserves creation order;
changing its value gives it a new position among equal-length paths.

Requests with a browser context use a private cache partitioned by the
top-level schemeful site, URL and `Vary` fields. Complete 200 responses with
explicit freshness or a validator can be retained: 8 MiB per body, 64 MiB in
total and 256 entries. Fresh responses avoid another origin request; stale
ones use ETag or Last-Modified and merge a 304 response. HEAD can revalidate a
stored GET without replacing its body. Explicitly fresh 301/302/307/308 GET
redirects are retained, and identical buffered GETs can wait on one pending
cache representation. A single byte range can be served from a complete,
unencoded fresh 200 entry. A complete 206 prefix with a strong ETag can be
retained within those same limits; a full GET first validates the prefix, then
requests the missing interval with If-Range. Only exact intervals with the
same strong ETag are joined. A changed resource replaces the old prefix;
truncated bodies are never accepted as complete. Other partial layouts and
multipart ranges continue through the origin. Script Range without If-Range
uses the network header slot and HTTP/1 spelling `Range`; with If-Range, Chrome's renderer slots and
`Cache-Control: max-age=0` apply. Both caller forms use
`Accept-Encoding: identity`.
`no-store`, `Vary: *` and truncated bodies are not cached. Low-level requests without a browser
context continue to contact the network. Cache-mode and cache-clearing APIs
remain unavailable.

For a response to a browser-context request, headers retain the received
Content-Encoding and Content-Length, as Chrome Fetch does. Original HTTP/1
Transfer-Encoding and Trailer declarations remain visible; actual trailer
fields are not promoted into response headers. The body is already
decoded and `Encoding` identifies the codings removed. Responses without a
browser context retain the decoded-body header contract used by the proxy.

The current unreleased transport fixes use the local `go.work`, which selects
the maintained checkouts in `../forks/{utls,fhttp,tls-client}`. The rebuilt local
executable includes those edits. Published module requirements have not been
advanced: publishing the fork changes and updating their pseudo-versions is a
separate release step. `GOWORK=off` selects the previously published transport.

Without `--request-kind` a request goes out as a navigation typed into the
address bar, with the profile's headers and whatever `-H` adds: what the first
request of a visit is. To plain http on another machine it goes as Chrome sends
it there, without the client hints and `Sec-Fetch-*` and offering neither
Brotli nor zstd, and each hop of a redirect as its own URL is; `-H` adds what
it is given all the same, a `Referer` too, though a navigation from a page gets
its `Referer` from `--request-kind navigation --initiator-url`. A page sends
others, and Chrome sends each kind its own way. `--request-kind` says which
this is, and `--initiator-url` the page it is sent from, and every request of
the run goes out as Chrome 155 was measured sending that kind
([GO.md](GO.md#browser-contexts) has the rules): a form's POST with
`Cache-Control`, `Origin` and the form's `Content-Type`; `fetch()` and an XHR
with `Accept: */*` and `Sec-Fetch-Mode: cors`; `Referer` and `Sec-Fetch-Site`
as the page stands to the URL; and only the cookies SameSite lets through. A
`fetch` or `xhr` to another origin that CORS asks about goes after a preflight,
an `OPTIONS`, and not at all when the preflight does not allow it: that URL
fails, said with `CORS:`, and is not tried again. A `fetch` or `xhr` to another
origin carries no cookies, and goes out, its preflight with it, on connections
of its own, as Chrome keeps those of requests without credentials apart. Its
redirects are followed as Chrome follows a page's, each hop worked out again
([GO.md](GO.md#redirects)), and one Chrome would not follow fails the same way.
From a page over https a `fetch`, an `xhr` or a form goes nowhere on plain http
on another machine, which Chrome blocks as mixed content (a form only until
the person using it says to go on past its warning, which tls-forge does not
do): a redirect there fails, said with `mixed content:`, and is not tried
again, a form's only when it posts the form there again (307, 308).
The client hints an origin asked for with `Accept-CH` go with every request of
the run to it, as Chrome sends them ([GO.md](GO.md#client-hints)).

What a page could not send is refused, with exit code 2, before anything is
sent or written: a navigation with `-H` or `-d`, a form, `fetch` or `xhr`
without `--initiator-url`, a header a script cannot set (`Cookie`, `Origin`,
`Referer`, `Sec-*`, `User-Agent`), a `fetch`, `xhr` or form from a page over
https to plain http on another machine, and a profile of a browser other than
a Chromium one, or one with no headers of its own. The block the run begins
with says what its requests are sent as.

### Checking the page

```bash
tls-forge fetch --wait-for-element '#price' https://shop.example/item/7
tls-forge fetch --wait-for-element '.product [data-sku]' --retry 2 --input urls.txt --report
tls-forge fetch --wait-for 'In stock' https://shop.example/item/7
tls-forge fetch --wait-for '/"status":\s*"ok"/' https://api.example/health
tls-forge fetch --wait-for '/в наличии/i' --wait-for-element '#price' https://shop.example/item/7
```

A site that turns a client away often does it with a 200 and a page of its
own, a challenge or a notice, rather than with a status that says so; and one
that does say so may still send the page. `--wait-for-element` names, as a CSS
selector, an element the real page has, and `--wait-for` text it has. Given
either, the body decides and the status does not: an answer whose HTML has an
element matching the selector, and whose body has the text, is the page, a 403
too, and one without one of them is not, a 200 too. Such an answer is counted
on its own row of the count, as `✗ 200 OK, no #price` or
`✗ 403 Forbidden, no "In stock"`, kept out of the share that came back as the
page, asked for again by `--retry` as a 503 would be, and makes the run exit
non-zero, saying how many pages were without each; one with it is counted as
the page, `✓ 403 Forbidden`, and is not asked for again. Its line of JSON says
`"missing_element": "#price"` or `"missing_text": "In stock"`, its row in a
report says `200, no #price` with how the page began, and its log and trace
say it too. Given both, a page has to have both, and its row names each it is
without: `200, no #price and no "In stock"`. So name something only the real
page has: a selector that an error page matches too makes that page the page.
A `-X HEAD` gets no body to look into, and is refused with either.

`--wait-for` is text, looked for as it is, case and all, unless it is written
as a regular expression: between slashes, with any of the flags `i` (any
case), `m` (`^` and `$` at every line), `s` (`.` matches a newline) and `U`
after the last, as `/\d+ in stock/i`. The syntax is Go's (RE2): no
look-around and no back-references, and a control character written as `\n`,
`\t` or `\x{…}`. So a value that begins with a slash and ends with one, or
with one and letters, is a regular expression, and its letters must be those
flags: `/in stock/g` and `/path/to/file` are refused, and text that has that
shape is looked for as `/\/path\/to\/file/`. Any other value is text, a path
like `/catalog/item.html` with it. Text is shown in quotes and a regular
expression between its slashes, so the two are told apart: `no "In stock"`,
`no /\d+ in stock/i`. A flag that is not one of the four, an empty `//`, a
pattern that does not compile and text that is not UTF-8 are usage errors,
before anything is fetched.

The body is what came, decompressed and nothing else: the HTML as the server
sent it, read as text in one of two ways, as `--html-decoding` says. `legacy`,
the default and what page checks have always done, reads it in the encoding
its byte order mark or its `Content-Type` names, else as UTF-8 when it is that
throughout, else in the one a `<meta>` in its first kilobyte names, or as
windows-1252. `browser` reads it as Chrome 155 decodes a document of its type:
in the encoding its byte order mark names, else its `Content-Type`, else what
a document of the type names in itself, which for HTML is an XML declaration
at the very start and, over it, the first `<meta>` naming an encoding before
the page leaves its head and is a kilobyte in, for XML its declaration, and
for CSS an `@charset` rule; else as UTF-8 for XML and JSON, and windows-1252,
what Chrome in English falls back to, for HTML and text. So a page in UTF-8
that names windows-1251 is read as windows-1251, as Chrome shows it, plain
text that names nothing as windows-1252, and XML only up to the first byte
its encoding has nothing for, where Chrome stops. Chrome also guesses the
encoding of HTML, CSS and text that name none from their bytes, and finds
windows-1251 or GBK that way; `browser` does not guess, and reads such a
page as windows-1252. What Chrome 155 did with 174 bodies, and the few of
them it guessed, are in `testdata/chrome155-decoding.json`, and `browser` is
held to the rest. Given without `--wait-for` or `--wait-for-element`,
`--html-decoding` reads nothing, and is refused. The report says which way the
body was read.

Nothing is rendered and no script runs, so an element or text a script adds is
not there to be found, and nothing is waited for. Text is looked for in the
markup, so `Tom &amp; Jerry` is what a page with an ampersand has, and a
script's text is in it like any other. A selector that will not parse, or is
only spaces, is a usage error too.

### Keeping every request

```bash
tls-forge fetch --repeat 20 --retry 2 -o out/ https://example.com/
tls-forge fetch --input urls.csv -o out/ > results.jsonl
```

`--output` names a directory, made if it is not there, and every request is
kept in it as three files whose names begin alike: the host it went to, when
it was made, and which request of the run it was, then what each file is. So
the directory lists by host and then by time, and the files of one request
sit together.

```text
out/example.com-2026-08-16-091854-584-1-logs.log
out/example.com-2026-08-16-091854-584-1-response.html
out/example.com-2026-08-16-091854-584-1-trace.json
```

- The `-response` page is what came back, whatever its status: what a server
  says when it turns a request away is the page most worth reading. A request
  that got no answer has none. It ends in what its `Content-Type` says it is,
  so that it opens as that: `.html`, `.json`, `.xml`, `.js`, `.css`, `.txt`, `.png`,
  `.pdf` and the like, `.json` for any `+json` type and `.xml` for any `+xml`.
  The header wins over the bytes: JSON sent as `text/plain` is kept as `.txt`,
  as a browser would show it. A response that names more than one type, in two
  fields or in one, is kept as the last of them, the one a browser goes by;
  `*/*` names none. Only when there is no `Content-Type`, it says no more than
  `application/octet-stream`, or it names a type the list does not know, do
  the bytes decide: `.json` when they parse as JSON, then what
  `http.DetectContentType` recognises, else `.txt` for text and `.bin` for the
  rest. A page that came compressed, as gzip, deflate, br or zstd, is kept
  decoded, as a browser shows it, and the header fields that go with it in
  `-i`, the JSON lines, the report and the trace describe it decoded:
  `content-encoding` and `content-length` come off. A coding Chrome does not
  know either is left as it came, its field with it.
- The `-logs.log` is the request written out for a person: what it was, the run
  it was made in, the profile and the proxy it went with, where it came out,
  how it ended, and
  every try at it with what the proxy answered when it opened the tunnel,
  the connection it went out on, each thing it waited on and for how long, the
  request as it was written, what the answer came with, how an answer that was
  not a 2xx began, and the wait before the next try.
- The `-trace.json` is the same request as a trace of its own, in the Trace
  Event JSON format [ui.perfetto.dev](https://ui.perfetto.dev/) opens: the
  request, inside it every try, and inside each try its steps.
- With `--pcap`, a fourth, `example.com-2026-08-16-091854-584-1.pcapng`: the
  connections the request went out on, every byte each way and the TLS
  secrets that open them, for Wireshark; see
  [Reading a run in Wireshark](#reading-a-run-in-wireshark).

Beside them is the log of the whole run, `run-<time>.log`, named for the
moment the run began, unless `--log` puts it somewhere else; see
[Logging a run](#logging-a-run). That moment, `2026-08-16-091850-563`, is the
run's id: its log, its report, its trace, each request it keeps and each
session it saves (in the set's `note`) say it, so that what one run left can be
told from another's.

The host is written in lower case, without its port, and anything a file name
cannot hold on every system becomes `_`; a host longer than 100 characters
keeps its first 91 and a hash of the whole, so that every name fits a file
system and two such hosts still list apart. The moment is the one the request
was made, to the millisecond, and the number counts the requests of the run
from one, in the order they were handed out. All three are written with mode
`0600`, as a report is: the log and the trace name what was asked for and
where it went, with credentials and cookie values written as `***`, and a page
can be one that only a session could open. A file that cannot be written ends
the run, since every request after it would have nowhere to go either.

`--clear-output-dir` empties the `--output` directory first, so that what is
in it afterwards is this run's and nothing else's: every file and directory in
it, hidden ones too, and a link without what it points to, while the
directory itself stays where it was. It happens once the run has read what it
reads before it starts and before it writes anything, so a `--trace`, a
`--report` or `--save-cookies` file in the directory is this run's. A
directory that is not there yet has nothing to empty, and how many entries
went is said on standard error. Since it deletes, it refuses, with the reason
and without removing anything, a directory whose loss would be a disaster
rather than a clean slate: the root of the file system, the home directory or
one that holds it, the directory the command runs in or one that holds it
(`-o .`), one with a git repository in it, one holding a file the run reads
(`--input`, `--cookies`, `--exit-headers`, and a `.json` `--save-cookies`,
which a run reads to add its session to the ones there), and one holding the
file standard output or error is redirected to. A directory is known by what
it is, whatever it is called: through a link, in other capitals where names
ignore case (`-o /Users/ME` is the home directory /Users/me on a Mac), or by
another name the system gives it (macOS's `/System/Volumes/Data/Users/me`).

### Tracing a run

```bash
tls-forge fetch --trace run.json https://example.com/
tls-forge fetch --input urls.csv --trace run.json
```

`--trace` records what a run did, step by step, in the Trace Event JSON format.
Open the file at [ui.perfetto.dev](https://ui.perfetto.dev/) or in
`chrome://tracing` to see it as a timeline: one row for the command, one more
row per worker when several requests run at once, a bar for every try at a
URL, and inside it a bar for each thing the try waited on.

| In the trace | Meaning |
|---|---|
| `fetch` | The whole run, with its settings; it ends with the error, if there was one |
| `profile`, `exit-ip`, `cookies loaded`, `cookies saved`, `summary` | What the run was wearing, where it came out, and the session and totals it handled |
| `GET <url>` | One try, with its run and attempt number. It ends with the status, size, final URL and response headers, or with the error |
| `dns`, `connect` | The name lookup and the TCP dial, with every address tried and why any of them failed |
| `tls`, or `proxy+tls` through a proxy | From the dial to a usable connection, with the TLS version, cipher and ALPN it settled on, and the proxy's answer to `CONNECT` as `proxy_answer` |
| `send` | Writing the request: the header fields in wire order, and whether the connection was reused |
| `wait`, `receive` | Until the first byte of the response, and from there to its end |
| `redirect`, `retry`, `saved` | A redirect being followed, a try about to be made again and why, and a body written to a file |

A step that was still in progress when a try failed is marked `unfinished`,
which shows where the time went: a request that timed out waiting for the
server ends in an unfinished `wait`. An answer that is not a 2xx keeps the first
512 bytes of its body in the trace, because a later try replaces it everywhere
else.

The file holds one event per line, so it can be searched without a viewer:

```bash
grep '"error"' run.json
jq -c '.[] | select(.name == "retry") | .args' run.json
jq -r '.[] | select(.ph == "X") | "\(.name)\t\(.dur)"' run.json
```

Times are microseconds: `ts` since the Unix epoch and `dur` as a length. Events
are written as they happen, so a run that is interrupted leaves a trace without
its closing bracket. The format allows that: Perfetto opens such a file and
shows the request that was in flight as unfinished. The file is replaced on
every run, in a directory made for it if there is none, and created with mode
`0600`. Each try adds about two kilobytes,
most of it the header fields of the request and the response.

A [report](#reporting-a-run) of a traced run links every request to the trace
and opens the request's own at ui.perfetto.dev with one click.

A trace is meant to be kept and passed on, so it leaves out what a session is
worth. Proxy passwords, cookie values, `Authorization` credentials and the
values of headers whose names contain `token`, `secret`, `password` or `key`
are written as `***`; cookie names, cookie attributes and the authorization
scheme are kept. URLs are recorded in full, including their query strings.

### Logging a run

```bash
tls-forge fetch -o out/ https://example.com/
tls-forge fetch --input urls.csv --log run.log
tls-forge fetch --log run.jsonl --log-level debug https://example.com/
tls-forge fetch --log - --log-level info https://example.com/
```

A run writes down what it does as it does it, a line for each thing, for
whoever has to work out afterwards what went wrong: every lookup of a name and
what it found, every dial, what a proxy said to `CONNECT`, every TLS handshake
with the ClientHello that went out and the certificates that came back, the
header fields of each request in the order they were written, the HTTP/2
frames that came back, and how each try ended. A run that never finished has
it up to where it stopped.

With `--output` the log is kept there as `run-<time>.log`; `--log FILE` puts it
anywhere else, in a directory made for it if there is none, and `--log -` on
standard error, around the count. Without either there is none. A file is
added to rather than replaced, so that a run does not lose the one before it,
and is created with mode `0600`. A name ending in `.json`, `.jsonl` or
`.ndjson` gets JSON lines, and anything else `key=value` text, its times to the
microsecond:

```text
time=2026-10-15T23:51:58.983934+02:00 level=DEBUG msg=connected worker=1 req=1 run=1 try=1 client=3 conn=127.0.0.1:56797->127.0.0.1:9417 tls="TLS 1.3" cipher=TLS_AES_128_GCM_SHA256 alpn=h2 resumed=false server_name=localhost certificate="CN=tlsforge echo" took=688.375µs
```

`--log-level` says how much. `trace`, the default, is all of it; `debug` leaves
out the ClientHellos, the certificates and the HTTP/2 frames; `info` is a line
for each request, each answer, each try's result and the run; `warn` and
`error` keep what went wrong. The transport is asked to say what frames it reads
only for a log kept at `trace`, and only from then on: without one it makes no
line about a frame, which cost a request on loopback about a tenth of its time.

| Record | Level | What it says |
|---|---|---|
| `run`, `summary`, `run ended` | INFO, or WARN for a run that failed | The run's settings, its totals, and how it ended |
| `client`, `fresh client`, `profile handshake`, `profile http2`, `profile headers`, `idle connections closed`, `client closed` | INFO, DEBUG | Each client: the profile, its JA4, the HTTP/2 preface with its Akamai fingerprint, the header order; each worker's own, and when their connections were let go |
| `request`, `response`, `request failed` | INFO, WARN | Each try: what was asked, and the answer, or why there was none, whether that was a timeout, and the step it gave up in: `prepare`, `dns`, `connect`, `proxy`, `tls`, `send`, `wait`, `receive`, `body` or `redirect` |
| `dns lookup`, `dns answer`, `dns failed`, `dial`, `dialed`, `dial failed` | DEBUG, WARN | The lookup with every address it found, and each TCP dial. A dial that fails is DEBUG: another address may still answer, and a request none answered says so itself |
| `proxy tls`, `proxy connect`, `proxy answer`, `proxy refused`, `proxy tls failed`, `proxy connect failed` | DEBUG, WARN | The handshake with an HTTPS proxy, the `CONNECT` with its header fields, the answer with the tunnel's number and header fields, and a refusal with up to 1 KiB of what the proxy said |
| `connected`, `reused connection`, `connection kept for the next request` | DEBUG | The connection by both its ends, the tunnel it goes through, the TLS version, cipher suite and ALPN, whether the session was resumed, the server name and certificate |
| `client hello`, `certificate`, `handshake extras` | TRACE | The ClientHello that went out on each new connection: JA4, JA4_r, JA3, and every extension, cipher suite, version, group, key share and signature algorithm in order, and the length of its GREASE ECH payload as `ech_payload_bytes`, drawn for each connection; each certificate of the server's chain |
| `client hints asked` | DEBUG | What an origin asked for with `Accept-CH` on the answer to a navigation in a browser context: the hints its requests carry from then on, none for an empty one |
| `client hints asked over ALPS` | DEBUG | The hints a connection's ALPS asked an origin for in an `ACCEPT_CH` frame that a page's request to it did not carry: the request goes with them, after `Accept`, as Chrome sends it again with them |
| `restarted for client hints` | INFO | A navigation started again where it began, as Chrome starts one, for the hints a `Critical-CH` said its page needs |
| `restarted for a 421` | INFO | A request a server answered 421 (Misdirected Request), sent again on a connection of its host's own, as Chrome sends it once |
| `request sent`, `first byte`, `response headers`, `redirect`, `redirect not followed` | DEBUG, WARN | The header fields as written, pseudo-headers included, in order; the answer's status, protocol and header fields; each redirect, and the twentieth, which is not followed |
| `transport` | TRACE, WARN | What the HTTP/2 transport says: every frame it reads, the connections it opens and closes, and, as a warning, a server breaking the protocol or a cookie it will not keep |
| `retry`, `page check`, `result`, `exit`, `cookies loaded`, `cookies saved`, `report` | INFO, WARN | Why a try is made again and after how long, what `--wait-for` and `--wait-for-element` found, how each request ended, where the run comes out, the session and the report |

Every record of a request says which it is: `req`, its number in the run,
`run` under `--repeat`, `worker`, `try`, and `client`, the client it went
through; one that asks a site where the request came out says `probe`. A
record that ends a step says how long the step took as `took`. Every
connection is dialed for a request, and its lookup, dial and tunnel are in
that request's records; the `connected` record of a later request that goes
out on it names it, as `conn`, and its tunnel. What the transport says of a
frame names no request;
with one request at a time, a frame belongs to the one around it.

A log leaves out what a trace does: proxy passwords, cookie values,
`Authorization` credentials and the values of headers whose names contain
`token`, `secret`, `password` or `key` are written as `***`. The lines in which
the HTTP/2 transport says each header field it encodes are left out, since
`request sent` has the fields without their secrets. A DATA frame shows up to
256 bytes of the body it carried, as the transport does.

`--log` cannot name a file another flag names, by any path or link to it:
that is a usage error, as it is for every file a run reads or writes; see
[Files a run reads and writes](#files-a-run-reads-and-writes). A log that
cannot be written is said once the run is over, and the run exits 1.

### Reading a run in Wireshark

```bash
tls-forge fetch -o out/ --pcap https://example.com/
```

`--pcap` keeps, beside each request's files, `NAME.pcapng`: the connections
the request went out on, every byte each way at the moment tls-forge wrote or
read it, and the TLS secrets of each in the file itself, in a Decryption
Secrets Block, so that Wireshark opens it decrypted as it is: no capture to
start, no key log to give it, nothing to run as root. It holds the request's
connections alone, each try's, the one its site is asked over and, through a
proxy, the one to the proxy: an HTTP or HTTPS proxy's, with the CONNECT that
opened the tunnel, or a SOCKS4, SOCKS4a, SOCKS5 or SOCKS5h proxy's, with the
handshake that did; not the run's question to an address service, which no
request went out on. A connection is let go of before the request is kept, so
its capture holds how it ended; with `--reuse-connection` a URL's repeats share
theirs, and each repeat's capture holds it from its start to where that repeat
was kept. Wireshark finds the site's TLS after a SOCKS handshake on any port,
and shows the handshake itself on port 1080, or on another with
`-d tcp.port==PORT,socks` (Decode As… in the app).

The file is made by tls-forge from what it wrote and read, and its TCP/IP
headers are made up: the ends of each connection are its own, but its segments
are tls-forge's writes and reads, numbered from zero, with no TCP options and
no retransmission, and the first packet of each connection says so in a
comment. What is above them, TLS and HTTP, is exact; what the system did on the
wire, its handshake and its TCP/IP fingerprint, is not there, and a capture of
the wire, below, has it. What a proxy was given in the clear to open a
tunnel is masked, a `*` for each of its bytes so that nothing else moves: a
SOCKS5 proxy's password, and an HTTP proxy's `Proxy-Authorization` past its
scheme, both as a log writes them, the user name and the scheme kept; an
HTTPS proxy's goes under its TLS, which the secrets in the file open as they
open every connection's. The capture is written with mode `0600`, and whoever
has it reads every connection in it; `editcap --discard-all-secrets` makes a
copy without the secrets, which says nothing of what went over TLS.

To read the wire itself:

```bash
# In one terminal, capture what goes over the wire as long as the run takes,
# on the interface it goes out by (en0 on most Macs, any on Linux):
tcpdump -i en0 -w run.pcap 'tcp port 443'
# In another, run with the secrets of its connections kept:
tls-forge fetch --keylog run.keys https://example.com/
# Then read the capture with them, in Wireshark or tshark:
tshark -r run.pcap -o tls.keylog_file:run.keys -Y http2
```

A capture of a run is TLS records, which say nothing without the secrets of
their connections. `--keylog FILE` adds those of every connection the run
makes to the file, in the NSS key log format that browsers write to the file
`SSLKEYLOGFILE` names: the connections to the sites, the one to an HTTPS proxy
and the sites' inside its tunnel, and the one that asks where the run comes
out. Given the file (Preferences, Protocols, TLS, (Pre)-Master-Secret log
filename, or `-o tls.keylog_file:FILE` to `tshark`), Wireshark shows each
connection as the run wrote and read it: the handshake decrypted, every HTTP/2
frame and HTTP/1.1 message, headers and bodies. Through an HTTP proxy, whose
CONNECT goes in the clear, the site's connection in the tunnel is read as well.
Through an HTTPS proxy Wireshark reads the connection to the proxy, the CONNECT
and its answer, but not the site's TLS inside it, which it shows as HTTP
continuation data (Wireshark 4.6.9): the site's secrets are in the file all
the same.

So does anybody else who has the file: it reads every cookie, credential and
body of the run. It is created with mode `0600`, added to rather than replaced,
as the browsers do, so that one file serves every run of a capture, and is for
looking into a run and deleting, never for keeping. `--keylog -` is refused:
secrets go to no stream. A file that cannot be written is said once the run is
over, and the run exits 1; the requests themselves go on. The capture is the
machine's to make: on macOS it needs access to `/dev/bpf`, which Wireshark's
ChmodBPF gives (`-i any` needs root there), and on Linux root or `CAP_NET_RAW`.
From Go, `WithKeyLogWriter` does the same for a client; see
[GO.md](GO.md#reading-a-client-in-wireshark).

### Reporting a run

```bash
tls-forge fetch --repeat 20 --retry 2 -o out/ --report https://example.com/
tls-forge fetch --repeat 20 --retry 2 --report=run.json https://example.com/
tls-forge fetch --input urls.csv --report=reports/ --report-format html,json
```

`--report` writes the run down when it is over: as a page for whoever opens
it, as a JSON document for a program, or as both from the same run.
`--report-format` says which, as `html`, `json` or `html,json`. Without it the
name says: a path ending in `.json`, in any case, gets the document, and
anything else the page, a directory as well, whatever it is called.

Given on its own, `--report` puts the report beside what the run kept: in the
directory `--output` names, or in the current directory when there is none,
named after the moment the run began, as its log is:
`report-2026-08-16-091854-584.html`.
A path of its own is given after an equals sign, `--report=reports/` or
`-R=run.html`, because the flag needs none: a path after a space is read as
the next URL, and `fetch` says so when it is not one.

The page is one HTML file with nothing to load from anywhere else, so it can be
opened offline and sent on as one file; only opening a trace in Perfetto, below,
goes anywhere. At the top is the share of requests that came back as the page,
with how many answered with something else, or, when `--wait-for-element` or
`--wait-for` names what the page has, how many answers were without it, and
how many got no answer, and under
it the data, the retries, the time the run took and the average time of one
request. Then there is a row for every request: when it started, how long it
took, how it ended, how much came back and how many tries it took. Rows are in
the order the requests were sent, and when a URL was asked for more than once
each row says which run it was. The proxy a request went through and the address
it came out of are each said once above the rows when every request had the
same, and on each row when they did not: a proxy that hands every request an
address of its own gives the rows a column of them, and the line above says how
many there were. The table of proxies lists the addresses each one came out of.

Every row opens, and shows what that request took:

- where it ended up when it was redirected, the file it was saved to, when it
  started and ended to the millisecond, why where it came out is not known,
  and the error in full;
- when the run was traced, the trace: the one the request was kept with under
  `--output`, with its log, or else the `--trace` file of the whole run, each
  a link from where the report is; and **Open in Perfetto**, which opens the
  trace of that request alone at [ui.perfetto.dev](https://ui.perfetto.dev/)
  in a new tab;
- every try that was made at it, with how the try ended, how long it took and
  how long was waited before the next one;
- the connection each try went out on: new or already open, the address at the
  other end, where it came out when its proxy said, the TLS version, cipher
  suite and protocol the handshake settled on, and the header fields of the
  proxy's answer to `CONNECT`;
- each thing the try waited on and for how long: the name lookup with the
  addresses it found, the dial, the handshake, sending the request, waiting for
  the first byte and receiving the answer. A redirect is listed where it
  happened, and the step a failed try stopped in is marked as that;
- the request as it went out: every header field in the order it was written,
  the HTTP/2 pseudo-headers included, which is the part of a request a server
  can tell a browser by;
- what the answer came with: its header fields and, when it was not the page,
  the first 512 bytes of its body, which is usually where a server says why.

Each try is also drawn as a bar on the length of the whole request, so the
tries of one request line up as a picture of it, with the waits between them
as the gaps. These are the steps a [trace](#tracing-a-run) records, measured by
the same clock, so the report and the trace of one run agree.

Open in Perfetto needs nothing but the report: the trace of each request is
written into the page, compressed, because a page opened from a file may read no
other file, and handed to the viewer it opens. It is the trace kept beside the
request under `--output`, byte for byte, and without `--output` the request as
it would have been kept. Perfetto asks before it opens a trace that a page it
does not know hands it, which a page opened from a file is: answer Yes. The
report holds the one script that does this, and only when the run was traced.
Links are relative, so a directory that holds the report and what the run kept
can be moved or sent on whole.

A report leaves out what a trace does, so that it can be passed on: proxy
passwords, cookie values, `Authorization` credentials and the values of
headers whose names contain `token`, `secret`, `password` or `key` are written
as `***`. The start of a body that was not the page is kept as it came.

The JSON document holds what the page shows, under names of its own:

```json
{
  "command": "fetch",
  "version": "0.3.0",
  "run_id": "2026-08-16-091850-563",
  "started": "2026-08-16T09:18:50.563+02:00",
  "profile": "chrome_155_macos",
  "generated": "2026-08-16T09:18:54.584+02:00",
  "summary": {
    "requests": 20, "scraped": 18, "not_2xx": 2, "no_response": 0,
    "success_rate": 90, "bytes": 10386, "retries": 4,
    "elapsed_ms": 4021, "avg_ms": 199
  },
  "requests": [
    {
      "url": "https://example.com/",
      "status": 200,
      "final_url": "https://example.com/",
      "bytes": 577,
      "started": "2026-08-16T09:18:50.563+02:00",
      "ended": "2026-08-16T09:18:50.908+02:00",
      "ms": 345,
      "run": 1,
      "attempts": 2,
      "exit": {"ip": "203.0.113.7", "country": "PL"},
      "tries": [
        {
          "started": "2026-08-16T09:18:50.563+02:00",
          "ms": 84.2,
          "status": 503,
          "bytes": 19,
          "connection": {
            "reused": false, "remote": "104.20.23.154:443",
            "tls": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "alpn": "h2"
          },
          "steps": [
            {"name": "dns", "from_ms": 0.3, "ms": 1.9, "note": "example.com → 104.20.23.154"},
            {"name": "connect", "from_ms": 2.2, "ms": 6.4, "note": "104.20.23.154:443"},
            {"name": "tls", "from_ms": 8.6, "ms": 12, "note": "TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2"},
            {"name": "send", "from_ms": 20.6, "ms": 0.065, "request_headers": [":method: GET", ":authority: example.com"]},
            {"name": "wait", "from_ms": 20.7, "ms": 63.3},
            {"name": "receive", "from_ms": 84, "ms": 0.164}
          ],
          "response_headers": ["retry-after: 1", "server: cloudflare"],
          "body_start": "<html>…",
          "wait_ms": 250
        }
      ]
    }
  ]
}
```

A request is the JSON line a list is answered with, without the body and under
the same names, with `exit` and `tries` added. Times are milliseconds, and those
of a try and of its steps keep a fraction, because most steps are over in less
than one. `success_rate` is a percentage. `trace` is the `--trace` file of the
run, when there was one. A step the try ended in carries `"unfinished": true`, a
redirect is a step named `redirect`, and `proxies` lists each proxy that was
used with its `requests`, `came_back`, `alive` and `exits`, every address its
requests came out of. An `exit` has the `ip`, or the `hash` of it when that is
all the proxy said. A request whose exit is not known has `exit_error`, why,
instead of `exit`, and the `connection` of a try has the proxy's answer as
`proxy_answer` and where it said the connection came out as `exit`. A field
with nothing to say is left out. The same things are masked as on the page.

The document holds every request, where the page stops at 2,000 rows. `tries`
are there for the requests whose tries were kept: the first 2,000 that failed
or answered with something other than the page, and the first 2,000 others.

Given a directory, or a path ending in a separator, a report is named after
the moment the run began in the same way, `.html` or `.json`; the `--output`
directory counts as one before the run has made it. One format given any other
path is written to that path, whatever it is called, and replaced on every run
once the new one is whole. Two cannot both be, so the path then names them
both: `--report=run`, or `--report=run.html`, with `html,json` writes
`run.html` and `run.json`. A report is created with mode `0600`, and its name
is the last thing a run prints. A path that cannot be a report's is refused
before the run, as for every file; see
[Files a run reads and writes](#files-a-run-reads-and-writes). One that cannot
be written once the run is over fails it with exit code 1, after the pages
have gone where they were going; of two, the one that could be written still
is.

The report is written however the run ended, a request that got no answer
included. Where a request came out is what its proxy said, or for one made
without a proxy, the address asked about before the run; see
[Where a request came out](#where-a-request-came-out). The address a run
through a proxy was asked about before it began is at the foot of the page,
and given to no request. The page holds at most 2,000 rows: the requests that
failed or answered with something other than the page come first, and it says
how many rows it left out.

Runnable CLI and SDK examples, with complete sample inputs and outputs, are in
[`example/`](example/).

## Reference

Every command with its flags, what each one prints and how it ends, and the
libraries for Go, Node.js and Python.

### Commands

```text
tls-forge <command> [flags]
```

| Command | Purpose |
|---|---|
| [`fetch`](#fetch) | Make requests with a browser fingerprint: one URL, or a list of them, each optionally through its own proxy |
| [`capture`](#capture) | Measure an installed browser and optionally save a reusable profile |
| [`compare`](#compare) | Compare a profile with an installed browser |
| [`profiles`](#profiles) | List available profiles |
| [`proxy`](#proxy) | Re-send requests from another program using the selected fingerprint |
| [`serve`](#serve) | Run the local TLS/HTTP fingerprint echo server |
| [`daemon`](#daemon) | Expose the client as a JSON Lines transport |
| [`version`](#version) | Print the build version |

Run `tls-forge <command> --help` for generated command help. Durations use Go
syntax such as `500ms`, `30s` or `2m`.

A command that fails says why on standard error, on a line that begins with
`tlsforge: ` once, whether the reason is the command's own or one the Go
library gave it:

```text
tlsforge: Get "http://127.0.0.1:1/": dial tcp 127.0.0.1:1: connect: connection refused
```

A run that fails for more than one reason, such as a request that got no
answer and then a report that could not be written, gives each reason a line
of its own, and every one of them begins the same way.

What a command says has the password of every URL in it taken out, on
standard error, in a log, a trace, a report and the JSON lines, in what
`daemon` answers and in what `proxy` reports and sends back with a 502: a
proxy that could not be read is otherwise quoted back whole, by whatever
tried to read it. A proxy's username is kept, since it tells two proxies
apart.

`fetch`, `proxy` and `daemon` take the proxy from an environment variable
with `--proxy-env NAME`: on the command line, a password is one that `ps`
shows to every user of the machine. The environment is not a secret either.
It keeps the password from other users, and from nobody who can read the
process itself, such as its owner and root. The variable is read only when it
is named, and naming one that is not set or is empty, or giving `--proxy` as
well, is a usage error before anything is asked. `daemon --proxy-stdin` takes
the proxy from the first line of its input instead, which is read once, and
the Node.js and Python packages start the daemon that way; see
[the init line](docs/protocol.md#the-init-line).

Ctrl-C, or SIGTERM as `kill`, a service manager and `docker stop` send it,
stops a command in order. `fetch` cancels the requests in flight, which its
report and lines say ended with `context canceled`, makes no others, and
writes its report, its session and the end of its trace, and exits 1; a
cookie a cancelled request's header fields set is in the session. `daemon`
answers the request it is making with that error, and exits 0, as it does at
the end of its input. A second signal ends a command where it stands, should
the first leave it waiting on something that does not look, such as an output
nobody reads. SIGKILL cannot be caught, and leaves what it leaves.

When no profile is selected, the network commands (`fetch`, `proxy` and
`daemon`) use a profile installed as `local`, if one exists, and otherwise
the latest bundled `chrome` profile. `compare` defaults to the bundled `chrome`
family so it can detect drift instead of comparing a fresh local measurement
with itself. Use `tls-forge profiles` to see the exact names available on the
machine. A command resolves its profile once, when it starts, and wears that
one to the end: a client it makes later, for a proxy a list reaches last, does
not pick up a profile installed, or a `--profile` file changed, meanwhile.

#### `fetch`

Make requests and report how they went. One URL is answered with its page, and
several URLs, or a list of them, with one JSON object for each request.

```bash
tls-forge fetch https://example.com/
tls-forge fetch --print-body https://tls.browserleaks.com/json
tls-forge fetch https://example.com/ > page.html
tls-forge fetch -i -H "Accept-Language: en-US" https://example.com/
tls-forge fetch -X POST -H "Content-Type: application/json" \
  -d '{"hello":"world"}' https://example.com/api
tls-forge fetch https://example.com/ https://example.org/
tls-forge fetch --input example/urls.csv --concurrency 8 --output out/ > results.jsonl
```

Usage: `tls-forge fetch [flags] [url...]`

`tls-forge fetch --help` lists the flags under the same headings as this table.

| Flag or argument | Meaning |
|---|---|
| **What to fetch** | |
| `[url...]` | One HTTP or HTTPS URL, or several |
| `--input <file>` | Read the URLs from a file; a list piped to standard input is read when no URL is named |
| `-u`, `--urls <a,b,c>` | Comma-separated URLs; highest input precedence |
| `-F`, `--format <format>` | How the list is read: `auto`, `lines`, `json` or `csv`; default `auto` |
| **The request** | |
| `-X`, `--method <method>` | HTTP method, for every URL; default `GET` |
| `-H`, `--header "Name: value"` | Add or override an ordered request header, for every URL; repeatable |
| `-d`, `--data <text>` | Request body, for every URL |
| `--request-kind <kind>` | Send every request as Chrome sends this kind: `navigation`, `form`, `fetch` or `xhr`; see [Sending a request as a page would](#sending-a-request-as-a-page-would) |
| `--initiator-url <url>` | The page a `--request-kind` request is sent from; a form, `fetch` and `xhr` need one, and a navigation without one is typed into the address bar |
| **Fingerprint and transport** | |
| `-p`, `--profile <name-or-path>` | Profile to impersonate; without one, the browser measured on this machine (`local`) when there is one, else `chrome`, the newest Chrome shipped |
| `-t`, `--timeout <duration>` | How long each try may take, all of it: its connection, redirects, answers to a 401 or a 421, and body; default `30s` |
| `-k`, `--insecure` | Skip upstream certificate verification |
| **Proxy** | |
| `-x`, `--proxy <url>` | HTTP, HTTPS or SOCKS proxy, optionally with credentials; in a list, the proxy of every entry that names none |
| `--proxy-env <name>` | Read `--proxy` from this environment variable, such as `TLSFORGE_PROXY`, which keeps its password off the command line; no variable is read unless named. See [Through a proxy](#through-a-proxy) |
| `--exit-headers <file>` | A JSON file laid over the exit header fields built in: one of the same key replaces the built-in one, `"off": true` takes it out, the rest are added; see [Where a request came out](#where-a-request-came-out) |
| `--no-exit-lookup` | Make no request to learn where requests come out: no address service before the run, no probe of a site, no name a proxy gave resolved. What a proxy says when it opens a tunnel is still read |
| **Session** | |
| `-b`, `--cookie name=value` | Seed one cookie; repeatable |
| `--cookies <file>` | Load a warmed session from JSON, a browser export, or Netscape cookies.txt |
| `--cookie-set <id>` | Select a set from a multi-session JSON file; otherwise one is chosen at random, once for each proxy the run goes through, when it starts, and the log and the trace say which |
| `--save-cookies <file>` | Atomically save the final session, one set for each proxy; `.txt` selects Netscape format, which holds one session and is refused for a run through more than one proxy |
| **Running** | |
| `-c`, `--concurrency <n>` | Requests to run at once; default `4`, and one URL is asked for one at a time unless this is given. In `compare`, `-c` is `--color` |
| `--retry <n>` | Ask again up to `n` more times when the answer is not a 2xx, or does not come, each time on a connection of its own; default `0` |
| `--repeat <n>` | Make every request `n` times, each on a connection of its own; default `1` |
| `--reuse-connection` | Repeat a URL, and try it again, on the connection its first request opened, rather than on a new one: through a proxy, out of the same exit |
| `--wait-for <text>` | Count an answer as the page when its body has this text in it, whatever its status, or, written as `/regexp/` with any of the flags `i`, `m`, `s` and `U`, text the regular expression matches; see [Checking the page](#checking-the-page) |
| `--wait-for-element <selector>` | Count an answer as the page when its HTML has an element matching this CSS selector, whatever its status: one without it is asked for again like a 503, shown as `200, no <selector>`, and fails the run; see [Checking the page](#checking-the-page) |
| `--html-decoding <mode>` | How `--wait-for` and `--wait-for-element` read a body as text: `legacy`, the default, or `browser`, as Chrome 155 decodes the document; refused without either; see [Checking the page](#checking-the-page) |
| **Output** | |
| `-o`, `--output <dir>` | Keep every request in this directory: its page, a log of it and a trace of it, and a log of the run; see [Keeping every request](#keeping-every-request) |
| `--clear-output-dir` | Empty the `--output` directory before the run writes into it, of every file and directory in it; refused for a directory whose loss would be a disaster, see [Keeping every request](#keeping-every-request) |
| `--pcap` | With `--output`, keep beside each request's files the connections it went out on as `NAME.pcapng`, every byte each way and the TLS secrets that open them, for Wireshark to read as it is, through a proxy the CONNECT or the SOCKS handshake that opened its tunnel, its credentials masked; written with mode `0600`; see [Reading a run in Wireshark](#reading-a-run-in-wireshark) |
| `-i`, `--include` | Print the status and response headers in front of the page; with JSON lines, add them to each line as `headers` |
| `--json` | Write a JSON line for each request even when one URL is named |
| `--print-body` | Print the page or the JSON lines on standard output even when that is a terminal, and the page even when `--output` keeps it |
| `-v`, `--verbose` | Print a line when each request finishes, and one for each retry while requests are made one at a time |
| `--progress <mode>` | Redraw the count while the run goes: `auto`, `always` or `never`; default `auto` |
| `--color <mode>` | Colour the count by outcome: `auto`, `always` or `never`; default `auto` |
| **Report, trace and log** | |
| `-R`, `--report[=<path>]` | Write a report with every request in it, into the `--output` directory or the current one unless a path is given; see [Reporting a run](#reporting-a-run) |
| `--report-format <format>` | What the report is written as: `html`, `json`, or `html,json` for both; by default `json` for a `--report=PATH` ending in `.json`, and `html` otherwise |
| `--trace <file>` | Write every step of the run as Trace Event JSON; see [Tracing a run](#tracing-a-run) |
| `--log <file>` | Write down everything the run does as it does it: every request, the connections it went out on and what came back; `-` is standard error, and a name ending in `.json`, `.jsonl` or `.ndjson` gets JSON lines. With `--output`, kept there as `run-<time>.log` unless this names another; see [Logging a run](#logging-a-run) |
| `--log-level <level>` | How much the log says: `error`, `warn`, `info`, `debug`, or `trace`, which adds every TLS handshake, certificate and HTTP/2 frame; default `trace` |
| `--keylog <file>` | Add the TLS secrets of every connection the run makes, to its sites and its proxy, to this file, in the NSS key log format browsers write to the file `SSLKEYLOGFILE` names, so that Wireshark reads a capture of the run; created with mode `0600`; see [Reading a run in Wireshark](#reading-a-run-in-wireshark) |

What comes out is decided by how the command was asked, not by how many URLs
it ended up with:

- one URL named on the command line is answered with its page, the way `curl`
  answers;
- several URLs, `--urls`, `--input` or a list on standard input are answered
  with JSON Lines, one object for each request, and so is anything given
  `--json`.

A list that happens to hold one URL therefore still comes out as a line, and a
script reading the output does not have to know how long the list was.

On a terminal, `fetch` says how the run went rather than printing the page: a
bar for how far it has got, a line for how long that has taken, and a row for
each status code the answers came back with.

```text
  █████████████████████████████▓▓▓▒▒▒▒▒▒▒▒  40/40  100%
  5s elapsed · 731 B

  ✓ 200 OK                    29   73%
  → 304 Not Modified           3    8%
  ✗ 403 Forbidden              5   13%
  ✗ 503 Service Unavailable    3    8%

  Requests      40
  Retries       0
  Success rate  72.5%
  Avg time      126ms
```

The bar is cut by how the answers went, and the rows are marked the same way:
green and `✓` for a 2xx, yellow and `→` for a 3xx, red and `✗` for everything
else, each with a shade of its own in the bar so that the three can be told
apart without colour. A request that got no answer at all is counted in a last
row, `no response`. Each row gives how many answers had that status and their
share of those that have come back. While a run is going the second line also
says roughly how long is left.

When the run is over, four figures follow the rows: how many requests were
made, how many further tries `--retry` spent on them, the share of the requests
that ended with a 2xx, and the average time of one request. That time is
measured from when a request is sent to its last answer, so a request that was
tried again counts every try and the waits between them. A run that was stopped
early says how far it got, as `12 of 40`.

The count is redrawn in place while the run goes and stays on screen when it
ends. It is redrawn and coloured only when standard error is a terminal, and
`NO_COLOR` turns the colour off; anywhere else it is printed once, plainly, at
the end. A run of one request is reported on one line instead, which ends with
how many times it was tried again when it was:

```text
  ✓ 200 OK · 577 B · 54ms
  ✓ 200 OK · 577 B · 1.1s · 2 retries
```

The body is the output, so it still goes wherever standard output was pointed:
`tls-forge fetch URL > page.html` and `tls-forge fetch URL | jq .` need no flag.
It is only a terminal that does not get it unless `--print-body` asks, because a page
is thousands of lines nobody reads as they go past. With `--output` the body
goes to its directory alone, and `--print-body` prints it as well. `-i` prints the
status and headers whether or not the body is printed. JSON lines follow the
same rule, each of them holding a whole page: a pipe and a redirect receive
them, a terminal only with `--print-body`, and a run that printed none says so at
the end. The count and everything else that is commentary go to standard
error, so the lines stay machine-readable.

How a session is saved and read again is in [Cookies across
runs](#cookies-across-runs).

Before the first request, `fetch` asks a public service which address it comes
out of, through the same proxy and with the same profile. No cookie is sent
with the question. The answer is the last line of the block on standard error
that names the profile in use:

```text
  exit-ip     203.0.113.7 · PL
```

The same block says when the profile was measured on another platform than
this machine's, whether it was asked for by name or chosen because no capture
of that version exists for this machine. A profile changes the handshake and
the headers, but the TCP/IP packets under them are always this machine's:

```text
  tcp/ip      this machine's, macOS: the profile is Windows's, and a server that reads TCP/IP can tell the two apart
```

Four services are asked, in this order: `www.cloudflare.com/cdn-cgi/trace`,
`checkip.amazonaws.com`, `api.ipify.org` and `ipinfo.io`. The next one is asked
as soon as the one before it fails, or has said nothing for its share of the
wait, and the first to answer is believed; normally that is one request to the
first. Amazon and ipify report the address without a country.

This is at least one additional request to a third party on every run. The
lookup waits at most five seconds in all, and when nobody answers the line says
so instead of failing the fetch. A list whose entries name different proxies
has no one address to report, and nobody is asked. `--no-exit-lookup` asks
nobody, and the line says `not looked up · --no-exit-lookup`.

##### Where a request came out

The address asked about before the run is where every request made without a
proxy comes out. Through a proxy it is not where any request came out: the
question went on a connection of its own, and a proxy that hands every
connection an address of its own gave the requests others. Asking again for
each request would ask about another connection each time.

Only the proxy knows, and some say so in their answer to the `CONNECT` that
opens each tunnel. `fetch` opens the tunnel through an HTTP or HTTPS proxy
itself and keeps that answer with the connection, so every request says where
it came out, and no request is made to anybody to find out.

For a plain `http://` destination, Chrome profiles forward the request to an
HTTP or HTTPS proxy without CONNECT. An HTTPS proxy negotiates HTTP/1.1 or
HTTP/2 for this forwarding hop; HTTP/2 uses the destination's `:authority`
and `:scheme: http`. Proxy credentials stay on the proxy hop. HTTPS
destinations continue to use CONNECT.

With a Chrome profile, CONNECT streams and ordinary HTTP requests share the
HTTPS proxy's outer H2 connection within one client and top-level site. Origin
credential modes retain separate origin connections; their proxy hop can share
the same proxy-authenticated channel. Fresh clients and different top-level
sites keep separate pools. Closing or timing out one CONNECT affects only that
stream. CONNECT uses its own measured H2 priority, independently of the origin
request. After a fatal TLS write failure, the connection closes without sending
another encrypted alert with a sequence the peer cannot reconstruct.

Every URL, every repeat of it and every try goes out on a connection of its
own, through a proxy on a tunnel of its own, so a proxy that hands every
connection an address of its own gives each one. Once the run has been to a
site, a new connection there resumes the TLS session the site handed out, as
Chrome's does: the same handshake with `pre_shared_key` added last, and so a
JA4 of one extension more. Each of the `--concurrency` workers keeps sessions
of its own, so a site sees as many first contacts as there are workers that
went to it. `--reuse-connection` keeps a URL's connection for its repeats and
its tries instead, so that they come out where its first request did. A
request's redirects go through its connection, but for a hop Chrome sends on
another: one to another site goes through a connection of that site's, and
one that leaves a script's request without credentials through one of those
that carry none. What the site a request ended at is asked over the same
connection goes through its last hop's, but for a script's request from a
page of another origin (below).

Which fields say it, and what to ask when none does, is a table,
[`cmd/tls-forge/exit-headers.json`](cmd/tls-forge/exit-headers.json), built
into the binary. The file `--exit-headers` names, wherever it is, is laid over
it when a run begins, as `mergeRight` lays one object over another, so the
table is changed without building anything. The table built in covers:

| Field | Sent by |
|---|---|
| `X-Exit-IP`, with the country in `X-Exit-Country` | Massive, NodeMaven, shellroute |
| `X-Proxy-Exit-IP` | NodeMaven |
| `X-ProxyMesh-IP` | ProxyMesh |
| `X-BD-Outgoing-Ip`, and `ip=` in `X-BD-Dynamic-Egress-Info` | g3proxy |
| `Node-Ip`, with `Node-Country` | SOAX, when the `CONNECT` asks with `Respond-With: ip,country`, which the file makes every `CONNECT` say |
| `x-brd-ip`, and `brd_ip=` in `Proxy-Status` | Bright Data: the address on datacenter and ISP zones, a hash of it on residential and mobile ones |
| `x-luminati-ip`, `x-hola-ip` | Bright Data and Luminati before it, no longer sent |
| `X-NN-LLS` | NetNut, a long-session token that holds one exit, when the user name asks for one with `-nnid-0` |
| `X-Scrapoxy-Proxyname` | Scrapoxy, the name of the proxy rather than its address |
| `X-Crawlera-Slave`, in the response | Zyte Smart Proxy Manager |
| `peer_ip=` in `x-brd-debug`, in the response | Bright Data Web Unlocker and SERP API, with `-debug-full` |

Oxylabs, Decodo, IPRoyal, Webshare, Apify, Nimble, Evomi, DataImpulse, GeoNode,
Infatica, Rayobyte, PacketStream, Proxy-Cheap, Live Proxies, Storm Proxies,
Shifter, Proxy-Seller, ProxyEmpire, Froxy, MarsProxies, Proxyrack, Asocks,
anyIP, Byteful, Thordata, Zyte API, Crawlbase, ScraperAPI, ScrapingBee and
ScrapeOps document no such field: some send one on errors, and Byteful an ID
of the request rather than of the exit. Nor do Kookeey, IPFoxy and the IPIDEA
network, 922 S5, PIA S5, LunaProxy, PyProxy, IPIDEA and ABCProxy, which was
taken down in January 2026: each of them says to read the address off a
service that echoes it. Nor does an open-source forward proxy
as it comes: Squid, Tinyproxy, 3proxy, Privoxy, mitmproxy, goproxy, Envoy,
Caddy's forwardproxy, gost, glider, v2ray and Xray, sing-box, mihomo and Tor's
HTTP tunnel all answer `CONNECT` without one. Envoy can be set up to add one
with `response_headers_to_add` and `%UPSTREAM_LOCAL_ADDRESS%`, and a field of
your own then reads it. A proxy in front of another, as Squid with a
`cache_peer`, mitmproxy, gost, v2ray or mihomo are, answers `CONNECT` itself
and drops whatever the proxy behind it said.

A file laid over the table needs only what it changes. A field or a probe in it
replaces the table's of the same key, which is a field's `header`, in any case,
the answer it comes `in` and the `param` it reads, and a probe's `when` and
`path`; one with `"off": true` takes the table's out; the rest are added. The file's are read before
what is left of the table's, so where an answer holds both, the file's is
believed. [`example/exit-headers.json`](example/exit-headers.json) does each of
these:

```json
{
  "fields": [
    {"header": "X-Egress-IP", "value": "address", "country": "X-Egress-Country", "provider": "a proxy of one's own"},
    {"header": "x-brd-ip", "provider": "Bright Data"},
    {"header": "Node-Ip", "off": true}
  ],
  "probes": [
    {"when": "cf-ray", "path": "/cdn-cgi/trace", "off": true}
  ]
}
```

It adds a field the table does not have, replaces Bright Data's with one that
does not ask what a hash stands for, and takes out SOAX's field, with the
`Respond-With` every `CONNECT` said for it, and the Cloudflare probe.

`header` is the field, in any case. `value` is what it holds: `address`, an IP
address with or without a port after it, `hash`, the proxy's own hash of the
address, `name`, whatever else the proxy calls where the tunnel comes out, or
left out for an address or a hash. `0.0.0.0` and `::` say nothing, and an IPv4
address written as IPv6 is the IPv4 address. `param` is the parameter that
holds it when the field is `name=value` pairs separated by semicolons, as
`brd_ip` in `Proxy-Status`, in any of the items of a list of them separated
by commas, which a `Proxy-Status` two proxies wrote is; a semicolon or a comma
in quotes separates nothing. `country` and `country_param` are the field, and the parameter
of it, that name the tunnel's country. `in` is `response` for a field a proxy
that decrypts the traffic writes into the answer to the request; a site can
write one there as well, so it is believed only when the answer to `CONNECT`
said nothing. `ask` is header fields every `CONNECT` is to say, for a proxy
that answers with the field only when asked; they go to every proxy, and to
no site. `provider`, `source` and `note` are for whoever reads the file. A key
the file does not know, a `header`, `country` or `when` that no header field
can be called, an `ask` a `CONNECT` cannot say (one that frames it, such as
`Content-Length`, or the credentials, which come from the proxy's URL), a
`value` or `in` that is none of the ones above, two fields or two probes of
one key, an empty file, or more after the table ends the run before it
begins, so that a misspelled file is not silently ignored. A byte order mark
before the table is passed over.

When the proxy says nothing, or says only a name, the file can say what to
ask, and only where nothing but the same exit can answer:

- `probes` are asked of the site itself, over the very connection the request
  went out on. The example asks a site behind Cloudflare, one whose response
  came with `cf-ray`, for `/cdn-cgi/trace`, which every such site answers with
  `ip=` and `loc=`: where the request came from, and so where it came out. The
  answer is believed only when it came back over the same tunnel, which the
  tunnel's number says; over another it would be another exit's. A probe goes
  out on the connections of the site it asks, as a request with no browser
  context does ([GO.md](GO.md#browser-contexts)), which a request redirected
  there from another site went out on too. A script's request
  (`--request-kind fetch` or `xhr`) from a page of another site went out on
  the connections of the page's site, which is not the probed URL's, and one
  from a page of another origin of the URL's site on those of requests that
  carry no credentials, as such a request carries none: its probe goes
  through another tunnel, and is not believed.
- `resolve`, on a field, turns a name the proxy gave into the address: it asks
  `url` through the same proxy with a user name that says to go out through the
  exit of that name. The example asks Bright Data's `brdtest.com/myip.json`
  with `-ip-<hash>`, once for each hash.

Both are a request more, to the site or to the proxy's own service, and only
when a report is written or the requests are kept. A site behind Cloudflare
sees a visitor ask for `/cdn-cgi/trace`, which a browser does not; take the
probe out with `"off": true` if that matters more than the address. Nothing is asked
of anybody else on a connection of its own: the answer would be another
connection's. `--no-exit-lookup` makes neither, nor the lookup before the run:
what the proxy said is all that is known, a name it gave is shown as the name,
and a request it said nothing of came out somewhere nobody asked about. The
fields the file has a `CONNECT` say with `ask` are still said, being no
request of their own.

```json
{
  "fields": [{"header": "x-brd-ip", "resolve": {"user": "{user}-ip-{value}",
    "url": "https://brdtest.com/myip.json", "format": "json", "ip": "ip", "country": "country"}}],
  "probes": [{"when": "cf-ray", "path": "/cdn-cgi/trace", "format": "lines", "ip": "ip", "country": "loc"}]
}
```

`format` is `json`, an object, or `lines`, a `key=value` to a line, and `ip`
and `country` the keys that hold the address and the country. An address found
this way says how in the opened row of the report, in the log, as `by` in the
JSON report and as `exit_by` in the traces.

The value has to be what the field says before it is believed: a hash is
letters and digits only, at least sixteen of them, and a name has nothing in
it a terminal would take for an instruction. A proxy that will not say the
address and names it instead, as Bright Data does with a hash, is taken at its
word: the name is where the request came out, the same name being the same
address, and it is shown as it is, since there is no telling the address from
it. A proxy that says nothing, as most do, leaves where its requests came out
unknown, and the [report](#reporting-a-run) says so rather than guess. The
fields of the answer are in the report, in the log of every request kept with
`--output` and in the trace, so whether a proxy says anything can be read off
one run:

```bash
tls-forge fetch -o out/ --proxy http://user:pass@proxy.example:8080 https://example.com/
grep -A5 "answer to CONNECT" out/*.log
```

A SOCKS proxy's answer has no header fields, and through one where a request
came out is not known. Through an HTTP or HTTPS proxy HTTP/3 is off, as QUIC
cannot go through it.

##### Files a run reads and writes

Before it reads the list, empties a directory or opens a file, a run checks
every file its flags name together: what it reads (`--input`, `--cookies`,
`--exit-headers`), what it writes (`--trace`, `--log`, `--keylog`, `--report`,
`--save-cookies`), and the files its standard output and error are
redirected to. These are usage errors, with exit code 2 and the reason, before
anything is emptied, opened, made or asked:

- one file under two flags, when the run writes it for either: by the same
  name, through a symbolic link, by a hard link, or, on macOS and Windows, by
  a name that differs only in case. `--input urls.txt --trace urls.txt` would
  have read the list and written the trace over it. Two flags that only read a
  file may name it, and so may `--cookies` and `--save-cookies`, which start a
  session from a file and save it back there;
- a file the run writes that standard output or error is redirected to;
- a file that is the `--output` directory, or that the directory or another
  file would have to be made in;
- a file the run writes that is a directory, is named with a trailing
  separator, or would go in a directory that a file is in the way of.

What is in a directory `--clear-output-dir` is about to empty counts as gone,
since it will be by then. Every file a run writes goes in a directory made for
it if there is none, and is created with mode `0600`. A report and a session
are written beside their file and moved over it once whole, so one that fails
half way, or a disk that fills, leaves the one before it as it was; a symbolic
link where one goes is replaced rather than followed, and a device such as
`/dev/null` is written to as it is.

#### `capture`

Open an installed Chromium-based browser, record its TLS and HTTP behaviour and
optionally save a reusable profile. HTTP/1.1 and HTTP/2 are measured as two
independent cold top-level navigations, each using a fresh temporary browser
profile, so the transition between protocols cannot alter `Sec-Fetch-*`.

A browser tls-forge cannot launch — Firefox, Safari, a phone's — is measured
with `--manual`: tls-forge listens, and you open its page in that browser.

```bash
tls-forge capture
mkdir -p profiles && tls-forge capture --save profiles/
tls-forge capture --browser edge --headless --save edge.json
tls-forge capture --install
tls-forge capture --manual --install
tls-forge capture --manual --addr 0.0.0.0:8443 --host my-mac.local --save profiles/
```

Usage: `tls-forge capture [flags]`

| Flag | Meaning |
|---|---|
| `-b`, `--browser <name-or-path>` | `chrome`, `chromium`, `edge`, `brave`, or an executable path; auto-detected when omitted |
| `--headless` | Run without a window; TLS/HTTP structure remains useful for drift checks, but Chrome may expose `HeadlessChrome` and therefore differ in header values from a headed profile |
| `-s`, `--save <path>` | Save a profile; an existing directory gets `<name>/<platform>.json` |
| `--install` | Save into the user profile directory so `--profile local` can find it |
| `--set <NAME=VALUE>` | With `--save` or `--install`, a value the profile keeps of this machine, as its header carries it: `accept-language`, or a client hint of the machine's (`sec-ch-ua-platform-version`, `-arch`, `-bitness`, `-model`, `-wow64`, `-form-factors`); repeatable |
| `-n`, `--name <name>` | Override the profile name; otherwise derive it from the browser version |
| `-j`, `--json` | Print the raw capture instead of a human summary |
| `-t`, `--timeout <duration>` | Maximum browser measurement time; default `2m` |
| `--browser-arg <argument>` | Append a browser process argument; repeatable, mainly for CI environments |
| `--manual` | Wait for a browser you open the page in yourself, rather than launching one; `--timeout` is then ten minutes unless given |
| `--addr <host:port>` | With `--manual`, where to listen; default `127.0.0.1:0`. `0.0.0.0:8443` lets in a phone on this network |
| `--host <name>` | With `--manual`, the name the page is opened at, which its certificate is made for; default `localhost`. Not an address when a profile is kept: a browser names no server (SNI) to an address |

A profile keeps some of the machine it was captured on, which every request
with it says: the languages of the browser's person (`accept-language`), and,
for a Chromium browser, the client hints a server can ask for of the system's
version, the processor, the model and the form. `capture` lists them after it
saves a profile, and `--set` changes one, given as its header carries it:
`--set 'accept-language=de-DE,de;q=0.9' --set 'sec-ch-ua-platform-version="15.7.4"'`.
A hint the browser does not send, as Firefox and Safari send none, is not
given one: the profile is not kept.

The page asks the browser for every client hint a server can ask for, with a
`<meta http-equiv="Accept-CH">`, which applies to the page's own requests alone
and which no later visit carries, and the profile keeps what the browser sends
when asked: the user agent's and the system's above, and the device's (its
memory, its pixel ratio, the window's size), the network's (`rtt`, `downlink`,
`ect`) and its person's preferences (colour scheme, reduced motion and
transparency). `capture` says how many of them the browser sent.

Installed profiles live below the operating system's user configuration
directory. Set `TLSFORGE_PROFILES` to choose another directory. Running
`capture --install` again replaces the local machine profile after a browser
update.

##### Measuring a browser you open

`--manual` prints an address and waits for a browser to come to it, in four
steps the page itself walks you through:

1. Open the address in the browser to measure, typed or pasted.
2. It warns about the certificate, made for this run: accept it. The page then
   asks for one more visit.
3. Open the address again in a new tab, typed or pasted. That visit is the one
   measured.
4. The page then gives a second address, at a listener that offers HTTP/1.1
   alone: open it the same way, typed into a new tab, and again if the
   browser warns about the certificate there too, as Firefox does for another
   port. That visit measures the browser over HTTP/1.1, and the command ends
   with it; or finish without it on the page.

After the visit measured, its page opens 26 more connections to the server,
which ends each after its answer: their ClientHellos show what the browser
draws anew for every connection, the order of its extensions and the length of
its GREASE ECH payload, and the profile draws what was measured rather than
what the browser's name suggests. One of them is given a session ticket and
the next resumes it, and `capture` says whether the browser resumes as
tls-forge does. What a profile cannot say, an extension in some hellos only or
a resumption otherwise than tls-forge's, is said in the summary and kept in the
profile's notes. Measured on Chrome 155: its order drawn, a payload of 144,
176, 208 or 240 bytes, and resumed as tls-forge resumes.

The visit after the warning is not measured, because what a browser sends once
a person says yes to a certificate can be a reload of the refused page, which
is not what it sends when somebody opens an address. The visit measured has to
come on a connection of its own, so every answer outside a measurement ends
its connection; a visit that is a reload, comes from a link, or comes on a
connection that has carried another request is turned away with the reason,
and you can open the address again. Each browser has a first visit of its own,
told apart by its address and its user agent, so Firefox and Safari can be
measured one after the other.

For a phone, listen on the network and give the name the phone reaches this
machine by: `--addr 0.0.0.0:8443 --host my-mac.local`. An iPhone finds a
`.local` name by Bonjour; another phone needs a name your network's DNS knows.
Not the machine's address: a browser names no server (SNI) to an address, so
what it sends there would make a profile that names none to any site, and
`capture` refuses to keep one; without `--save` or `--install` it still shows
what the browser sent. Nothing on the server authenticates anybody, which the
command warns about; stop it once the phone has been measured. Without
`--host`, the address printed is `localhost`, which a phone cannot open, and
the command says so, with a name this machine may be reached by.

The profile is named after the browser and its version, `firefox_148`, and
filed under the platform its user agent says, which for a phone is not this
machine's: `safari_18/ios.json`, used as `--profile safari_18_ios`.
`--install` keeps it under that name rather than as `local`, so
`--profile firefox_148` then finds the Firefox measured here ahead of the
catalogue's handshake without headers. A Chromium browser is named by the
brand it names to scripts: Brave's user agent is Chrome's word for word, and
it is kept as `brave_155`; one that names no brand but Chromium's, as
`chromium_155`. `--install` keeps nothing under the name of a profile
tls-forge ships, `chrome_155_macos`: read before the shipped ones, it would
answer for that one from then on, and for `--profile chrome` too. Give it a
name of its own with `--name`, which is also how to replace a shipped one on
purpose. Measured over HTTP/1.1 by its own visit,
typed as the first was rather than sent there by the page, which would show in
what it sends, the profile has the browser's HTTP/1.1 as it spelt it; finished
without that visit, it has none, and a request that goes out over HTTP/1.1
with it uses the same headers in canonical spelling. `compare --manual` holds
a profile to the browser over HTTP/1.1 too when it was measured so.

#### `compare`

Measure an installed browser and the selected client profile against the same
local server, then print a field-by-field diff.

The browser is measured over both HTTP/1.1 and HTTP/2. HTTP/1.1 names are
compared with their exact wire casing; HTTP/2 remains lower-case as required by
the protocol. Profiles that predate the optional HTTP/1.1 section continue to
work with the historical fallback.

The ClientHello is compared field by field: the record layer, the versions, the
session id's length, the cipher suites and compression methods, the extensions
as a set, since Chrome shuffles them, each list an extension holds, the trust
anchor IDs, in their order when the browser sends them sorted, as Chrome 154
and later do, and the contents of every extension that is the same on each
connection. What the browser draws for each connection is compared by its shape
instead of its bytes: where GREASE goes, how long it is and which of its values
are one, the length of each key share, ECH's cipher suite and key, and the
identities and binders of `pre_shared_key`. Of the keys themselves, what a
server can check is compared too, as `keys`: that each key of `key_share` and
ECH's is a public key of its kind, as the browser's always is, and that keys
of one kind are each their own, as Chrome's three X25519 keys are. An X25519
key is below 2^255−19 with its top bit clear, of a point of the curve in the
group of prime order; a NIST curve's is a point of it; an ML-KEM key passes
FIPS 203's check. Bytes of the right length in a key's place match every
other field and fail this one. The length of the ECH payload,
which Chrome draws from four for every connection, is shown on a `~` line and
not compared. An extension no rule describes, sent by both with different
contents, is listed under `not checked`: it is neither a match nor a
difference, and the command exits `3`.

Captured profiles generate the GREASE ECH `enc` as a fresh X25519 public key
through uTLS's HPKE sender setup, rather than filling it with arbitrary bytes.
The payload is random, with the lengths above. This is GREASE ECH; it does not
establish successful ECH encryption or hide the server name. A client that
filled it with random bytes differs from Chrome in `keys` alone, as tls-forge
did before 6f819a7.

Over HTTP/2 the comparison covers the SETTINGS in order, the connection's
WINDOW_UPDATE, PRIORITY frames and the priority on HEADERS, the pseudo-header
order and values, and every other field with its value, in order. It also
reads the frames as they went, which the echo server keeps up to the end of
the first request's header block: which frames came, in what order and with
which flags, acknowledgements aside, and how each field was written in HPACK,
indexed or not, its name from which table, each string Huffman-coded or not.
Over HTTP/1.1 it covers the request's method and version, and every field in
order with its spelling and value. The page asked for and the name the server
was reached by are not compared: the values of `:path`, `:authority` and
`Host`, and the target of the request line. How `:path` was written is
compared on a line of its own, and shown on a `~` line when the page is one
the static table holds whole, such as `/`, which every client writes alike.

The output begins with what was measured: the browser's build and platform,
as it says them, how it was run, and which of its requests were compared,
protocol by protocol. `--json` carries the same as `measured`, the rule each
field was compared by as `manifest`, and both captures with the hello and the
HTTP/2 frames as they went.

```bash
tls-forge compare
tls-forge compare --profile chrome_151 --headless
tls-forge compare --json > comparison.json
tls-forge compare --manual --profile firefox_148
```

With `--manual` the browser is one you open the page in, as for
[`capture --manual`](#measuring-a-browser-you-open), and the comparison covers
TLS and HTTP/2: the browser is not measured over HTTP/1.1, so the client's
HTTP/1.1 is not held to it, and the output says so.

Usage: `tls-forge compare [flags]`

| Flag | Meaning |
|---|---|
| `-p`, `--profile <name-or-path>` | Profile to check; default `chrome` |
| `-b`, `--browser <name-or-path>` | Browser to measure; auto-detected when omitted |
| `--headless` | Run the browser without a window |
| `-j`, `--json` | Print both captures and the comparison as JSON |
| `-c`, `--color <mode>` | `auto`, `always` or `never`; default `auto`. In `fetch`, `-c` is `--concurrency`; the long names say the same in both |
| `-f`, `--full` | Do not trim matching values; differences are always printed in full |
| `-t`, `--timeout <duration>` | Maximum browser measurement time; default `2m` |
| `--browser-arg <argument>` | Append a browser process argument; repeatable |
| `--manual`, `--addr`, `--host` | Compare with a browser you open the page in; as for `capture` |

Exit codes are meaningful:

| Code | Meaning |
|---|---|
| `0` | Browser and client match on every compared field |
| `3` | Measurement succeeded, but fingerprints differ, or something could not be compared |
| `1` | Comparison could not be completed |
| `2` | Invalid arguments or help output |

#### `profiles`

List profiles from the local profile directory, profiles embedded in this
binary and compatible profiles from the underlying transport catalogue.

```bash
tls-forge profiles
```

Usage: `tls-forge profiles`. This command has no flags.

Profile names can be passed to `--profile`. A JSON profile path is also
accepted directly:

```bash
tls-forge fetch --profile ./profiles/my-chrome.json https://example.com/
```

A name from the transport's catalogue — `firefox_148`, `safari_ios_18_5`,
`okhttp4_android_13` — brings a handshake and HTTP/2 settings and no headers:
the transport has never claimed to know what headers a browser sends. A
request with one carries only the headers given with `-H`, and no `User-Agent`
unless one of them is; never the transport's own `Go-http-client`, which would
say what is talking more plainly than any handshake could hide it. The run
says so in its header. To wear Firefox or Safari whole, measure it with
`capture --manual`.

#### `proxy`

Run an intercepting HTTP/HTTPS proxy. It terminates incoming TLS and creates a
new outbound connection with the selected browser fingerprint. A normal
CONNECT tunnel cannot replace a fingerprint because it passes the caller's TLS
bytes through unchanged.

```bash
tls-forge proxy
export HTTPS_PROXY=http://127.0.0.1:8080
curl --proxy http://127.0.0.1:8080 \
  --cacert "/path/printed/by/tls-forge" https://example.com/
```

The command prints the exact certificate path. Its default follows the OS user
config directory: usually `~/.config/tls-forge/ca.pem` on Linux,
`~/Library/Application Support/tls-forge/ca.pem` on macOS, and
`%AppData%\tls-forge\ca.pem` on Windows.

Usage: `tls-forge proxy [flags]`

| Flag | Meaning |
|---|---|
| `-p`, `--profile <name-or-path>` | Profile used for outbound requests; without one, the browser measured on this machine (`local`) when there is one, else `chrome` |
| `-x`, `--proxy <url>` | Optional upstream proxy |
| `--proxy-env <name>` | Read the upstream proxy from this environment variable, such as `TLSFORGE_PROXY`, instead |
| `-t`, `--timeout <duration>` | How long each outbound request may take, all of it; default `30s` |
| `-k`, `--insecure` | Skip certificate verification on outbound connections |
| `-a`, `--addr <host:port>` | Listen address; default `127.0.0.1:8080` |
| `--ca-cert <file>` | CA certificate; generated in the user config directory by default |
| `--ca-key <file>` | Matching CA private key |
| `-q`, `--quiet` | Suppress per-connection error messages |
| `--max-request-body <bytes>` | Largest request body buffered by the proxy; default `16777216` (16 MiB) |

The proxy deliberately has no cookie jar; it forwards the caller's `Cookie`
header. Fields that describe a connection rather than what goes over it are
not passed from one to the other, in either direction: `Connection`,
`Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
`Proxy-Connection`, and every field a `Connection` names, as well as
`Proxy-Authorization`. An answer's fields are written in the order of their
names. An answer to `HEAD` keeps the length a `GET` would have had and has no
body, and a 204 or a 304 has neither. A request to upgrade to another
protocol, a WebSocket among them, is answered 501 and its connection ended,
rather than sent on as an ordinary request. A request inside a `CONNECT`
tunnel goes to the host and port the `CONNECT` named, whatever port its own
`Host` leaves out; one that names another host or another port is answered 421
and goes nowhere. What a client sends behind its `CONNECT` without waiting for
the answer is the start of the tunnel. The generated CA can impersonate any site to a client that trusts it.
Prefer trusting it only for the specific process, keep the private key secret,
and remove that trust when the proxy is no longer needed. The proxy does not
authenticate incoming clients: a non-loopback `--addr` must be protected by a
firewall or authenticated tunnel. The certificate and key must either both
exist and match or both be absent. Incoming connections expire after 30 seconds
without any read or write progress. A request's header has 10 seconds from its
first byte to arrive, and one longer than 1 MiB is answered 431; the TLS
handshake in a tunnel has 10 seconds in all. A body has no such time, only the
30 seconds of each read, so a large upload on a slow link goes through. At most
1024 connections are served at once, and the next waits to be accepted until
one of them ends. The generated leaf-certificate cache is limited to 1024
hostnames.

#### `serve`

Run the local HTTPS measurement server independently. `/` contains the browser
capture page; `/api/all` returns the current connection's TLS and HTTP
fingerprint as JSON.

```bash
tls-forge serve
tls-forge serve --addr 0.0.0.0:8443
curl -k https://localhost:8443/api/all
```

Usage: `tls-forge serve [flags]`

| Flag | Meaning |
|---|---|
| `-a`, `--addr <host:port>` | Listen address; default `127.0.0.1:0` chooses an available port |
| `--host <hostname>` | Hostname used in the URL, certificate and SNI; default `localhost` |
| `--session-tickets` | Enable TLS session resumption; disabled by default because resumption changes the fingerprint |

The certificate is generated for each run, so test clients must trust it or
explicitly disable verification for this local endpoint. The server does not
authenticate incoming clients; the CLI warns when `--addr` exposes it beyond
loopback. A connection that makes no read or write progress for 30 seconds is
closed. The TLS handshake has 10 seconds in all, and a request 10 seconds from
its first byte: over HTTP/1.1 the whole of it, over HTTP/2 each frame, and a
stream whose request has not ended by then is reset. An HTTP/2 connection with
no stream open for 30 seconds is told `GOAWAY`, however busy its client keeps
it. At most 128 connections are served at once, and the next waits to be
accepted until one ends. The server keeps the latest 128 connections, pages
served, captures nobody has waited for, and visitors a manual capture trusts.

HTTP/1.1 is read as RFC 9112 has it, and no further. A request the server
cannot read whole is answered with the status that says why, and the reason,
before its connection closes: 400 for a space before a header's colon, a header
continued on the next line, a carriage return inside a line or a length that
is not digits; 413 for a body over 64 KiB; 414 and 431 for a line over 8 KiB,
more than 100 header lines, or header lines over 64 KiB in all; 417 for an
expectation other than `100-continue`; 501 for `Transfer-Encoding`; 505 for a
version other than HTTP/1. A client that sends `Expect: 100-continue` is told
to go on before its body is read. `Connection: close`, or HTTP/1.0 without
`Connection: keep-alive`, closes the connection after the answer.

HTTP/2 keeps to what the client said: an answer goes as its flow-control
windows open, and the server's header blocks fit the header table it allows.
A connection has at most 100 streams open and 512 KiB held for them at once;
a stream past either is refused with `REFUSED_STREAM`, and one the client
resets is let go at once. A header list over 64 KiB is answered 431 and a
body over 64 KiB 413, and a stream that breaks the protocol is reset while the
others go on. A frame over 16 KiB, a header block that cannot be decoded, a
setting out of range, or a window past 2^31-1 ends the connection with a
`GOAWAY` that says why. Request trailers are read and dropped.

#### `daemon`

Run one long-lived client behind a JSON Lines protocol. This is the transport
used by the Node.js and Python SDKs.

```bash
echo '{"id":1,"url":"https://example.com/"}' | tls-forge daemon
```

Usage: `tls-forge daemon [flags]`

| Flag | Meaning |
|---|---|
| `-b`, `--cookie name=value` | Seed one cookie; repeatable |
| `--cookies <file>` | Load a warmed session |
| `--cookie-set <id>` | Select a set from the cookie file |
| `-p`, `--profile <name-or-path>` | Profile to impersonate; without one, the browser measured on this machine (`local`) when there is one, else `chrome` |
| `-x`, `--proxy <url>` | Upstream proxy |
| `--proxy-env <name>` | Read the upstream proxy from this environment variable, such as `TLSFORGE_PROXY`, instead |
| `--proxy-stdin` | Read the upstream proxy from the first line of standard input, the init line, as the Node.js and Python packages do; see [the protocol](docs/protocol.md#the-init-line) |
| `-t`, `--timeout <duration>` | How long each request may take, all of it; default `30s` |
| `-k`, `--insecure` | Skip certificate verification |

One request object is read per line:

```json
{"id":1,"method":"POST","url":"https://example.com/api","headers":{"content-type":"application/json"},"order":["content-type"],"body":"{\"a\":1}","setCookie":["session=abc"]}
```

The response repeats `id` and contains `status`, final `url`, `body`,
multi-valued `headers`, `cookies`, and `error` when the request failed. An
input line is read when it is at most 16 MiB, its newline included; a longer
one ends the daemon, as described in [the protocol](docs/protocol.md).
Requests are processed sequentially so one daemon remains one browser identity
and one cookie jar.

#### `version`

Print the version stamped into the binary:

```bash
tls-forge version
```

Usage: `tls-forge version`. This command has no flags. A source build without
version linker flags reports `dev`.

#### Exit codes and the environment

Every command ends with one of four codes:

| Code | Meaning |
|---|---|
| `0` | It did what it was asked. `proxy`, `serve` and `daemon` end with it when they are told to stop |
| `1` | It could not do all of it: a request that got no response, a page without what `--wait-for` or `--wait-for-element` asks for, a report, trace, log or session that could not be written |
| `2` | What it was given cannot run, said before anything is done; `-h` and `--help` too |
| `3` | `compare` measured, and the client and the browser differ |

What tls-forge reads from its environment:

| Variable | What it does |
|---|---|
| the one `--proxy-env` names | The proxy, for `fetch`, `proxy` and `daemon` |
| `NO_COLOR` | Set to anything, turns colour off |
| `TLSFORGE_PROFILES` | Where the profiles measured on this machine are kept, instead of the config directory |
| `XDG_CONFIG_HOME`, `HOME`, `AppData` | Where the config directory is, as the platform has it: the proxy's authority and the measured profiles |
| `GODEBUG=http2debug=2` | Adds each HTTP/2 header field the transport decoded to a run's log, its secret values left out; the frames are there at the `trace` level without it |
| `TLSFORGE_BIN` | For the Node.js and Python packages, the binary to run |

tls-forge reads no `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` or `NO_PROXY`, in
either case. A run goes through the proxy `--proxy` gives, or the one in the
variable `--proxy-env` names, and through none otherwise. Those variables are
how another program, a browser or `curl`, is pointed at `tls-forge proxy`.

### Language libraries

The root README intentionally contains only a working introduction for each
SDK. Every language has its own detailed API document with all constructor and
request options, response fields, lifecycle rules and failure behaviour.

#### Go

```bash
go get github.com/Sec-CH-Lemon/tls-forge
```

```go
package main

import (
	"fmt"
	"log"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

func main() {
	client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	res, err := client.Get("https://tls.browserleaks.com/json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.Status, res.Text())
}
```

See the complete [Go library documentation](GO.md).
The runnable consumer project is in [`example/go/`](example/go/).

#### Node.js

```bash
npm install tls-forge
```

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome' });
try {
  const res = await client.get('https://tls.browserleaks.com/json');
  console.log(res.status, res.body);
} finally {
  client.close();
}
```

See the complete [Node.js SDK documentation](node/README.md). The package
ships its TypeScript types. The runnable consumer projects are in
[`example/node/`](example/node/) and, in TypeScript,
[`example/typescript/`](example/typescript/).

#### Python

```bash
pip install tls-forge
```

```python
import tlsforge

with tlsforge.Client(profile="chrome") as client:
    response = client.get("https://tls.browserleaks.com/json")
    print(response.status, response.json())
```

See the complete [Python SDK documentation](python/README.md).
The runnable consumer project is in [`example/python/`](example/python/).

## Troubleshooting

- **A command exits 2 and says `bad usage`.** What it was given cannot run, and
  nothing was done: the message names the flag or the value. `--help` lists
  every flag.
- **`fetch` prints nothing but a line on a terminal.** The page is the output,
  and a terminal gets it only with `--print-body`. A pipe or a redirect gets it
  without one.
- **A program behind `tls-forge proxy` refuses its certificates.** The proxy
  signs every site with its own authority, whose certificate path it prints on
  start: the program has to trust that certificate.
- **`capture` or `compare` finds no browser.** Name one with `--browser`, by
  name or by the path of its executable, or open the page in one yourself with
  `--manual`.
- **A Node.js or Python request fails with `SessionReset`.** The transport the
  session was in has gone, and its cookies with it. The request was not sent:
  warm the session again, or keep it in a cookie file.
- **A site still turns the requests away.** A fingerprint is not all a site
  looks at: tls-forge runs no JavaScript, defaults to HTTP/1.1 or HTTP/2, and the TCP/IP
  packets under each connection are this machine's operating system's.
  [docs/support.md](docs/support.md) says what is reproduced and what is not,
  and `tls-forge compare` holds this client to the browser on this machine.

## Limitations

The handshake and the headers are not all that gives a client away, and
tls-forge does not reproduce everything else. It does not run
JavaScript, load a page's subresources or solve challenges, and
the TCP/IP packets under every connection are this machine's operating
system's. Redirects are followed as Chrome follows them, and a form's POST,
`fetch()` and an XHR go out as Chrome sends them, CORS, mixed content and the
client hints a server asked for and all, when a request says it is one
([GO.md](GO.md#browser-contexts)).
[docs/support.md](docs/support.md)
lists what is reproduced, how each part is checked, and where it is known not
to be.

The Go SDK can explicitly enable the experimental HTTP/3 transport through
`WithTransportOption(tls_client.WithProtocolRacing())`. It races connection
establishment and sends the request once over the selected transport. The
Chrome policy applies measured QUIC TLS 1.3 vectors and initial receive
windows. The current QPACK decoder is stateless: table capacity and blocked
streams remain zero, and nonzero configurations are refused. H3 ALPS
bootstrap is unavailable and is not advertised. QUIC transport parameters, QPACK compression,
discovery and complete lifecycle behavior still have differences; enabling
this option does not establish a Chrome-equivalent H3 fingerprint.

For Chrome profiles, selected local TLS protocol failures receive one bounded
connection retry before any HTTP is sent. This does not retry a failed
certificate check, cancellation or an application request. The CLI's
`--retry` separately controls further request attempts.

## Development

```bash
make test         # Go race tests
make cover        # 100% Go statement coverage gate
make node-test    # 100% Node line/function/branch coverage gate
make python-test  # 100% Python statement/branch coverage gate
make python-typecheck # the Python package's types, mypy in strict mode
make docs-check   # every relative link in the documentation leads somewhere
make generated-check # gofmt, tidy modules, report.css and notices as made
make workflows-check # every action a workflow uses pinned to a release commit
make wrapper-smoke # Node and Python against the real Go daemon
make release-test # the release scripts, at 100% line/function/branch coverage
make vet
make lint
make check        # all of the above
make dist         # the release set a tag would build, in dist/set
```

Published releases have a second, registry-facing gate. The
[`published e2e`](.github/workflows/published-e2e.yml) workflow installs an
exact version of the Go, npm and PyPI distributions on Linux, macOS and Windows,
makes a real request through each SDK, runs both architectures of the GHCR
image, and checks the current stable Homebrew formula on macOS. It runs only
when a maintainer starts it from the Actions page or from the command line:

```bash
gh workflow run published-e2e.yml \
  --ref main \
  -f version=0.1.0 \
  -f check_brew=true
```

Homebrew exposes one current stable formula, so disable `check_brew` when
verifying a prerelease or an older version after the tap has moved forward.

Whether tls-forge still matches the Chrome people run is asked every Monday by
the [`drift`](.github/workflows/drift.yml) workflow. It compares the shipped
profile with Google Chrome Stable and proposes a fresh one in a pull request
when they differ. It also measures every fixture of the bench again, on Stable
and on Beta, on macOS, where they were measured, and on Linux and Windows, for
which profiles are shipped too, and files an issue for each platform, channel
and major when what Chrome does differs from them in the same scenario twice
running (what one run alone has is the runner's, and files nothing): which
connection a request goes on, what it sends, its HPACK, TLS records, ALPS,
WINDOW_UPDATEs, URLs, charsets, extension order and False Start. What a build's
version and platform decide, `sec-ch-ua` and the length it gives an HTTP/1.1
head, is the profile's, and not a difference there. A fixture the browser
cannot be measured against is a difference of its own, and the rest are
measured all the same; a scenario Chrome does otherwise on the platform it
runs on, as Negotiate on Windows, is passed over there, saying so. Start it by
hand with `gh workflow run drift.yml`, which files nothing unless given `-f
file=true`, runs one half alone with `-f profile=false` or `-f
behaviour=false`, and measures only some runners or channels with `-f
os='["windows-latest"]' -f channels='["beta"]'`, and only some fixtures and
scenarios with `-f fixtures=connections -f only=conn-fetch,conn-resume`
(measure's flags and `--only`; CI minutes are limited), or hold the browser on
your machine to the fixtures:

```bash
go run ./internal/harness/measure --browser PATH --check --newer
```

Where Chrome's sandbox cannot start, as on a hosted runner's Linux or Windows,
add `--browser-arg=--no-sandbox`: without it Chrome loads no page and says
nothing.

Release and maintenance documentation:

- [`CHANGELOG.md`](CHANGELOG.md) — user-visible changes;
- [`RELEASING.md`](RELEASING.md) — release process;
- [`docs/profiles.md`](docs/profiles.md) — capture format and profile resolution;
- [`docs/protocol.md`](docs/protocol.md) — JSON Lines daemon protocol;
- [`docs/pinned.md`](docs/pinned.md) — the Google Chrome a release is held to, and the check;
- [`example/`](example/) — runnable Go, Node.js, Python and CLI examples.

## Licence and attribution

The project is licensed under the
[Apache License 2.0](LICENSE). Redistributed source or binaries must retain the
required licence and attribution notices described by that licence.

- [`NOTICE`](NOTICE) contains the project's copyright and attribution notice.
- [`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt) contains licences and
  notices for dependencies linked into distributed binaries.

The captured ClientHello and browser profile fixtures are measurements of
Chrome's protocol output; they do not contain Chrome source code. The project is
not affiliated with or endorsed by Google or Cloudflare.

Use the software only on systems and traffic you are authorised to access.


### Experimental Chrome HTTP/3 CID and receive policy

The local four-fork workspace applies the measured Chromium policy to captured
Chrome profiles when `WithProtocolRacing` selects HTTP/3: one UDP socket per
connection, an 8-byte original destination CID and an empty source CID. It accepts
1472-byte UDP payloads without changing the 1250-byte Initial or the conservative
transmit MTU. Its DATAGRAM frame limit is 65536; every frame still has to fit the
negotiated QUIC packet/path limit. The active peer-CID limit is 2 and the ACK timer
includes a 1 ms margin within the default 25 ms advertised limit; both default-valued
parameters are omitted. Complete transport-parameter TLVs are shuffled and their
GREASE identifiers are freshly drawn from the full reserved 62-bit family.

The CID shape and these initial limits do not establish migration, loss recovery,
HTTP/3 discovery, dynamic QPACK, ALPS bootstrap, compatible version negotiation or
Google-specific connection-option parity. Missing backend APIs remain open. See
the shared browser knowledge base for exact source/build and paired wire evidence.


### Experimental HTTP/3 version information

Captured Chrome's H3 policy uses QUIC v1 and advertises transport parameter
`version_information` (17): chosen version 1, plus v1 and one freshly drawn reserved
version in the compatible list. Generic parsing follows RFC9368: malformed information is a transport parameter
error and a chosen/packet-version disagreement is a version-negotiation error.
The captured-Chrome policy reproduces two measured Chrome155 deviations: it
accepts a zero Available Version and uses PROTOCOL_VIOLATION(0x0a) for invalid
version information. A zero Chosen Version is still refused;the actual selected
version must remain v1. Typed errors retain their original codes. Missing server information is allowed on this fresh
v1 connection. The policy rejects v2 or multi-version configurations before
opening a socket and does not advertise cross-version negotiation support.

Google option `ORIG` in parameter 12584 requests the HTTP/3 ORIGIN experiment.
It does not describe the original destination CID. The current H3 backend lacks
an ORIGIN consumer and corresponding authorized connection-pooling path, so the
option remains unadvertised and those scenarios remain open. Dynamic QPACK and
H3 ALPS bootstrap also remain open until their required APIs exist.
