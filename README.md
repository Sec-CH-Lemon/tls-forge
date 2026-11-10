# TLS Forge

`tls-forge` is an HTTP client and command-line tool for making requests with a
real browser's network fingerprint. A measured profile controls the TLS
ClientHello, JA3/JA4-relevant fields, HTTP/1.1 header casing and order, HTTP/2
and HTTP/3 settings, pseudo-header order, regular header order and browser
headers as one coherent identity.

Use it when an ordinary Go, Node.js or Python HTTP client is rejected because
its network stack does not match the browser named by its `User-Agent`.
`tls-forge` can be used as:

- a standalone CLI for one request or a list of them;
- an intercepting proxy for an existing program;
- a Go library;
- a Node.js or Python SDK backed by the same Go transport;
- a local measurement tool for capturing and comparing browser fingerprints.

It does not execute page JavaScript, load subresources or solve managed
challenges and CAPTCHAs. It addresses the TLS and HTTP fingerprint checks that
happen before, or alongside, normal HTTP handling. With the shipped profiles
each request is a fresh browser instance: redirects and retries share state
only inside that request.

**Documentation:** installation, guides, integrations and generated API and CLI
references are in [`docs/`](docs/index.md) and at <https://tls-forge.com/docs/>.

**Release status:** this README describes engine **2.0.0**, not yet
released. The latest release, which the release binaries, Homebrew, npm, PyPI
and Docker install, is 1.0.1 (Go module path without `/v2`). See
[release status](docs/support/release-status.md).

## What is a TLS fingerprint?

Before an HTTPS client can send `GET`, headers or a `User-Agent`, it sends a TLS
ClientHello. That message exposes choices made by its networking stack,
including:

- supported TLS versions and cipher suites;
- extensions and their order;
- supported groups, key shares and signature algorithms;
- GREASE values and ALPN protocols;
- session-resumption, application-settings and Encrypted Client Hello
  behaviour.

Servers can retain the complete structure or reduce it to identifiers such as
JA3 and JA4. The negotiated HTTP protocol adds more signals: exact HTTP/1.1
header casing and order, or HTTP/2 and HTTP/3 SETTINGS, window updates,
pseudo-header order, normal header order and values.

Changing only `User-Agent` is therefore insufficient. Node.js and Python
normally use OpenSSL, Go uses `crypto/tls`, while Chrome uses BoringSSL. Their
handshakes differ before the server sees any HTTP header.

Cloudflare uses these signals in its bot-detection products. Cloudflare Bot
Management exposes JA3 and JA4 fingerprints as request fields that can be used
in WAF custom rules, Transform Rules and Workers; see Cloudflare's official
[JA3/JA4 fingerprint documentation](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/).

The profiles in this project are measurements, not hand-written guesses: Chrome
151 to 157 on macOS, Linux and Windows. The `chrome` alias selects the newest,
Chrome 157, for the host platform; pin an exact name such as
`chrome_157_macos` when the identity must stay fixed. `tls-forge compare`
measures a real browser and this client against the same local echo server and
reports every difference it finds.

## Install

A Chromium-based browser is required only for `capture` and `compare`.
Fetching, proxying and the language SDKs do not require a browser.

### Release binary

Prebuilt binaries are published for macOS and Linux on arm64 and x86-64, and
Windows on x86-64. Download the archive for your platform from
[GitHub Releases](https://github.com/Sec-CH-Lemon/tls-forge/releases), extract
it and place `tls-forge` (or `tls-forge.exe`) on `PATH`:

```bash
mkdir -p ~/.local/bin
install -m 0755 tls-forge ~/.local/bin/tls-forge
tls-forge version
```

Each release after 0.2.2 carries `SHA256SUMS`, and GitHub keeps signed
provenance for every file of it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
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

With Go 1.27.3 or newer:

```bash
go install github.com/Sec-CH-Lemon/tls-forge/v2/cmd/tls-forge@latest
```

The binary is written to `$(go env GOPATH)/bin` unless `GOBIN` is set.

### Docker

Release images are published for `linux/amd64` and `linux/arm64`:

```bash
docker run --rm ghcr.io/sec-ch-lemon/tls-forge \
  fetch --print-body https://tls.browserleaks.com/json
```

Mount a directory when a command reads or writes files:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sec-ch-lemon/tls-forge \
  fetch --input /work/urls.csv --output /work/out > results.jsonl
```

The image runs as the user `tlsforge` in `/work`, not as root; a mounted
directory has to be writable by that user, or pass
`--user "$(id -u):$(id -g)"`. `capture` and `compare` are not supported in the
image, which contains no browser.

## Build from source

Requirements: Go 1.27.3 or newer, and Git and Make for the standard build.

```bash
git clone https://github.com/Sec-CH-Lemon/tls-forge.git
cd tls-forge
make build
./bin/tls-forge version
```

`make build` writes `bin/tls-forge` and stamps its version. Go uses cgo where
it finds a C compiler; without a working one, build with `CGO_ENABLED=0 make
build`. A plain `go build -o tls-forge ./cmd/tls-forge` reports version `dev`.
A release-style static build, and cross-compilation, need no external
toolchain:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v2.0.0" \
  -o tls-forge ./cmd/tls-forge

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -o tls-forge.exe ./cmd/tls-forge
```

To build the container image:

```bash
docker build -t tls-forge .
docker run --rm tls-forge version
```

Run all project checks before distributing a build:

```bash
make check
```

## Verify the fingerprint

If a Chromium-based browser is installed, start with:

```bash
tls-forge compare
```

The command measures the browser and the selected profile locally, then compares
TLS, JA4, HTTP/2 settings, header order and header values. A matching result is
stronger than checking only a JA3 or JA4 hash. See
[capture and compare](docs/guides/capture-compare.md).

## Commands

```text
tls-forge <command> [flags]
```

| Command | Purpose |
|---|---|
| [`fetch`](#fetch) | Make requests with a browser fingerprint: one URL, or a list |
| [`capture`](#capture) | Measure an installed browser and optionally save a reusable profile |
| [`compare`](#compare) | Compare a profile with an installed browser |
| [`profiles`](#profiles) | List available profiles |
| [`proxy`](#proxy) | Re-send requests from another program using the selected fingerprint |
| [`serve`](#serve) | Run the local TLS/HTTP fingerprint echo server |
| [`daemon`](#daemon) | Expose the client as a JSON Lines transport |
| [`version`](#version) | Print the build version |

Run `tls-forge <command> --help` for every flag of a command; the
[CLI reference](docs/reference/cli.md) lists them all. Durations use Go syntax
such as `500ms`, `30s` or `2m`. When no profile is selected, the network
commands use `chrome`: the newest Chrome, shipped or kept on this machine. A
browser measured here with `capture --install` is used when it is named, as
`--profile local`.

Every command ends with one of four codes:

| Code | Meaning |
|---|---|
| `0` | It did what it was asked; `proxy`, `serve` and `daemon` also when told to stop |
| `1` | It could not do all of it: a request that got no response, a page without what `--wait-for` asks for, a file that could not be written |
| `2` | What it was given cannot run, said before anything is done; `--help` too |
| `3` | `compare` measured, and the client and the browser differ |

tls-forge reads no `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` or `NO_PROXY`: a run
goes through the proxy `--proxy` gives, or the one in the variable
`--proxy-env` names, and through none otherwise.

### `fetch`

Make requests and write each page to standard output. A terminal gets only a
line saying how the request went, unless `--print-body` is given; a pipe or a
file gets the page.

```bash
tls-forge fetch --print-body https://tls.browserleaks.com/json
tls-forge fetch https://example.com/ > page.html
tls-forge fetch -X POST -H "Content-Type: application/json" \
  -d '{"hello":"world"}' https://example.com/api
tls-forge fetch --input urls.csv --concurrency 8 > results.jsonl
tls-forge fetch --retry 2 --wait-for-element '#price' -o out/ --report https://example.com/
tls-forge fetch --random-profile --input urls.txt > results.jsonl
```

Usage: `tls-forge fetch [flags] [url...]`. The flags, by group:

| Group | Main flags |
|---|---|
| What to fetch | URLs as arguments, `--input FILE`, `-u`/`--urls a,b,c`, `-F`/`--format auto\|lines\|json\|csv` |
| The request | `-X`, `-H "Name: value"`, `-d`; `--request-kind navigation\|form\|fetch\|xhr` with `--initiator-url` and `--clicked`, or `--form`, to send a request as a page would |
| Fingerprint and transport | `-p`/`--profile`, `--random-profile`, `-t`/`--timeout`, `-k`/`--insecure`, `--dns-server` |
| Proxy | `-x`/`--proxy`, `--proxy-env NAME`, `--exit-lookup`, `--exit-headers FILE` |
| Session | `-b name=value`, `--cookies FILE`, `--cookie-set`, `--save-cookies FILE` |
| Running | `-c`/`--concurrency`, `--retry`, `--retry-as-browser`, `--repeat`, `--wait-for TEXT`, `--wait-for-element SELECTOR` |
| Output | `-o`/`--output DIR` (every request's page, log and trace), `--clear-output-dir`, `--pcap`, `-i`, `--json`, `--print-body`, `-v` |
| Report, trace and log | `-R`/`--report`, `--trace FILE`, `--log FILE`, `--log-level`, `--keylog FILE` |

A list is one URL a line, a JSON array, or a CSV with `url` and `proxy`
columns, each entry with its own proxy where it names one.
`--random-profile` draws a profile for each request from every browser profile
this build can wear, and each result line says which it wore. `--pcap` and
`--keylog` keep the TLS secrets Wireshark opens a run with, so whoever has the
file reads every connection. The guides cover each in full:
[requests](docs/guides/requests.md),
[browser contexts](docs/guides/browser-context.md),
[lists](docs/guides/batch.md), [proxies](docs/guides/proxies.md),
[cookies](docs/guides/cookies.md),
[retries and page checks](docs/guides/retries.md) and
[output and diagnostics](docs/guides/diagnostics.md).

### `capture`

Open an installed Chromium-based browser, record its TLS and HTTP behaviour
and optionally save a reusable profile. `--manual` measures a browser you open
the page in yourself, which nothing here can launch: Firefox, Safari, a phone's.

```bash
tls-forge capture
tls-forge capture --browser edge --headless --save edge.json
tls-forge capture --install
tls-forge capture --manual --addr 0.0.0.0:8443 --host mymac.local --save phone.json
```

`--install` keeps the profile in this machine's profile directory
(`TLSFORGE_PROFILES` chooses another), where `--profile` finds it by name and
the network commands use it by default.

### `compare`

Measure an installed browser and the selected profile against the same local
server, then print a field-by-field diff; exit code `3` when they differ.

```bash
tls-forge compare
tls-forge compare --profile chrome_155_macos --headless
tls-forge compare --json > comparison.json
```

A headless browser says `HeadlessChrome` in its `User-Agent`, which a headed
profile does not; the rest of the structure compares all the same.

### `profiles`

List the profiles measured on this machine, those shipped in this binary and
those of the underlying transport's catalogue, which carry a handshake but no
headers of their own.

```bash
tls-forge profiles
tls-forge fetch --profile ./profiles/my-chrome.json https://example.com/
```

A profile pins the engine major it was made for, and one of another is refused
before anything is sent; see [profiles and compatibility](docs/guides/profiles.md).

### `proxy`

Run an intercepting HTTP/HTTPS proxy. It terminates incoming TLS and makes a
new outbound connection with the selected browser fingerprint. A normal
CONNECT tunnel cannot replace a fingerprint because it passes the caller's TLS
bytes through unchanged.

```bash
tls-forge proxy
curl --proxy http://127.0.0.1:8080 \
  --cacert "/path/printed/by/tls-forge" https://example.com/
```

The command prints the path of the certificate authority it signs every site
with, which HTTPS clients have to trust. That authority can impersonate any
site to a client that trusts it: trust it only for the process that needs it,
keep its key secret, and remove the trust when done. The proxy does not
authenticate its clients, so a non-loopback `--addr` must be protected by a
firewall or an authenticated tunnel. See the [local proxy](docs/integrations/proxy.md).

### `serve`

Run the local HTTPS measurement server: `/` is the browser capture page and
`/api/all` returns the current connection's TLS and HTTP fingerprint as JSON.

```bash
tls-forge serve --addr 127.0.0.1:8443
curl -k https://localhost:8443/api/all
```

Its certificate is made for each run, so a client has to trust it or skip
verification for this local endpoint.

### `daemon`

Run one long-lived client behind a JSON Lines protocol on standard input and
output: the transport the Node.js and Python SDKs use.

```bash
echo '{"id":1,"url":"https://example.com/"}' | tls-forge daemon
```

Each answer repeats the request's `id` and carries `status`, the final `url`,
`body`, `headers`, `cookies`, and `error` when the request failed.
`--proxy-stdin` takes the proxy URL from the first line instead of the command
line. See the [daemon protocol](docs/integrations/daemon.md).

### `version`

Print the version stamped into the binary:

```bash
tls-forge version
```

## Language libraries

Every language has its own document with every option, response field,
lifecycle rule and failure.

### Go

```bash
go get github.com/Sec-CH-Lemon/tls-forge/v2
```

```go
package main

import (
	"fmt"
	"log"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v2"
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

See the [Go library documentation](GO.md) and the runnable project in
[`example/go/`](example/go/).

### Node.js

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

See the [Node.js SDK documentation](node/README.md); the package is written in
TypeScript and ships its types. Runnable projects are in
[`example/node/`](example/node/) and [`example/typescript/`](example/typescript/).

### Python

```bash
pip install tls-forge
```

```python
import tlsforge

with tlsforge.Client(profile="chrome") as client:
    response = client.get("https://tls.browserleaks.com/json")
    print(response.status, response.json())
```

See the [Python SDK documentation](python/README.md) and the runnable project
in [`example/python/`](example/python/).

## Limitations

The handshake and the headers are not all that gives a client away. tls-forge
runs no JavaScript and loads no subresources, and the TCP/IP packets under
every connection are this machine's operating system's. It makes no
speculative connections, as Chrome's preconnects are. HTTP/3 goes where a
name's HTTPS record or an answer's `Alt-Svc` names `h3`, as Chrome's does.
[Scope and limits](docs/support/limits.md) says what is reproduced, how each
part is checked, and where it is known not to be; and
[troubleshooting](docs/support/troubleshooting.md) answers the common failures.

## Development

```bash
make test             # Go race tests
make cover            # 100% Go statement coverage gate
make node-test        # Node types in strict mode, 100% line/function/branch coverage
make python-test      # 100% Python statement/branch coverage gate
make python-typecheck # the Python package's types, mypy in strict mode
make docs-check       # every relative link in the documentation leads somewhere
make docs-site-check  # generated references, a strict site build and its links
make generated-check  # gofmt, tidy modules, report.css and notices as made
make workflows-check  # every action a workflow uses pinned to a release commit
make wrapper-smoke    # Node and Python against the real Go daemon
make release-test     # the release scripts, at 100% line/function/branch coverage
make vet
make lint
make check            # all of the above
make dist             # the release set a tag would build, in dist/set
```

Release and maintenance documentation:

- [`CHANGELOG.md`](CHANGELOG.md) — user-visible changes;
- [`RELEASING.md`](RELEASING.md) — release process;
- [`research/profiles.md`](research/profiles.md) — capture format and profile resolution;
- [`research/protocol.md`](research/protocol.md) — JSON Lines daemon protocol;
- [`research/support.md`](research/support.md) — every behaviour, and how it is checked against Chrome;
- [`research/pinned.md`](research/pinned.md) — the Google Chrome a release is held to;
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
