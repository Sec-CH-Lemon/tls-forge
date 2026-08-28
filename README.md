# TLS Forge

`tls-forge` is an HTTP client and command-line tool for making requests with a
real browser's network fingerprint. A profile controls the TLS ClientHello,
JA3/JA4-relevant fields, measured HTTP/1.1 header casing and order, HTTP/2
settings, pseudo-header order, regular header order and browser headers as one
coherent identity.

Use it when an ordinary Go, Node.js or Python HTTP client is rejected because
its network stack does not match the browser named by its `User-Agent`.
`tls-forge` can be used as:

- a standalone CLI for one request or a batch;
- an intercepting proxy for an existing program;
- a Go library;
- a Node.js or Python SDK backed by the same Go transport;
- a local measurement tool for capturing and comparing browser fingerprints.

It does not execute page JavaScript and does not solve managed challenges or
CAPTCHAs. It addresses the TLS and HTTP fingerprint checks that happen before,
or alongside, normal HTTP handling.

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

## Install

A Chromium-based browser is required only for `capture` and `compare`. Fetching,
batch processing, proxying and the language SDKs do not require a browser.

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

### Homebrew

On macOS or Linux:

```bash
brew tap Sec-CH-Lemon/tap
brew trust --formula Sec-CH-Lemon/tap/tls-forge
brew install Sec-CH-Lemon/tap/tls-forge
```

Homebrew requires explicit trust for third-party taps. Review the tap before
granting it.

### Go install

With Go 1.25.13 or newer:

```bash
go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest
```

The binary is written to `$(go env GOPATH)/bin` unless `GOBIN` is set.

### Docker

Release images are published for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/sec-ch-lemon/tls-forge
docker run --rm ghcr.io/sec-ch-lemon/tls-forge \
  fetch https://tls.browserleaks.com/json
```

Mount a directory when a command reads or writes files:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sec-ch-lemon/tls-forge \
  batch --input /work/urls.csv --output /work/results.jsonl
```

`capture` and `compare` are intentionally not supported by the small release
image because it does not contain a browser.

## Build from source

Requirements:

- Go 1.25.13 or newer;
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
stronger than checking only a JA3 or JA4 hash.

## Commands

```text
tls-forge <command> [flags]
```

| Command | Purpose |
|---|---|
| [`fetch`](#fetch) | Make one request with a browser fingerprint |
| [`batch`](#batch) | Fetch many URLs concurrently, optionally with one proxy per URL |
| [`capture`](#capture) | Measure an installed browser and optionally save a reusable profile |
| [`compare`](#compare) | Compare a profile with an installed browser |
| [`profiles`](#profiles) | List available profiles |
| [`proxy`](#proxy) | Re-send requests from another program using the selected fingerprint |
| [`serve`](#serve) | Run the local TLS/HTTP fingerprint echo server |
| [`daemon`](#daemon) | Expose the client as a JSON Lines transport |
| [`version`](#version) | Print the build version |

Run `tls-forge <command> --help` for generated command help. Durations use Go
syntax such as `500ms`, `30s` or `2m`.

When no profile is selected, the network commands (`fetch`, `batch`, `proxy`
and `daemon`) use a profile installed as `local`, if one exists, and otherwise
the latest bundled `chrome` profile. `compare` defaults to the bundled `chrome`
family so it can detect drift instead of comparing a fresh local measurement
with itself. Use `tls-forge profiles` to see the exact names available on the
machine.

### `fetch`

Make one request and write its decompressed body to standard output.

```bash
tls-forge fetch https://example.com/
tls-forge fetch -i -H "Accept-Language: en-US" https://example.com/
tls-forge fetch -X POST -H "Content-Type: application/json" \
  -d '{"hello":"world"}' https://example.com/api
```

Usage: `tls-forge fetch [flags] <url>`

| Flag or argument | Meaning |
|---|---|
| `<url>` | Required HTTP or HTTPS URL |
| `-b`, `--cookie name=value` | Seed one cookie; repeatable |
| `--cookies <file>` | Load a warmed session from JSON, a browser export, or Netscape cookies.txt |
| `--cookie-set <id>` | Select a set from a multi-session JSON file; otherwise one is chosen at random |
| `--save-cookies <file>` | Atomically save the final session; `.txt` selects Netscape format |
| `-p`, `--profile <name-or-path>` | Profile to impersonate |
| `-x`, `--proxy <url>` | HTTP, HTTPS or SOCKS proxy, optionally with credentials |
| `-t`, `--timeout <duration>` | Request timeout; default `30s` |
| `-k`, `--insecure` | Skip upstream certificate verification |
| `-X`, `--method <method>` | HTTP method; default `GET` |
| `-d`, `--data <text>` | Request body |
| `-i`, `--include` | Print status and response headers before the body |
| `-o`, `--output <file>` | Write the body to a file instead of stdout |
| `-H`, `--header "Name: value"` | Add or override an ordered request header; repeatable |

Cookie files are treated as credentials and saved with mode `0600`. JSON files
can retain multiple named sessions; Netscape `.txt` files contain one jar and
are compatible with tools such as curl and wget.

### `batch`

Fetch a list concurrently and emit one JSON object per URL. Results go to
stdout or `--output`; progress and summaries go to stderr, so the JSON Lines
stream remains machine-readable.

```bash
tls-forge batch https://example.com/ https://example.org/
tls-forge batch --input example/urls.csv --concurrency 8
tls-forge batch --input urls.json --output results.jsonl --report reports/
```

Usage: `tls-forge batch [flags] [urls...]`

| Flag or argument | Meaning |
|---|---|
| `[urls...]` | URLs passed directly when neither `--urls` nor `--input` is used |
| `-b`, `--cookie name=value` | Seed one cookie; repeatable |
| `--cookies <file>` | Load warmed cookies |
| `--cookie-set <id>` | Select one set from the cookie file |
| `--save-cookies <file>` | Save one resulting session per distinct proxy |
| `-p`, `--profile <name-or-path>` | Profile to impersonate |
| `-x`, `--proxy <url>` | Default proxy for entries that do not specify one |
| `-t`, `--timeout <duration>` | Per-request timeout; default `30s` |
| `-k`, `--insecure` | Skip upstream certificate verification |
| `-i`, `--input <file>` | Read URLs from a file; stdin is used when no source is given |
| `-u`, `--urls <a,b,c>` | Comma-separated URLs; highest input precedence |
| `-F`, `--format <format>` | `auto`, `lines`, `json` or `csv`; default `auto` |
| `-c`, `--concurrency <n>` | Concurrent requests; default `4` |
| `-o`, `--output <file>` | Write JSON Lines results here instead of stdout |
| `-d`, `--body-dir <dir>` | Store response bodies separately and reference their paths |
| `--repeat <n>` | Number of retries after a URL does not load; default `3` |
| `-v`, `--verbose` | Print one status line when each request finishes |
| `--progress <mode>` | Live stderr status: `auto`, `always` or `never`; default `auto` |
| `-R`, `--report <path>` | Write a self-contained HTML report; a directory gets a timestamped filename |
| `--report-ip[=false]` | Ask `https://ipinfo.io/json` once per proxy for report metadata; default `true` |

Input precedence is `--urls`, then `--input`, then positional URLs, then stdin.
When an inline response body is not valid UTF-8, `body` is base64 and the row
contains `"body_encoding":"base64"`; `bytes` always remains the original byte
count. `--body-dir` writes the original bytes directly instead.
With `--format auto`, `.json` selects JSON, `.csv` selects CSV and every other
name uses one URL per line.

Supported list shapes:

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

The command creates one client and cookie jar per distinct proxy. A batch exits
non-zero when one or more URLs fail.

Runnable CLI and SDK examples, with complete sample inputs and outputs, are in
[`example/`](example/).

### `capture`

Open an installed Chromium-based browser, record its TLS and HTTP behaviour and
optionally save a reusable profile.

```bash
tls-forge capture
mkdir -p profiles && tls-forge capture --save profiles/
tls-forge capture --browser edge --headless --save edge.json
tls-forge capture --install
```

Usage: `tls-forge capture [flags]`

| Flag | Meaning |
|---|---|
| `-b`, `--browser <name-or-path>` | `chrome`, `chromium`, `edge`, `brave`, or an executable path; auto-detected when omitted |
| `--headless` | Run without a window; TLS/HTTP structure remains useful for drift checks, but Chrome may expose `HeadlessChrome` and therefore differ in header values from a headed profile |
| `-s`, `--save <path>` | Save a profile; an existing directory gets `<name>/<platform>.json` |
| `--install` | Save into the user profile directory so `--profile local` can find it |
| `-n`, `--name <name>` | Override the profile name; otherwise derive it from the browser version |
| `-j`, `--json` | Print the raw capture instead of a human summary |
| `-t`, `--timeout <duration>` | Maximum browser measurement time; default `2m` |
| `--browser-arg <argument>` | Append a browser process argument; repeatable, mainly for CI environments |

Installed profiles live below the operating system's user configuration
directory. Set `TLSFORGE_PROFILES` to choose another directory. Running
`capture --install` again replaces the local machine profile after a browser
update.

### `compare`

Measure an installed browser and the selected client profile against the same
local server, then print a field-by-field diff.

The browser is measured over both HTTP/1.1 and HTTP/2. HTTP/1.1 names are
compared with their exact wire casing; HTTP/2 remains lower-case as required by
the protocol. Profiles that predate the optional HTTP/1.1 section continue to
work with the historical fallback.

```bash
tls-forge compare
tls-forge compare --profile chrome_151 --headless
tls-forge compare --json > comparison.json
```

Usage: `tls-forge compare [flags]`

| Flag | Meaning |
|---|---|
| `-p`, `--profile <name-or-path>` | Profile to check; default `chrome` |
| `-b`, `--browser <name-or-path>` | Browser to measure; auto-detected when omitted |
| `--headless` | Run the browser without a window |
| `-j`, `--json` | Print both captures and the comparison as JSON |
| `-c`, `--color <mode>` | `auto`, `always` or `never`; default `auto` |
| `-f`, `--full` | Do not trim matching values; differences are always printed in full |
| `-t`, `--timeout <duration>` | Maximum browser measurement time; default `2m` |
| `--browser-arg <argument>` | Append a browser process argument; repeatable |

Exit codes are meaningful:

| Code | Meaning |
|---|---|
| `0` | Browser and client match on every compared field |
| `3` | Measurement succeeded, but fingerprints differ |
| `1` | Comparison could not be completed |
| `2` | Invalid arguments or help output |

### `profiles`

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

### `proxy`

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
| `-p`, `--profile <name-or-path>` | Profile used for outbound requests |
| `-x`, `--proxy <url>` | Optional upstream proxy |
| `-t`, `--timeout <duration>` | Outbound request timeout; default `30s` |
| `-k`, `--insecure` | Skip certificate verification on outbound connections |
| `-a`, `--addr <host:port>` | Listen address; default `127.0.0.1:8080` |
| `--ca-cert <file>` | CA certificate; generated in the user config directory by default |
| `--ca-key <file>` | Matching CA private key |
| `-q`, `--quiet` | Suppress per-connection error messages |
| `--max-request-body <bytes>` | Largest request body buffered by the proxy; default `16777216` (16 MiB) |

The proxy deliberately has no cookie jar; it forwards the caller's `Cookie`
header. The generated CA can impersonate any site to a client that trusts it.
Prefer trusting it only for the specific process, keep the private key secret,
and remove that trust when the proxy is no longer needed. The certificate and
key must either both exist and match or both be absent.

### `serve`

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
explicitly disable verification for this local endpoint.

### `daemon`

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
| `-p`, `--profile <name-or-path>` | Profile to impersonate |
| `-x`, `--proxy <url>` | Upstream proxy |
| `-t`, `--timeout <duration>` | Transport request timeout; default `30s` |
| `-k`, `--insecure` | Skip certificate verification |

One request object is read per line:

```json
{"id":1,"method":"POST","url":"https://example.com/api","headers":{"content-type":"application/json"},"order":["content-type"],"body":"{\"a\":1}","setCookie":["session=abc"]}
```

The response repeats `id` and contains `status`, final `url`, `body`,
multi-valued `headers`, `cookies`, and `error` when the request failed. Input
lines are limited to 16 MiB. Requests are processed sequentially so one daemon
remains one browser identity and one cookie jar.

### `version`

Print the version stamped into the binary:

```bash
tls-forge version
```

Usage: `tls-forge version`. This command has no flags. A source build without
version linker flags reports `dev`.

## Language libraries

The root README intentionally contains only a working introduction for each
SDK. Every language has its own detailed API document with all constructor and
request options, response fields, lifecycle rules and failure behaviour.

### Go

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

See the complete [Node.js SDK documentation](node/README.md).
The runnable consumer project is in [`example/node/`](example/node/).

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

See the complete [Python SDK documentation](python/README.md).
The runnable consumer project is in [`example/python/`](example/python/).

## Development

```bash
make test         # Go race tests
make cover        # 100% Go statement coverage gate
make node-test    # 100% Node line/function/branch coverage gate
make python-test  # 100% Python statement/branch coverage gate
make wrapper-smoke # Node and Python against the real Go daemon
make vet
make lint
make check        # all of the above
```

Release and maintenance documentation:

- [`CHANGELOG.md`](CHANGELOG.md) — user-visible changes;
- [`RELEASING.md`](RELEASING.md) — release process;
- [`docs/article.ru.md`](docs/article.ru.md) — Russian introduction to TLS fingerprinting and TLS Forge;
- [`docs/profiles.md`](docs/profiles.md) — capture format and profile resolution;
- [`docs/protocol.md`](docs/protocol.md) — JSON Lines daemon protocol;
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
