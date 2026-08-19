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
docker run --rm ghcr.io/sec-ch-lemon/tls-forge fetch https://tls.browserleaks.com/json
```

Or build it yourself, from the same Dockerfile the release uses:

```bash
docker build -t tls-forge .
docker run --rm tls-forge fetch https://tls.browserleaks.com/json
```

The image is Alpine plus one static binary, about 30 MB, running as a non-root
user. The examples below say `tls-forge` for brevity; substitute the full image
name if you pulled it.

Anything that reads or writes files needs the directory mounted, and the paths
you pass have to be the ones inside the container:

```bash
docker run --rm -v "$PWD:/work" tls-forge fetch -o /work/out.json https://tls.browserleaks.com/json
```

The daemon speaks over stdin and stdout, so it needs the input kept open:

```bash
echo '{"id":1,"url":"https://tls.browserleaks.com/json"}' | docker run --rm -i tls-forge daemon
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

## Examples

[example/](example/) holds one of every file the tool reads, with the commands
that use them and the output they produce. It is the place to go to remember how
a list, a proxy column or a warmed session is meant to look.

## Commands

| | |
|---|---|
| [`fetch`](#fetch) | make one request wearing the fingerprint |
| [`batch`](#batch) | fetch a list of URLs, each through its own proxy |
| [`capture`](#capture) | measure the browser on this machine and save a profile |
| [`compare`](#compare) | diff this library against that browser |
| [`profiles`](#profiles) | list what can be impersonated |
| [`proxy`](#proxy) | run a proxy that re-sends every request with the fingerprint |
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

Flags shared by every command that makes requests: `--profile`, `--proxy`,
`--timeout`, `--insecure`, and the four for [cookies](#warmed-cookies).

### Warmed cookies

Warming a session costs something: a browser, a challenge, sometimes a person.
Once it is warm it is worth keeping, so it can be handed to a run, written down,
and used again tomorrow.

```bash
tls-forge fetch -b "session=abc" https://example.com/       # by hand
tls-forge fetch --cookies cookies.json https://example.com/ # from a file
tls-forge fetch --cookies cookies.json --cookie-set warm-eu https://example.com/
tls-forge fetch --save-cookies cookies.json https://example.com/login
```

| flag | |
|---|---|
| `-b`, `--cookie` | one cookie as `name=value`, repeatable. curl's letter |
| `--cookies` | a file of warmed sessions to start from |
| `--cookie-set` | which set in that file to use. One at random when not named |
| `--save-cookies` | write the session the run ends with here. A `.txt` writes a cookies.txt |

`--cookie` carries a name and a value and nothing else; anything needing a
domain or an expiry belongs in a file. What a file gives is applied first and
the flags on top, so a cookie named by hand overrides the one of the same name
in a set.

#### The file

A file holds **sets**, not cookies, because a session is the unit that was
warmed. Twenty sessions in one file are twenty identities to spread a run over,
not one pile of cookies to mix.

```json
{
  "version": 1,
  "sets": [
    {
      "id": "warm-eu",
      "note": "logged in, EU exit",
      "warmed": "2026-08-16T09:07:55Z",
      "cookies": [
        {
          "name": "session",
          "value": "eu-111",
          "domain": "example.com",
          "path": "/",
          "secure": true,
          "http_only": true,
          "expires": "2030-01-02T03:04:05Z"
        }
      ]
    }
  ]
}
```

Only `name` and `value` are required. `domain` decides what a cookie is sent to
and defaults to the host being asked; a cookie with no `expires` is a session
cookie and never goes stale on its own. One that has expired is left out of the
run rather than sent, and the count of what was dropped is printed.

#### The format everything agrees on

A **Netscape cookie file**, `cookies.txt`, is read and written as well, and it
is the one to use when a session has to travel between tools: curl writes it
with `-c` and reads it with `-b`, and so do wget, yt-dlp and every browser
extension that offers an export.

```bash
curl -c jar.txt https://example.com/            # curl warms it
tls-forge fetch --cookies jar.txt …             # this reads it
tls-forge fetch --save-cookies jar.txt …        # this warms it
curl -b jar.txt https://example.com/            # curl reads it
```

Seven tab-separated fields, `domain includeSubdomains path secure expires name
value`, with two conventions that are not obvious: an expiry of `0` means a
session cookie, and a domain prefixed `#HttpOnly_` marks the cookie HttpOnly
while looking exactly like a comment.

Two JSON shapes are read besides this format's own, because a warmed session
arrives from wherever it was warmed: a bare array of sets, and a bare array of
cookies, which is what a browser extension exports and becomes one set.
`httpOnly` and `expirationDate` are understood alongside this format's own
spellings, so an export needs no rewriting.

#### Picking one

Name a set with `--cookie-set`, or name none and one is drawn at random. Random
rather than the first, because a file of warmed sessions exists to be spread
over. A file holding one set needs no seed to be repeatable.

The choice is made **per client**, and a client is one identity: one
fingerprint, one jar, one exit. In `batch` that means one set per proxy rather
than one per URL, since seeding a second warmed session into a jar that already
holds one describes a browser that was two people at once.

#### Writing one down

`--save-cookies` appends what the run ended up holding, under an id naming when
it was warmed:

```bash
tls-forge batch -i urls.csv --save-cookies cookies.json
```

Appended rather than replaced, so a file is built up over run after run, and one
set per proxy, each noting which exit warmed it. The file is written `0600`: a
warmed session is a credential.

### fetch

One request, with the browser's handshake, HTTP/2 preamble and headers. The body
comes back decompressed.

```bash
tls-forge fetch https://tls.browserleaks.com/json
tls-forge fetch -i https://tls.browserleaks.com/json          # status and headers first
tls-forge fetch -o out.json https://tls.browserleaks.com/json # to a file
tls-forge fetch -H "Referer: https://example.com/" https://example.com/page
tls-forge fetch -X POST -d '{"a":1}' \
  -H "content-type: application/json" https://api.example.com/v1
tls-forge fetch -x http://user:pass@proxy.example:8080 https://tls.browserleaks.com/json
tls-forge fetch --profile chrome_151 --timeout 45s https://tls.browserleaks.com/json
```

`tls.browserleaks.com/json` is used throughout this README as the example URL
because it answers with what it saw: the JA4, the JA4_r, the HTTP/2 fingerprint
and the user-agent of whatever asked. Fetch it and the reply is the proof the
impersonation worked, which no other example URL can give you.

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

With no list at all it reads standard input, and says so rather than going
quiet. Ctrl-C ends it; a command stuck somewhere that cannot notice the first
interrupt still dies on the second.

| flag | |
|---|---|
| `-u`, `--urls` | the list as a comma-separated string, instead of a file |
| `-i`, `--input` | the list as a file. Standard input if neither is given |
| `-F`, `--format` | `auto`, `lines`, `json` or `csv`. `auto` reads the file's extension |
| `-c`, `--concurrency` | how many pages to fetch at once, 4 by default |
| `-o`, `--output` | write the JSON lines here instead of to the terminal |
| `-d`, `--body-dir` | write bodies to this directory and reference them instead of inlining them |
| `--repeat` | times to try a URL again when it does not load, 3 by default |
| `-v`, `--verbose` | print a line for every request as it finishes |
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

#### When a page does not load

`--repeat` is how many further tries a URL gets, three by default, so a
transient failure costs a pause rather than a row in the report.

```bash
tls-forge batch -i urls.csv --repeat 5
tls-forge batch -i urls.csv --repeat 0     # one try, no more
```

The waits between tries double from a quarter of a second and stop at two: 250
ms, 500 ms, 1 s, then 2 s for anything further. A repeat with no pause is not
another try. Measured before the pauses were added, a URL through a dead proxy
recorded two attempts inside one millisecond, which is the same failure twice
against a host whose situation had not had time to change.

Only a request that got no answer is repeated. A 503 is an answer, and asking
again for it four times would be four times the load on a site already saying
it is unwell.

Interrupting the run does not wait out the pauses first.

#### Watching it run

`-v` prints a line for every request as it finishes:

```
$ tls-forge batch -i urls.csv -v
  200      559 B     52ms       https://example.com/
  ---        0 B    423ms x2    https://127.0.0.1:1/gone  connection refused
  503        0 B    546ms       https://httpbin.org/status/503
  200      1.3 kB   762ms       https://tls.browserleaks.com/json  via http://eu-1.proxy:8080
```

Status, volume, how long it took, how many tries it needed if more than one,
the URL, the proxy that carried it, and what went wrong. On finishing rather
than on starting: at any real concurrency a line per departure and a line per
arrival interleave into something nobody reads, and what is in flight is what
the status line below is for.

It goes to standard error, like everything else that is commentary, so the JSON
lines on standard output stay readable. When the status line is drawing there
too, it steps aside for each of these and redraws underneath.

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
| `-s`, `--save` | write a reusable profile here. A directory gets `<name>.json` |
| `--install` | keep it in this machine's own directory as `local`, which every run then wears by default |
| `-n`, `--name` | name it yourself instead of `local` under `--install`, or the browser's version under `--save` |
| `-j`, `--json` | print the raw capture rather than a summary |
| `-t`, `--timeout` | how long to wait for the browser, 2m by default |

A browser window opens, shows what it sent, and can be closed. Nothing touches
your real browser profile: every launch gets a throwaway user-data directory,
which also keeps the `--ignore-certificate-errors` flag this needs from ever
applying to a profile you browse with.

#### `--install`, and what a run wears by default

```bash
tls-forge capture --install
```

```
wrote profile "local_macos" to ~/Library/Application Support/tls-forge/profiles/local/macos.json
use it with:  tls-forge fetch --profile local_macos <url>
```

It is filed as **`local`**, not under the browser's version, because there is
one browser on a machine and measuring it again after an update should replace
what is there rather than leave two. Version names are for profiles that ship.

From then on every command that fetches wears it without being asked, and says
so before it starts:

```
$ tls-forge fetch https://example.com/
────────────────────────────────────────────────────────────────────────
  profile     local_macos · measured on this machine
  browser     Chrome 151 on macOS
  from        ~/Library/Application Support/tls-forge/profiles/local/macos.json
  user-agent  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36
────────────────────────────────────────────────────────────────────────
```

Without one, a shipped profile is worn and it says that instead:

```
  profile     chrome_151_macos · shipped with tls-forge
  browser     Chrome 151 on macOS
  from        built into tls-forge
```

Four facts, because three of them are the ones people actually ask. **Which
profile** is only half an answer when several names reach one file, so the
**file** is named too — and `built into tls-forge` is an answer rather than a
blank. The **browser and version** are read out of the user-agent so nobody has
to parse one, and the user-agent is printed in full underneath because that is
the string a server reads.

It goes to standard error, so it does not disturb a body on standard output,
and it is printed every time on purpose. Which browser a request is
pretending to be is the one thing this program does, and the one thing that is
otherwise invisible: a run wearing a profile measured six months ago looks
exactly like a run wearing the right one. `--profile` still overrides, and
`tls-forge profiles` marks the same default with `<`.

Preferring the local one is the point of having measured it. A shipped profile
is a recording of somebody else's browser on an earlier day; the one on this
machine is the browser a server would compare against if it ever saw both.

#### The headers Chrome shows only Google

Writing a profile opens the browser a second time, under Google's name. Chrome
adds a block of headers to a Google property and to nothing else, so a capture
taken against an ordinary host cannot see them:

```
opening it once more, as a Google origin…

google      x-browser-channel  stable
            x-browser-year  2026
            x-browser-validation  iix1/iDR1W9e3SUCZHWKwrVpus8=
            x-browser-copyright  Copyright 2026 Google LLC. All Rights Reserved.
            x-client-data  CID0ygE=
            (after accept)
```

Nothing leaves the machine to measure it. The echo server takes Google's name,
the browser is told that name resolves to loopback, and it hands over what it
would have sent. The two captures were compared field by field: same JA4, same
JA4_r, same HTTP/2 fingerprint, same header list — the Google one has five more
headers, in one block, between `accept` and `sec-fetch-site`. That block is
kept in the profile as `google_headers` — the block, and where it goes:

```json
"google_headers": {
  "after": "accept",
  "headers": [
    { "name": "x-browser-channel",   "value": "stable" },
    { "name": "x-browser-year",      "value": "2026" },
    { "name": "x-browser-validation", "value": "iix1/iDR1W9e3SUCZHWKwrVpus8=" },
    { "name": "x-browser-copyright", "value": "Copyright 2026 Google LLC. All Rights Reserved." },
    { "name": "x-client-data",       "value": "CID0ygE=" }
  ]
}
```

`after` is what keeps that from being a reconstruction: the position is as
measured as the contents, and splicing the block back there reproduces the order
that was seen. The capture proves it rather than assuming it — the block is
spliced into the ordinary list and compared to the second capture, field by
field, and it is only written if the two are identical. A difference that is not
one block sitting at one place is refused rather than flattened into one.

From then on a request to a Google host sends that list and a request anywhere
else sends the ordinary one. Which hosts count was measured too, one host at a
time — 2,041 candidates in a single browser run, each resolved to a local
server — because it is a list inside Chrome rather than a rule: `google.io` and
`google.org` get the block, `google.ai` and `google.dev`, equally Google's, get
nothing. 261 endings matched, plus `youtube.com`, `ytimg.com` and
`gstatic.com`, and every subdomain of them.

Two things worth knowing before you rely on it:

- **`x-browser-validation` is derived from the user-agent.** The same browser
  sending `HeadlessChrome/151.0.0.0` and `Chrome/151.0.0.0` produced two
  different tokens, and each reproduced exactly on a second run with a fresh
  browser profile — so it replays, but only alongside the user-agent it was
  measured with. Override the user-agent and the token is dropped rather than
  sent: a value the receiver can recompute and find wrong is worse than one that
  is absent.
- **`x-client-data` is per-install.** It describes which field-trial groups that
  copy of Chrome is in, and every fresh browser profile produced a different
  one. A profile you captured carries yours; a profile that ships carries the
  one it was captured with, shared by everyone using it — which is true of its
  user-agent and its JA4 too, and is the trade a shipped profile is.

Browsers that are not Google Chrome send no such block, and the capture says so
rather than leaving the field blank:

```
google      nothing extra — this browser is not Google Chrome
```

#### The handshake is the same on every platform

Measured, not assumed. Chrome 151 captured on macOS and Chrome 151.0.7922.137
captured on Linux produce the identical handshake:

| | macOS | Linux |
|---|---|---|
| JA4 | `t13d1516h2_8daaf6152771_806a8c22fdea` | the same |
| JA4_r | | the same |
| HTTP/2 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | the same |
| header order | | the same |

Chrome carries its own BoringSSL, so the ClientHello it builds does not depend
on the operating system underneath. Of seventeen request headers, fourteen
match exactly. What a per-platform profile carries that matters is the three
that do not:

```
user-agent          Macintosh; Intel Mac OS X 10_15_7   vs   X11; Linux x86_64
sec-ch-ua-platform  "macOS"                             vs   "Linux"
```

So capturing on another machine will not move your JA4. It will give you a
user-agent and a platform hint that agree with each other, which a server can
check against nothing else but is free to notice.

#### One version, one directory

A version measured on several platforms is one profile with several spellings,
so it is kept as a directory:

```
profile/data/chrome_151/macos.json
profile/data/chrome_151/linux.json
```

Three names reach them:

| name | what it means |
|---|---|
| `chrome_151` | Chrome 151 as it looks from **this machine**: macOS here, Windows there |
| `chrome_151_linux` | that platform, said outright, whatever this machine is |
| `chrome` | the newest measured Chrome, then as above |

The plain name meaning this machine's platform is the right way round: anything
else is one word longer and says so, which is what a thing that changes what a
server sees should ask for. A version with no capture for this machine falls
back to the first there is: the ClientHello does not depend on the platform, so
what differs is the user-agent, and a profile that says macOS is a coherent
identity from anywhere.

#### Measuring the current Chrome

There is no Windows profile here yet, and none has been invented. The
[capture workflow](.github/workflows/capture.yml) is how a real one gets made:
run it by hand from the Actions tab, and it drives a real headed Chrome on
macOS, Windows and Linux runners and offers the three as artifacts.

It names nothing. The version comes from the browser it measured, so it captures
whatever Chrome it ran and files it under that name — a workflow that said
`chrome_151` would file a Chrome 152 capture under 151 the moment Chrome
updated.

It measures **Google Chrome**, installed on the runner from Google. Not Chrome
for Testing, which is what `browser-actions/setup-chrome` provides and what this
used to use. Measured on one machine, same version, headless both times:

| | `sec-ch-ua` |
|---|---|
| Chrome for Testing | `"Chromium";v="151", "Not=A?Brand";v="99"` |
| Google Chrome | `"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"` |

Chrome for Testing says Chromium, on every request, and no flag changes it —
the branding is compiled in. Its TLS differs too, because it turns on the
testing field-trial configuration and with it experiments real users do not
have: 20 extensions against 18, the extra two being `0xCA34`, TLS trust anchor
identifiers, and `0x12E0`. That part `--disable-field-trial-config` does fix,
which is how the difference was pinned down, but a profile is the whole request
and half a browser is not one.

The price is that the version cannot be chosen: Google serves the current stable
build and nothing else. That matters because **"stable" is not one version** —
Chrome promotes a major by serving it to a slice of users and widening the slice
over days, so several are stable at once. A runner handed the new one first
would produce a profile matching almost nobody. So each platform reports what is
being served to it, which is not the same everywhere:

```
  macOS                             Linux
    151.0.7922.138   99.50%  <        151.0.7922.137  100.00%
    151.0.7922.139    0.25%
     152.0.7977.42    0.25%
```

On that day 152 had reached a quarter of a percent of macOS and Windows and had
not been offered to Linux at all.

[`scripts/chrome-version.py`](scripts/chrome-version.py) produces that and can
be run on its own:

```bash
python3 scripts/chrome-version.py
```

Chrome is fetched from dl.google.com rather than through a package manager,
because a runner image freezes its package metadata for weeks: `brew install
--cask google-chrome` on a macOS runner installed Chrome 150 while Google was
serving 151 and the cask itself pointed at 151. A run stops if the Chrome it got
is behind the one being served, and says so when it is ahead.

#### Nobody has to remember to check

A [weekly job](.github/workflows/drift.yml) installs a real Google Chrome on a
runner and asks `compare` whether the shipped profile still matches it. When it
does not, it **measures the browser on all three platforms and opens a pull
request** with the profiles it produced, assigned to whoever the repository
variable `PROFILE_REVIEWER` names. When it does match, it says nothing at all,
because a check that reports every week is a check nobody reads.

It calls the capture workflow rather than repeating it, so there is one place
that knows a runner needs `--no-sandbox` and that Chrome for Testing is a
different browser. Each profile is loaded and used to fetch a page before the
pull request opens, and the JA4 it produced is in the log.

**It does not merge.** A profile is a measurement, and the way a fingerprint
almost nobody sends ends up shipping is that nobody looked — which has already
happened here once, with Chrome for Testing. The pull request says what to check
before merging: that the platforms you expect are all there, that the
user-agents say Google Chrome rather than Chromium, and ideally
`tls-forge compare --profile <the file>` against your own browser.

One branch per version, so a second run finds its own and adds nothing. If the
drift is real but the capture produces nothing, it files an issue instead —
silence there would be indistinguishable from no drift.

A pull request opened with the workflow's own token does not start the other
workflows, by design, so it arrives without checks. A fine-grained token in
`PROFILE_PR_TOKEN`, with contents and pull-requests write, fixes that; without
one everything else still works.

This is the only thing here that breaks on its own. Every other check answers a
question about the code and can wait for a push; this one answers a question
about the world — Chrome ships a new major every few weeks, the handshake moves
with it, and the repository does not change. Without the timer the first sign is
somebody's scraper collecting challenge pages.

The version numbers are context rather than the verdict: Chrome can ship a new
major without touching its ClientHello, and has. What decides is the
comparison — which is why a run that cannot make one fails loudly instead of
reporting a browser that would not start as a profile that has drifted.

#### Before committing one

Nothing is committed for you. A capture is a measurement of one browser build,
and it belongs in the repository when someone has looked at it and decided it is
the one to ship. What to look at:

1. **The summary says whether the shipped profile still matches**, and when it
   does not, it shows the diff. That is the judgement call, and it cannot be
   made from a yes/no: a cipher list that gained one entry is a browser that
   moved on, while two extensions nobody has heard of is a browser running
   experiments. The second is not worth committing.
2. **Check it against your own Chrome**, which is the only comparison with a
   browser somebody actually uses:

   ```bash
   tls-forge compare --profile ~/Downloads/chrome_152/macos.json
   ```

   `every field matches` means the capture is the browser on your desk. Anything
   else is worth understanding before it ships.

Then copy it in and commit. Older versions can be captured too — Chrome for
Testing keeps thousands of builds — so a profile can be made for a version
after the fact by naming it when starting the run.

`tls-forge profiles` shows what there is, grouped, and every line is a name that
can be copied into `--profile`:

```
Measured from a real browser.
  * kept on this machine, and used ahead of anything shipped
  < what you get when no profile is named

* chrome_151
    chrome_151_linux
*   chrome_151_macos          <
```

Names rather than the user-agents behind them: the question a listing answers is
what is there and which one you get. The arrow goes on the file that is actually
used, not on every name that reaches it.

Both sources are shown at once, not one instead of the other: a machine that
measured its own macOS Chrome still resolves the shipped Linux profile, and a
listing that showed only the local one would be saying less than is true.

#### Where profiles are kept

Four places are searched for a `--profile` name, in this order:

1. anything registered at runtime by a program using the library,
2. **this machine's own directory**, which is where `capture --install` puts one, laid out the same way,
3. the profiles measured and shipped here,
4. the tls-client catalogue.

The order is the point. A profile captured from the Chrome on this machine
beats the one that shipped, because that browser is what a server will be
comparing the handshake against. `tls-forge profiles` marks the local ones with
a star and prints the directory:

```
* chrome_151               Mozilla/5.0 (Macintosh; …) Chrome/151.0.0.0 Safari/537.36
  chrome_144               Mozilla/5.0 (Macintosh; …) Chrome/144.0.0.0 Safari/537.36

Kept on this machine in: ~/Library/Application Support/tls-forge/profiles
```

The directory is under the user's config directory, `%AppData%` on Windows and
`~/.config` on Linux, rather than beside the binary: a profile is this machine's
measurement of this machine's browser and should survive a reinstall.
`TLSFORGE_PROFILES` moves it, which is how a container or a CI job says where to
look.

`--profile` also takes a path, for a profile that lives somewhere else
entirely:

```bash
tls-forge fetch --profile ./measured/my-chrome.json https://tls.browserleaks.com/json
```

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

Three exit codes, because "it ran and disagreed" and "it could not run" are
different answers and a script has to tell them apart:

| | |
|---|---|
| `0` | the client and the browser match |
| `3` | they differ — the report above says how |
| `1` | the comparison could not be made: no browser, it would not start, no such profile |

A check that read the second as the third would file a bug report every week
for a broken runner.

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

### proxy

A proxy that puts the browser's handshake on **whatever is pointed at it**. No
library, no rewriting a script: set one environment variable and the requests
your existing code already makes go out with Chrome's fingerprint.

```bash
tls-forge proxy
```

```
proxy listening on 127.0.0.1:8080

  export HTTPS_PROXY=http://127.0.0.1:8080
  curl --proxy http://127.0.0.1:8080 --cacert '/Users/me/Library/Application Support/tls-forge/ca.pem' https://tls.browserleaks.com/json
```

The authority goes wherever the OS keeps a user's configuration:
`~/Library/Application Support/tls-forge` on macOS, `~/.config/tls-forge` on
Linux, `%AppData%\tls-forge` on Windows. `--ca-cert` and `--ca-key` move it. The
printed command is quoted where the path needs it, so it survives being copied
whatever the directory is called.

Measured against the local instrument, curl on its own and the same curl through
the proxy:

| | JA4 | HTTP/2 | headers sent |
|---|---|---|---|
| curl | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` | `3:100;4:10485760;2:0\|1048510465\|0\|m,s,a,p` | user-agent, accept |
| through the proxy | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | Chrome's thirteen, in order |

The second row is what `tls-forge fetch` produces, which is what Chrome
produces. Running the suggested command reproduces both rows: browserleaks
reports back the JA4 and HTTP/2 fingerprint it saw, so the difference the proxy
makes is in the reply rather than in this table.

| flag | |
|---|---|
| `-a`, `--addr` | listen address, `127.0.0.1:8080` by default |
| `--ca-cert` | the authority to sign with, generated beside the config by default |
| `--ca-key` | its key |
| `-q`, `--quiet` | stop reporting per-connection failures |
| `-p`, `--profile` | which profile to wear |
| `-x`, `--proxy` | an upstream proxy to go out through |
| `-t`, `--timeout` | per-request deadline |
| `-k`, `--insecure` | skip certificate verification **upstream**, which is separate from what the client asks of the proxy |

#### It has to terminate TLS, and what that costs

Replacing a handshake means making it, so the proxy cannot tunnel. A tunnelled
`CONNECT` would carry your own client's fingerprint straight through to the
site, which is the thing being avoided. So the proxy answers `CONNECT` itself,
presents a certificate it signed, and makes its own connection outward.

That means clients have to trust the authority it generates, and **that
authority can impersonate any site to anything that trusts it**. Prefer
`--cacert` on the one command that needs it over installing it system-wide, and
delete the key when the job is done. It is written under the user's config
directory rather than the working directory, so that a key with that much power
does not get committed by whoever runs the proxy inside a repository.

The proxy keeps no cookie jar of its own. It forwards the `Cookie` header its
caller sent and nothing more, because a jar underneath would add a second one
from its own store and leave the caller's session and the proxy's quietly
diverging.

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
echo '{"id":1,"url":"https://tls.browserleaks.com/json"}' | tls-forge daemon
tls-forge daemon -p chrome_151 -x http://user:pass@host:8080
```

| flag | |
|---|---|
| `-p`, `--profile` | which profile to wear |
| `-x`, `--proxy` | upstream proxy |
| `-t`, `--timeout` | per-request deadline. Give it more than the caller's, or a timeout races |
| `-k`, `--insecure` | skip certificate verification |

The protocol is described under [Node.js](#nodejs), and there are working
clients for it in [node/](node/) and [python/](python/).

### version

```bash
tls-forge version
```

Prints the version the binary was stamped with at build time. A binary built
without `-ldflags` reports `dev`.

## Header rules

The block Chrome shows Google is one instance of a general shape: a destination,
some headers it is sent, and where in the browser's order they go. That shape is
a file, so a site expecting a header this library has never heard of does not
need this library to hear of it.

```json
{
  "rules": [
    {
      "host": "*.example.com",
      "after": "accept",
      "headers": [
        { "name": "x-api-version", "value": "3" }
      ]
    },
    {
      "host": "/^shop[0-9]+\\.example\\.net$/",
      "headers": [
        { "name": "x-shop", "value": "yes" }
      ]
    },
    {
      "host": "*.google.com",
      "remove": ["x-client-data"]
    }
  ]
}
```

```bash
tls-forge fetch --header-rules rules.json https://www.example.com/
```

The flag is on every command that makes requests — `fetch`, `batch`, `proxy`,
`daemon` — and `TLSFORGE_HEADER_RULES` names the same file for a run that cannot
pass a flag, which is how one reaches the Python and Node clients.

| field | |
|---|---|
| `host` | which destinations this is for. Three forms, below |
| `after` | the header the added ones go behind. Omitted, they go on the end |
| `headers` | added, or replaced in place if the profile already sends them |
| `remove` | headers this destination is not sent, including ones added here |

**`host` has three forms:**

| | matches |
|---|---|
| `example.com` | that host, exactly |
| `*.example.com` | that host **and** every subdomain of it |
| `/^shop[0-9]+\.example\.net$/` | a regular expression, against the lower-cased hostname |

The plain form is exact on purpose: a pattern that quietly covered subdomains
would send a site's headers to whatever it hosts for other people, and the star
is one character. The star form covers the bare domain as well as its
subdomains, which is how a browser's own match patterns read and what people
mean when they write one. Matching is against the hostname alone — no scheme, no
port, no path.

**What happens to the order.** A header the profile already sends keeps the
browser's place in the list and only changes value, because moving it would
change the fingerprint the profile is for. A header the browser never sends has
no observed position, so it goes where `after` says, or on the end.

**What wins.** Rules are applied in the order written, over the profile and over
the Google block, and under anything set for the client or for the request:

```
profile  →  Google block  →  rules, in file order  →  WithHeaders / -H  →  this request
```

A file is a default for a destination; an argument is a decision about one
request, and the decision wins.

**In Go**, the same thing without a file:

```go
client, err := tlsforge.New(
    tlsforge.WithHeaderRules(tlsforge.Rule{
        Host:    "*.example.com",
        After:   "accept",
        Headers: []profile.Field{{Name: "x-api-version", Value: "3"}},
    }),
)
```

`tlsforge.WithHeaderRulesFile(path)` reads the file instead, and rules passed in
code are applied after rules from a file, so code overrides the file the same way
a flag overrides a default.

A rules file that cannot be read, cannot be parsed, holds no rules, or holds a
pattern that will not compile is an error from `New` rather than a run with no
rules — because a run with no rules looks exactly like a run whose rules did not
match, and that is a bad afternoon.

## Add it to your project

> The command, the repository, the npm package and the PyPI package are all
> `tls-forge`. The Go package and the Python import are `tlsforge`, without the
> hyphen, because neither a Go identifier nor a Python module name can contain
> one — so they read `tlsforge.New(…)` and `import tlsforge`. Error strings use
> that name too, as Go convention expects.

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

res, err := client.Get("https://tls.browserleaks.com/json")
fmt.Println(res.Status, res.OK(), len(res.Body))
```

That is the whole of it: the request goes out with Chrome's handshake, Chrome's
HTTP/2 preamble and Chrome's headers in Chrome's order, and the body comes back
decompressed. Chrome advertises gzip, deflate, br and zstd, and a client that
advertises them has to be able to read them.

#### What comes back

```go
res.Status          // 200
res.OK()            // true for a 2xx
res.URL             // the final URL, after redirects
res.Body            // []byte, already decompressed
res.Text()          // the same as a string
res.Header          // map[string][]string, every value kept
res.Cookies         // []string, what the jar holds for that URL now
```

`Header` on the way back is a map because nothing downstream is fingerprinting
your reading of it. On the way out it is a list, which is the next section.

#### Headers are ordered, so they are a list

Header order is part of the fingerprint, and a Go map has no order. So the
outgoing type is a list:

```go
h := tlsforge.NewHeader("Referer", "https://example.com/", "X-Extra", "1")
h.Set("Accept-Language", "en-GB,en;q=0.9")   // replaces in place, or appends
h.Get("referer")                              // case-insensitive
h.Has("x-extra")
h.Del("x-extra")
h.Names()                                     // the order they will be sent in
```

Per-request headers are layered over the profile's rather than replacing them:
a name the browser already sends keeps the browser's position and takes your
value, and one it does not send is appended after the rest. `client.Headers()`
returns what the profile sends, so you can see what you are layering onto.

#### A request with everything on it

```go
res, err := client.Do(&tlsforge.Request{
    Method:  "POST",
    URL:     "https://example.com/api",
    Header:  tlsforge.NewHeader("Content-Type", "application/json"),
    Body:    []byte(`{"a":1}`),
    Cookies: []tlsforge.Cookie{{Name: "session", Value: "abc"}},
})
```

`Cookies` here seeds the jar before the request rather than writing a `Cookie`
header: the transport writes that header itself, and setting it by hand
replaces what the server put there earlier in the session, which no browser
does.

#### Options

Every option is a `tlsforge.Option` passed to `New`:

| | |
|---|---|
| `WithProfile(name)` | any name `tls-forge profiles` lists, including `local` for the browser you measured |
| `WithProfileValue(p)` | a `*profile.Profile` you loaded yourself |
| `WithProxy(url)` | `http://`, `https://` or `socks5://`, with credentials if it needs them |
| `WithTimeout(d)` | per-request deadline, 30s by default |
| `WithHeaders(h)` | headers on every request, layered the same way |
| `WithCookies(c)` | seed the jar at construction |
| `WithoutCookieJar()` | no jar at all, for a proxy that forwards its caller's `Cookie` |
| `WithCookieJar(jar)` | your own jar, to share or persist one |
| `WithoutRedirects()` | return the 302 instead of following it |
| `WithInsecureSkipVerify()` | skip certificate verification |
| `WithFixedExtensionOrder()` | stop shuffling TLS extensions, which only a test wants |
| `WithTransportOption(...)` | anything else tls-client takes |

```go
client, err := tlsforge.New(
    tlsforge.WithProfile("chrome"),
    tlsforge.WithProxy("http://user:pass@proxy.example:8080"),
    tlsforge.WithTimeout(20*time.Second),
    tlsforge.WithHeaders(tlsforge.NewHeader("Accept-Language", "de-DE,de;q=0.9")),
)
```

`WithFixedExtensionOrder` deserves its warning: Chrome shuffles its extension
order on every connection, so a client that always sent the same order would
differ from Chrome in exactly the way Chrome does not differ from itself. It
exists so a test can compare two handshakes byte for byte, and for nothing else.

#### The jar

```go
held, err := client.Cookies("https://example.com/")     // what the jar has for that URL
all, err := client.CookiesFor("https://example.com/")   // and for its parent domains
```

One client is one jar. Reading it out is how a warmed session gets written down
and handed to the next run — which is what `--save-cookies` does on the command
line, in the [format](#the-file) described above.

#### One client is one identity

One TLS fingerprint, one cookie jar, one exit IP. Rotating any of them means a
new client. That is deliberate: a jar shared between two fingerprints describes
a browser that changed its TLS stack mid-session, which is not a thing that
happens.

A client **is** safe for concurrent use — measured, twenty-four simultaneous
requests on one client under `-race` — so a pool of clients is a pool of
sessions rather than a pool of connections:

```go
clients := make([]*tlsforge.Client, len(proxies))
for i, proxy := range proxies {
    clients[i], err = tlsforge.New(tlsforge.WithProfile("chrome"), tlsforge.WithProxy(proxy))
    if err != nil {
        return err
    }
    defer clients[i].Close()
}

var wg sync.WaitGroup
for i, url := range urls {
    wg.Add(1)
    go func() {
        defer wg.Done()
        res, err := clients[i%len(clients)].Get(url)
        …
    }()
}
wg.Wait()
```

For scraping at any volume that is the shape to build on: one client per proxy,
each keeping its own jar for as long as that identity lasts.

#### Wearing a profile you measured

```go
data, err := os.ReadFile("my-chrome.json")
p, err := profile.Load(data)
client, err := tlsforge.New(tlsforge.WithProfileValue(p))
```

Or by name, once `tls-forge capture --install` has kept one:

```go
client, err := tlsforge.New(tlsforge.WithProfile("local"))
```

`client.Profile()` says which one is being worn, which is worth logging: a
program wearing a profile measured six months ago looks exactly like one wearing
the right one.

### Node.js

```bash
npm install tls-forge
```

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome' });
const res = await client.get('https://tls.browserleaks.com/json');
console.log(res.status, JSON.parse(res.body).ja4);
client.close();
```

```
200 t13d1516h2_8daaf6152771_806a8c22fdea
```

No Go, no build step, no download during install. The binary arrives as an
optional dependency, one package per platform, each declaring `os` and `cpu`, so
npm installs the one that matches and skips the others. That is the arrangement
esbuild uses, and it survives `npm ci --ignore-scripts`, which a postinstall step
does not.

#### What comes back

```js
res.status                     // 200
res.url                        // the final URL, after redirects
res.body                       // string, already decompressed
res.headers['content-type']    // multi-valued names joined with '; '
res.cookies                    // ['session=abc'] — what the jar holds for that URL
```

`headers` joins rather than picks: `set-cookie` arrives more than once routinely,
and a caller that only saw the first would lose a session.

#### Options

```js
const client = new Client({
  profile: 'chrome_151',
  proxy: 'http://user:pass@host:8080',
  timeout: 30_000,
  insecure: false,
  binary: './bin/tls-forge',
  onStderr: (line) => console.error(line),
});
```

| | |
|---|---|
| `profile` | any name `tls-forge profiles` lists, including `local` for the browser you measured |
| `proxy` | `http://`, `https://` or `socks5://` |
| `timeout` | per-request deadline in **milliseconds**, 45000 by default |
| `insecure` | skip certificate verification |
| `binary` | path to the transport, ahead of every other source |
| `onStderr` | receives the transport's diagnostics, a line at a time |

The transport is given a deadline fifteen seconds longer than yours, on purpose.
If they were equal, a request timing out would race: both sides would decide it
had failed, and the process would be killed while writing the answer.

#### Per request

```js
await client.get(url, {
  headers: { referer: 'https://example.com/' },
  order: ['referer'],
  cookies: ['session=abc'],
});

await client.post(url, '{"a":1}', { headers: { 'content-type': 'application/json' } });

await client.request({ url, method: 'DELETE', headers: { … } });
```

`headers` are layered over the profile's: a name the browser already sends keeps
the browser's position and takes your value, one it does not send is appended
after the rest. `order` orders the headers **you** send, not the whole request —
without it they go last, sorted, because a Go map iterates randomly and a header
set that reordered itself between two identical requests would be a fingerprint
of its own.

Do not set `cookie` by hand. The transport writes it from the jar, and setting
the header replaces what the jar holds, so cookies the server set earlier in the
session would silently vanish.

#### Failures

Everything rejects; nothing throws synchronously except a missing binary, which
throws from the constructor because no request could have worked:

```js
try {
  await client.get(url);
} catch (err) {
  // 'tlsforge: dial tcp …'          the request ran and failed
  // 'tlsforge: request timed out'   your deadline passed
  // 'tlsforge: transport exited …'  the process died; the client stays usable
}
```

`close()` is final. A closed client will not respawn, and a later request
rejects rather than quietly minting a new process with a new fingerprint and an
empty jar.

#### One client is one identity

One long-lived process: one TLS fingerprint, one cookie jar, one exit IP for its
whole life. Reconnecting per request is itself a signal, and no browser does it.

The protocol underneath is one request at a time, so calls on one client queue
rather than overlap. Parallelism is a pool, one client per proxy, which is also
what keeps the identities apart:

```js
const pool = proxies.map((proxy) => new Client({ profile: 'chrome', proxy }));
const results = await Promise.all(
  urls.map((url, i) => pool[i % pool.length].get(url).catch((err) => err)),
);
pool.forEach((client) => client.close());
```

#### Where the binary comes from

In order: the `binary` option, `TLSFORGE_BIN`, the platform package npm
installed, a local `npm run build`, then `PATH`. `resolveBinary()` is exported so
a script can ask which one it would use. Full documentation is in
[node/](node/).

### Python

```bash
pip install tls-forge
```

No Go, no build step, no download during install, and no dependencies — a wheel
is already platform-tagged, so pip fetches the one for your machine with the
binary inside it. The package installs as `tls-forge` and imports as `tlsforge`,
because a module name cannot have a hyphen in it.

A whole script:

```python
import tlsforge

with tlsforge.Client(profile="chrome") as client:
    res = client.get("https://tls.browserleaks.com/json")
    print(res.status, res.json()["ja4"])
```

```
200 t13d1516h2_8daaf6152771_806a8c22fdea
```

That address answers with the fingerprint it saw, so the reply is the proof
rather than a promise: a real Chrome on the same machine reports the same JA4.
`Client` is a context manager, and closing it is what ends the process
underneath, so `with` is the shape to reach for.

#### What comes back

```python
res = client.get(
    "https://example.com/page",
    headers={"referer": "https://example.com/"},
    cookies=["session=abc"],
)

res.status              # 200
res.ok                  # True for a 2xx
res.url                 # the final URL, after redirects
res.body                # str, already decompressed
res.json()              # the body parsed
res.headers["content-type"]
res.cookies             # ('session=abc',) — what the jar holds for that URL now
```

The body arrives decompressed: Chrome advertises gzip, deflate, br and zstd, and
a client that advertises them has to be able to read them. `headers` joins a
name that arrived more than once with `; `, because `set-cookie` routinely does
and a caller that saw only the first would lose a session.

Per-request `headers` are layered over the profile's: a name the browser already
sends keeps the browser's position and takes your value, and one it does not
send is appended after the rest. Do not set `cookie` by hand — pass `cookies=`
instead, which adds to the jar rather than replacing what the server put there.

#### Failures

```python
try:
    res = client.get(url)
except tlsforge.RequestFailed:   # it ran and failed: refused, DNS, TLS
    ...
except tlsforge.Timeout:         # the deadline passed; also a builtin TimeoutError
    ...
except tlsforge.TransportError:  # the transport would not start or died
    ...
```

All of them, plus `BinaryNotFound`, are `tlsforge.TLSForgeError`, so one `except`
catches the lot. A call that could never have worked — no URL — raises
`ValueError` and never reaches the network.

#### Scraping a list

One client is one identity: one TLS fingerprint, one cookie jar, one exit IP.
A client also **serialises**, because the protocol underneath is one request at
a time, so threads sharing one client queue behind each other. That is not a
limitation to work around: it is what one session is. Parallelism is a pool of
clients, one per proxy, which is also what keeps the identities apart.

```python
import contextlib, itertools, tlsforge
from concurrent.futures import ThreadPoolExecutor

proxies = ["http://user:pass@eu-1.proxy:8080", "socks5://us-3.proxy:1080"]

with contextlib.ExitStack() as stack:
    clients = [stack.enter_context(tlsforge.Client(proxy=p, timeout=20)) for p in proxies]
    turn = itertools.cycle(clients)

    def fetch(url):
        try:
            res = next(turn).get(url)
            return url, res.status, len(res.body)
        except tlsforge.TLSForgeError as err:
            return url, None, str(err)

    with ThreadPoolExecutor(len(clients)) as pool:
        for url, status, size in pool.map(fetch, urls):
            print(f"{str(status):>4}  {size:>8}  {url}")
```

```
 200       559  https://example.com/
 200       559  https://example.org/
 200      1263  https://tls.browserleaks.com/json
```

A jar spread across two exit IPs describes a browser that changed its network
mid-session, which is not a thing that happens. One client per proxy makes that
impossible rather than merely unlikely.

#### Warmed sessions and your own profile

```python
tlsforge.Client(cookie_file="cookies.json", cookie_set="warm-eu")
tlsforge.Client(profile="chrome_151_macos")
tlsforge.Client(binary="./bin/tls-forge", on_stderr=print)
```

The cookie file is the one [`tls-forge fetch --save-cookies`](#fetch) writes, so
a session warmed by the command line can be picked up by a script. `profile`
takes any name `tls-forge profiles` lists. `on_stderr` receives the transport's
own diagnostics a line at a time, which is where a dropped answer or a warning
shows up.

Full documentation, including how the binary is found, is in [python/](python/).

Under all three is the `daemon` command, one JSON object per line on stdin and
stdout, so any other language can borrow the fingerprint the same way:

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
The implementation was cross-checked against `tls.browserleaks.com/json` for the
same browser: same JA4, same JA4_r, same normalised JA3, same HTTP/2 fingerprint
and hash.

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

## Releasing

A release is a tag. Push `v0.1.0` and the binaries, the npm packages, the Python
wheels, the Docker image and the Homebrew formula are all built from it and
published — the tag is the only place a version is written down.
[RELEASING.md](RELEASING.md) has what to set up once, and `make dist` assembles
everything a tag would publish without publishing any of it.

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
