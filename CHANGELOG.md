# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

A note specific to this project: **a new profile is not a breaking change, but a
changed default profile can be.** `WithProfile("chrome")` resolves to the newest
measured Chrome, so adding a profile for a newer browser changes what that name
means. Pin the exact name — `WithProfile("chrome_151")` — when that matters.

## [Unreleased]

### Fixed

- **Six idle connections are kept per host instead of one.** Past the
  transport's default, a request beyond the second closed its connection when it
  finished and the next one dialled again: 1726 connections for 3000 requests
  over eight workers, which is slow, exhausts local ports on a long run, and
  makes a fresh handshake per request, the very signal this library exists to
  avoid. Six is Chrome's own limit for HTTP/1.1. Measured after: five
  connections for the same 3000 requests at four workers. HTTP/2 multiplexes and
  never saw any of it.
- The HTML report keeps at most 2,000 rows and says how many it left out.
  A run of 100,000 wrote 140 MB of HTML that no browser opens; it is now 2.7 MB.
  Everything that failed or answered with something other than a page is kept
  first, and the JSON lines still carry every row.
- Exit-address lookups stop after 50 proxies and say how many went unasked. A
  rotating list can name thousands, and one request each to somebody else's free
  service would take minutes and earn the rate limit.

- **A run held every page it fetched in memory until it ended.** The records
  kept for the summary and the report carried the response body, which neither
  of them shows. Measured at 200 MB of pages: 353 MB of resident memory before,
  137 MB after. What is kept now is a fixed couple of hundred bytes per URL.

- **A five-byte TLS record crashed `tls-forge serve`.** A handshake record
  carrying an empty payload made the ClientHello parser read the first byte of
  a buffer that had none, and the parse runs on the connection goroutine before
  any handshake completes, so any peer that could open a socket could stop the
  process. Found by a new fuzz target, not by the tests: the package was at
  100% statement coverage with the bug in it.
- Connection handlers now recover, so a panic costs one connection rather than
  the server, as `net/http` does in the same place.

### Added

- `batch -v` prints a line for every request as it finishes: status, volume,
  duration, attempt count when it took more than one, URL, proxy and error. On
  standard error, stepping around the status line when one is drawing there.

- The HTML report is styled with Tailwind: a lead figure for the success rate
  with a three-segment meter, a row of stat tiles, and status pills carrying a
  glyph and a word as well as a colour. Light and dark are both selected sets
  of steps rather than one flipped. The stylesheet is generated from the
  template by `make report-css` and compiled into the binary, so the report
  stays a single self-contained file and `go build` still needs nothing but Go;
  a test fails if the template uses a class the committed stylesheet lacks.

### Changed

- `--retry` becomes `--repeat`, and the default is 3 rather than none: it now
  counts further tries after the first, so a URL that does not load is asked for
  four times in all. The waits between them double from 250 ms and stop at two
  seconds; before, a repeat happened in the same microsecond as the failure it
  was repeating.

- `--report` given a directory names the file after the run,
  `report-2026-08-16-01:09:45:123.html`, rather than needing one invented per
  run. On Windows the colons are dashes, because a colon cannot appear in a
  file name there.
  Timestamps inside the report read `16 Aug 2026 01:10:10`.

- **A run now has three outcomes, not two.** A response that is not a 2xx is
  counted and shown apart from a page that was scraped and from a request that
  got nothing back: a 503 is neither. The exit code is unchanged and still turns
  on requests that got no response, so a batch expecting some 404s does not fail
  on them.

- Every `batch` run ends with a summary on standard error: how long it took,
  how many URLs succeeded and failed with the percentage of each, the volume of
  data, how many retries were spent, and how many proxies were used against how
  many carried at least one page. Dead proxies are named and counted, since
  "6 of 8 alive" does not say which two to replace.
- `batch --report FILE` writes a self-contained HTML report: a row per proxy
  and a row per URL with its start and end time, duration, outcome, volume,
  attempt count, proxy, and that proxy's exit address with a country flag. The
  address is asked of `https://ipinfo.io/json` once per proxy, announced on
  standard error before it happens, and skipped with `--report-ip=false`. The
  flag is computed from the country code rather than looked up.
- The JSON lines now carry `started` and `ended` timestamps.

- A live status line for `batch`: how many of the list are done, how many are in
  flight, how much body has come back, how long it has been going, roughly how
  much longer, and how many failed. Drawn on standard error, never on standard
  output, which carries the JSON lines; when both are the same terminal the line
  erases itself around each result so neither stream lands on the other.
  `--progress auto|always|never`, drawing only to a terminal by default.

- Licensed under Apache-2.0, with `NOTICE` and a generated
  `THIRD-PARTY-NOTICES.txt`. The published binaries are statically linked, so
  every dependency travels inside them and its licence requires the copyright
  notice to travel too; `make notices` regenerates the file from what is
  actually linked.
- Installable with Homebrew from `Sec-CH-Lemon/homebrew-tap`, updated by the
  release workflow. Note that current Homebrew requires
  `brew trust --formula` for any tap outside its own repositories.
- Release assets are `.tar.gz` archives carrying the binary together with
  `LICENSE`, `NOTICE` and `THIRD-PARTY-NOTICES.txt`, rather than a bare binary
  beside loose licence files.
- Published to npm on a pushed `v*` tag. The binary reaches users as a
  platform-specific optional dependency — `@sec-ch-lemon/tls-forge-<platform>-<arch>`
  — so installing needs no Go, downloads nothing, and works under
  `npm ci --ignore-scripts`.
- A Dockerfile: Alpine plus the static binary, about 30 MB, running as a
  non-root user and carrying the licence notices. Published to
  `ghcr.io/sec-ch-lemon/tls-forge` on a pushed tag, for linux/amd64 and
  linux/arm64, cross-compiled rather than emulated. CI builds the image and runs
  the binary inside it, since nothing else in the repository would notice a
  Dockerfile that stopped working.
- `tls-forge capture` — launch the installed browser, measure what it sends, and
  write a reusable profile from it.
- `tls-forge compare` — measure the browser and the library against one local
  instrument and print them as a field-by-field diff, green where they agree and
  red where they do not, exiting 1 on a difference so it can gate a release.
  `--color auto|always|never` (honouring `NO_COLOR`) and `--full`.
- `tls-forge fetch`, `serve`, `daemon`, `profiles`.
- `fingerprint` — ClientHello parsing and local JA3, JA4, JA4_r and Akamai
  HTTP/2 fingerprints, plus a structural diff that names the field that differs.
- `echo` — a local HTTPS server that records the raw ClientHello, the HTTP/2
  preamble and the header order, and reports them back as JSON.
- `profile` — browser identities as committable JSON, synthesised from a
  capture; family-name resolution (`chrome` → newest measured Chrome).
- `daemon` — the JSON-lines protocol, and a Node client in `node/`.
- A measured Chrome 151 profile (macOS, arm64), verified against
  `tls.peet.ws`: JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`, HTTP/2
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`.

- The Node client is at 100% line and function coverage, and `npm test` now
  fails below it, the way `make cover` does for Go. Branches are gated at the
  level reached rather than at 100: Node reports a branch percentage without
  saying which branch is missing, and a number nobody can act on is not a
  target.
- A fuzz target for the daemon's request decoder, so all five places that read
  input someone else wrote now have one.
- `batch` is tested against a real recording proxy: two servers, two proxies,
  and an assertion that each proxy carried its own server's traffic and not the
  other's. The other proxy tests prove only that each URL *tried* its own
  proxy, by reading the refusals.

- `tls-forge batch` fetches a list of URLs concurrently, **each through its own
  proxy**. The list comes from a file, from `--urls` as a comma-separated
  string, from arguments or from standard input, in three formats: JSON (an
  array of objects or of bare strings), CSV (columns by name or by position),
  and one URL per line. One client is opened per distinct proxy and shared
  between workers, because the proxy is the identity and a cookie jar should
  not cross two exit IPs. Output is JSON lines, one per URL, and the command
  exits 1 if any URL failed. `--concurrency` sets how many pages are fetched at
  once; asking for more workers than there are CPUs prints a warning on standard
  error and carries on, since fetching waits on the network rather than on a
  core. In a container the count comes from the cgroup rather than from
  `runtime.NumCPU`, which reports the hardware and would answer 64 on a 64-core
  host however little of it the container may use. Both cgroup layouts are
  read, v2 then v1; `GOMAXPROCS` is left alone.

- Fuzz targets for the two parsers that read bytes their reader did not choose:
  `FuzzParseClientHello` and `FuzzLoad`. Run them with
  `go test -fuzz FuzzParseClientHello ./fingerprint/`.

### Changed

- **Flags follow the usual convention: one dash for a short flag, two for a
  long one.** `-b` and `--browser` are the same flag; `-profile` is now
  `--profile` or `-p`. Short letters on `fetch` are curl's (`-X`, `-d`, `-H`,
  `-i`, `-o`, `-x`, `-k`), since that is the command it replaces. Short flags
  bundle and long ones take `--flag=value`. Parsing moved from the standard
  library's `flag`, which treats `-x` and `--x` as one thing and has no notion
  of a short form, to `spf13/pflag`.
- A mistyped flag now exits **2** rather than 1. `compare` uses 1 for "the
  fingerprints differ", so a typo exiting 1 read, to the job watching for
  exactly that, as a broken impersonation.

### Removed

- A `#closed` check in the Node client's `#pump` that no input could reach:
  `request()` rejects while closed and `close()` empties the queue, so the two
  conditions it tested for cannot hold at once.

### Notes

- TLS extension order is shuffled per connection by default, as Chrome does.
  Turn it off with `WithFixedExtensionOrder` when impersonating a client that
  sends a stable order, such as Firefox or Safari.
- The echo server does not issue session tickets by default, so captures are
  always the cold handshake — a resumed connection carries `pre_shared_key` and
  therefore a different JA4.
