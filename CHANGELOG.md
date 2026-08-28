# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

A note specific to this project: **a new profile is not a breaking change, but a
changed default profile can be.** `WithProfile("chrome")` resolves to the newest
measured Chrome, so adding a profile for a newer browser changes what that name
means. Pin the exact name — `WithProfile("chrome_151")` — when that matters.

## [Unreleased]

## [0.1.0] - 2026-08-28

### Added

- **HTTP/1.1 fingerprints are measured rather than inferred.** Browser capture
  records exact wire casing, order and protocol-only values such as
  `Connection`; profiles store them separately from the lower-case HTTP/2
  block; the client selects the layout after protocol negotiation; and
  `compare` reports HTTP/1.1 differences alongside TLS and HTTP/2.
- **The daemon protocol carries bodies that are not text.** A JSON string cannot
  hold arbitrary bytes: an encoder replaces every byte that is not valid UTF-8
  with U+FFFD, silently, and the response still said `200` with no error — so a
  Python or Node caller asking for an image got back something no decoder would
  open. Both `Request` and `Response` gained a `bodyEncoding` field; a body that
  is not valid UTF-8 travels as `base64` and says so. The field is **absent**
  for text rather than spelled `utf8`, so every ordinary response is on the wire
  it has always been on. `Response.content` (Python) and `response.content`
  (Node) are the bytes exactly as they arrived; `body` remains the text view.
  Requests accept `bytes`/`bytearray` and `Buffer`/`Uint8Array` respectively.
- **A committed fixture of the wire format**, in `testdata/protocol/`, asserted
  against by the Go, Python and Node suites alike. The protocol is implemented
  three times and the two binding suites run against their own fakes, so
  renaming a response field passed every gate and shipped a release in which
  Python callers silently received no cookies at all. One rename now breaks all
  three suites. A separate smoke gate now drives the real Go daemon from both
  wrappers and checks binary bodies and repeated response headers end to end.
- **Binary bodies in `batch` JSON Lines are lossless too.** Invalid UTF-8 is
  base64 with `body_encoding: "base64"`; `bytes` remains the original length.
- `--report <directory>` creates the directory. The command shown in README and
  `example/README.md` used to fetch the whole list and then fail at the last
  step, losing the report and exiting non-zero on a run that had worked.
  Generated names use one colon-free format on every OS, so they are valid on
  Windows as well.

### Security

- The `serve` and `proxy` commands warn when their resolved listener is exposed
  beyond loopback without authentication. The security and API documentation
  now state the trust boundary for non-loopback binds.
- **Cross-origin HTTP/1.1 redirects no longer restore credentials or the source
  `Host`.** The measured layout is rebuilt from the headers the redirect policy
  allowed for the destination instead of replaying the first request's block.
- **The proxy no longer forwards `Proxy-Authorization` to the destination.** It
  is addressed to the proxy, not through it; forwarding it handed the user's
  proxy password to whatever site they browsed to. `Proxy-Authenticate` is
  dropped with it.
- The intercepting proxy retains at most 1024 generated leaf certificates per
  authority, evicting the oldest hostname instead of growing for the lifetime
  of the process.
- **Proxy passwords are no longer written into `batch` output.** The proxy URL
  reached the HTML report, the JSON lines and the terminal summary verbatim —
  all three of which are made to be kept and passed on, and the report is
  written to be mailed to someone. The username survives, because it is what
  tells two proxies apart; the password does not. Error text is scrubbed too:
  `url.Parse` quotes back the whole string it could not parse, so a mistyped
  proxy wrote its own password into the field that had just been cleaned.
  Scheme-less `user:pass@host` proxies are covered too, and HTML reports are
  created with mode `0600` even when replacing an older permissive file.

### Fixed

- **A second browser measured by one echo server was handed the first
  browser's fingerprint.** The server pinned the first connection that fetched
  the capture page and filed every later report against it, so the second
  browser to open `tls-forge serve` saw the first browser's ClientHello, JA4 and
  header order beside its own user agent — while the first browser's session had
  its navigator data overwritten with the second's. Each served page now gets a
  navigation token used by its report, so overlapping browsers cannot be paired
  by timing. Completed captures are consumed once, so a later measurement does
  not return the previous browser forever.
- **`Close()` hung forever on a connection accepted while closing**, in both the
  proxy and the echo server. A connection accepted between `wg.Add` and the
  handler registering itself was counted in the WaitGroup but missing from the
  snapshot `Close` closes, so `Close` waited for a peer nobody would ever
  disconnect. `Ctrl-C` on `tls-forge proxy` with a browser holding keep-alive
  connections did not return.
- HTTP/2 request flow control in the echo server is replenished as DATA is
  consumed, so a second body on one connection cannot stall at 65,535 bytes.
- Repeated proxy headers and repeated Go `Header` values remain separate on the
  wire. Legacy HTTP/1.1 profiles use canonical casing; newly captured profiles
  preserve the browser's measured spelling, with one `Host` first.
- HTTP/1.1 browser capture uses its own cold top-level navigation instead of a
  scripted redirect from the HTTP/2 page. `Sec-Fetch-Site` therefore remains
  `none`, `Sec-Fetch-User` remains present, and `compare` rejects a capture made
  in the old redirect context.
- Custom profiles without the four required HTTP/2 pseudo headers are rejected,
  instead of constructing requests missing `:method`, `:path`, `:scheme` or
  `:authority`.
- `MeasureSelfAt` no longer writes into spare capacity owned by the caller's
  option slice. Session export deduplicates cookies across URLs on one host.
- Netscape cookie files that spell include-subdomains as `example.com TRUE` are
  normalised to `.example.com` instead of silently becoming host-only.
- Invalid profiles in the local profile directory report the file and parsing
  error instead of falling through to another profile under the same name.
- Line-oriented batch input accepts any whitespace, including tabs, between a
  URL and its optional proxy. Repeated URLs keep distinct `--body-dir` files,
  and an overflowing `--repeat` value is rejected instead of panicking.
- Silent peers cannot retain an echo or proxy connection forever. Read and
  write deadlines roll forward while traffic makes progress and expire after
  30 seconds of inactivity.
- The echo server rejects HTTP/1.1 requests with more than 100 headers, so a
  peer cannot retain unbounded capture slices by continuously sending short
  header lines.
- JA4 and JA4Raw no longer append or hash a trailing underscore when a
  ClientHello has no signature algorithms, matching FoxIO's reference vector.
- Builds, examples and fallback instructions now use the supported Go 1.26
  toolchain consistently.
- Node no longer keeps the event loop alive while its daemon is idle, preserves
  unwritten queued requests across a transport exit, reports stderr by logical
  line, accepts `cookieFile`/`cookieSet`, and can import on an unsupported
  platform when `TLSFORGE_BIN` supplies the executable.
- Release tags now run lint, vulnerability and cross-platform Go gates. Actions
  use their stable major tags (for example `@v7` and `@v8`), and a failed or
  empty Chrome-version lookup can no longer create `profile/chrome-`.

### Changed

- `npm test` runs every `test/*.test.js` rather than one named file, so a new
  test file cannot be added and silently never run.

### Documentation

- `docs/protocol.md` said the whole header sequence could be dictated by naming
  every header in `order`. It cannot: the merge keeps the profile's position for
  every name the profile already has. Documented as the deliberate behaviour it
  is, since the profile's order is the fingerprint being impersonated.
- `docs/profiles.md` told maintainers to refresh the shipped profile with
  `tls-forge capture --headless`, contradicting the same page's warning two
  sections earlier. Following it would have made every library user impersonate
  `HeadlessChrome` by default.
- `NOTICE` named `profile/data/chrome_151.json` in its licence carve-out, a file
  that does not exist — the three real files are under `profile/data/chrome_151/`.
- `GO.md` never documented `Client.Profile()`.
- The Russian article described JA4's ALPN field as "the first offered ALPN". It
  is the first and last **characters** of it, which `h2` hides and `http/1.1`
  — rendered `h1` — does not.

- **The Windows test job hung for five minutes and then failed.** Three separate
  things, all of them the tests rather than the code. `--ca-cert
  /no/such/root/ca.pem` is unwritable only where the root is: on Windows it
  resolves against the current drive, the directory is created, the proxy
  starts, and the command blocks on a context nothing cancels — the test now
  blocks the path with a file, which fails everywhere, and `exec` in the tests
  carries a deadline so no command can wedge the package again. Tests that
  produce a failure by chmod-ing something read-only are skipped there, because
  Windows has no Unix permission bits and the write they need to fail succeeds.
  And `-o /dev/null` is `os.DevNull`, which is `NUL` there.
- The test that checks where the proxy keeps its authority redirected `HOME` and
  `XDG_CONFIG_HOME` and said in a comment that this kept it out of the real
  config directory. On Windows `os.UserConfigDir` reads neither — it reads
  `AppData` — so the test wrote a CA private key into the runner's actual user
  profile and then failed to find it where it had looked. It sets all three now,
  derives the path the way the command does instead of guessing each platform's
  layout, and fails loudly if the redirection ever stops taking.

- **The capture workflow measured a Chrome almost nobody runs.** `setup-chrome`
  with `chrome-version: stable` installs Chrome for Testing's newest stable
  build, which is not the same thing as the build being served: with 152 already
  in the channel, 151.0.7922.138 was at 99% of the rollout and 152.0.7977.42 at
  0.5% — because Chrome promotes a major version by serving it to a slice of
  users and widening it over days, so several versions are stable at once. A
  profile is worth having only in so far as it looks like everybody else, so a
  fingerprint half a percent of Chrome sends is nearly as identifying as a
  home-made one. The run now asks Chrome's release data what is actually being
  served and measures the most widely served build, which also means the choice
  moves on its own as a rollout progresses. A rollout split across builds of one
  line settles the line first; a build Chrome for Testing does not publish falls
  back to the newest of that line and says so. `--channel beta` looks ahead on
  purpose, and an exact build can be named.

- **A runner installed Chrome 150 while Google was serving 151.** A runner image
  is built every few weeks and everything in it freezes at that moment,
  Homebrew's cask metadata included: the cask itself pointed at 151.0.7922.138
  and the runner's snapshot of it did not. Chrome is now fetched from
  dl.google.com on all three platforms rather than through a package manager or
  whatever the image came with, and a run stops if the version it got is behind
  the one being served. Ahead is allowed and noted — that is an early slice of a
  rollout, which is worth seeing rather than refusing.

- **A capture from a CI runner was of the wrong browser.** `setup-chrome`
  installs Chrome for Testing, which is not Chrome. Measured on one machine,
  same version, headless both times: it sends `sec-ch-ua: "Chromium";v="151",
  "Not=A?Brand";v="99"` where Chrome sends `"Not=A?Brand";v="99", "Google
  Chrome";v="151", "Chromium";v="151"` — it announces itself as Chromium on
  every request, and no flag changes that, because the branding is compiled in.
  Its TLS differs too: it turns on the testing field-trial configuration and
  with it experiments real users do not have, sending 20 extensions against
  Chrome's 18, the extra two being `0xCA34` (TLS trust anchor identifiers) and
  `0x12E0`, which utls does not know and which therefore would not even load.
  `--disable-field-trial-config` fixes the TLS half and nothing else, so the
  workflow installs Google Chrome itself instead. The cost is that the version
  can no longer be chosen — Google serves the current stable and nothing else —
  so the run reports what is being served next to what it measured, and drops
  the inputs that promised a choice it cannot make.

- **The capture workflow could not capture anything.** Chrome's sandbox does not
  work on a hosted runner and fails silently: the browser starts, never loads
  the page, and the measurement times out having watched something that was
  never going to answer. `--browser-arg` passes flags through to the browser —
  `--no-sandbox` is the one CI needs — and it is for the machine rather than the
  measurement, since process isolation is not TLS.
- **`chrome.exe --version` on Windows launches the browser** instead of printing
  a version and exiting. The step that read it sat for seven minutes emitting
  Chrome's startup logs before the job was cut off. Windows keeps the version in
  the file itself, and it is read from there now.

- **A hanging job now fails instead of hanging.** Every CI job has a ceiling,
  and `go test` is given a `-timeout` well under it, so a test that wedges is
  killed by Go — which prints a goroutine dump naming it — rather than by the
  runner, which prints nothing and leaves the next person guessing. The whole
  suite takes seconds; five minutes is a wide margin, not a target.

- **The library would not start on Windows at all.** `chrome_151` is a directory
  of captures, one per platform, and no Chrome has been captured on Windows yet.
  A version name resolved to this machine's platform or, failing that, to the
  only capture there was — and with two, it resolved to nothing. So `chrome_151`
  was unknown, `chrome` was unknown, the default profile was unknown, and
  `tlsforge.New()` returned an error that named `chrome_151` in the list of
  profiles it said it did not know. It now falls back to the first capture in
  sorted order, which costs nothing that matters: Chrome carries its own
  BoringSSL, so the ClientHello is the same on every platform, down to the byte.
  Only the user-agent differs, and a profile that says macOS is a coherent
  identity from anywhere. `profiles` marks the one that will be used, as before.

- **The command `tls-forge proxy` prints could not be copied on macOS.** The
  authority lives under the user's config directory, which on macOS is
  `~/Library/Application Support`, so the suggested `curl --cacert <path>`
  arrived at curl as two arguments: it read `/Users/me/Library/Application` as
  the certificate and tried to fetch `Support/tls-forge/ca.pem` as a URL. Paths
  and names going into a printed command are now quoted when they need it, in
  `proxy` and in `capture --install`, which prints a `--profile` whose name the
  caller chose.

- **Ctrl-C did nothing to `tls-forge batch` waiting on standard input.** Run
  with no list, the command waits for URLs to be typed; the interrupt was caught
  and turned into a cancelled context that the blocked read never looked at, so
  it was swallowed, and so was every one after it. The read now happens on a
  goroutine of its own and the first interrupt ends the command; any after the
  first are handed back to the runtime, so a command stuck anywhere else still
  dies on the second.
- `batch` with nothing to read says it is waiting for input rather than going
  quiet, which is what made this look like a hang in the first place.

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

- **A weekly check that the shipped profile still matches a real Chrome, which
  measures a new one and opens a pull request when it does not.** The one thing
  here that breaks without anyone touching it: Chrome ships a new major every few
  weeks and the handshake moves with it. The job installs Google Chrome on a
  runner, runs `compare`, and on a difference calls the capture workflow — rather
  than repeating it — to measure all three platforms, proves each profile by
  fetching a page with it, and opens a pull request assigned to whoever
  `PROFILE_REVIEWER` names. One branch per version; an issue instead when the
  drift is real but nothing could be measured; silence when it all still matches.
  It does not merge: a profile is a measurement, and a fingerprint almost nobody
  sends ships when nobody looks.
- `capture` is callable as a reusable workflow, so the knowledge that a runner
  needs `--no-sandbox` and that Chrome for Testing is a different browser lives
  in one place.
- `compare` exits **3** when the client and the browser differ, keeping 1 for a
  comparison that could not be made. They shared a code until something needed
  the difference: a scheduled check that read "the browser would not start" as
  "the profile has drifted" would file a bug report every week for a broken
  runner.

- **`capture --install` files the profile as `local`, and every run wears it.**
  One name rather than one per version: there is one browser on a machine, and
  measuring it again after an update should replace what is there. A command
  that fetches now prefers it over a shipped profile without being asked, which
  is the point of having measured it — a shipped profile is a recording of
  somebody else's browser on an earlier day.
- **Every command that fetches says which profile it is wearing**, on standard
  error, before it starts: the profile and where it came from, the browser and
  version read out of the user-agent, the file it was read from — or `built into
  tls-forge` — and the user-agent in full. Which browser a request is pretending
  to be is the one thing this program does and the one thing otherwise
  invisible: a run wearing a profile measured six months ago looks exactly like
  a run wearing the right one. The `profiles` listing marks the same default,
  from the same rule rather than a second copy of it.
- `profile.Profile.Source()` says which file a profile was read from, so the
  line above can name it. Unexported underneath, so it can never reach the JSON
  and be mistaken for part of the profile.

- **The Python package is released by tag**, alongside npm, Homebrew, the
  GitHub Release and the image. `scripts/pypi-release.py` builds one wheel per
  platform with the binary inside, and refuses to produce one that is missing
  the binary, has lost its exec bit, or lacks the licence notices — three ways
  to ship something that installs and then does not work. Linux gets one wheel
  carrying both a manylinux and a musllinux tag, since the binary is static;
  checked on glibc and on Alpine. Uploads use PyPI Trusted Publishing, so there
  is no token to store or rotate. [RELEASING.md](RELEASING.md) is what to set
  up, once.
- CI runs the whole packaging path on every push — cross-compile, both
  packaging scripts, then install the built wheel and run the binary out of it
  — so a tag is not the first time any of it runs. `make dist` does the same
  locally without publishing.

- The README's Python section is a section rather than a mention: what a
  `Response` carries, which exception means what, and the pool-of-clients shape
  a script actually reaches for, every snippet run before it was written down.

- **A Python client**, in [`python/`](python/): `pip install tls-forge`, then
  `import tlsforge`. Same daemon protocol as the Node client, and the same
  identity model — one `Client` is one process, one fingerprint, one jar, one
  exit IP — with a context manager, a frozen `Response` carrying `.ok` and
  `.json()`, and an exception per thing worth doing about it. No dependencies,
  and the binary ships in the wheel, so nothing is downloaded at install time.
  A client serialises rather than pretending a session can overlap itself;
  parallelism is a pool of clients. Measured against the real transport: the
  JA4 it produces is Chrome's. At **100% line and branch coverage**, gated by
  `make python-test`, with the suite running against a stand-in transport so it
  needs no Go build and no network.

- **`tls-forge proxy`**: a proxy that re-sends whatever is pointed at it with
  the browser's handshake, so an existing script needs one environment variable
  rather than a rewrite. Measured: curl through it produces Chrome's JA4, HTTP/2
  fingerprint and header order instead of its own. It terminates TLS, because a
  tunnelled CONNECT would carry the caller's fingerprint through, so clients
  must trust the authority it generates; that authority is kept under the user's
  config directory and its power is spelled out where it is documented.
- `WithoutCookieJar`, which the proxy needs: it forwards its caller's Cookie
  header and a jar underneath would add a second one from its own store.

- A measured `chrome_151_linux` profile, captured from a headed Chrome
  151.0.7922.137 on Linux. Its handshake is identical to the macOS one: same
  JA4, same JA4_r, same HTTP/2 fingerprint, same header order. Chrome carries
  its own BoringSSL, so the ClientHello does not depend on the platform. What
  differs is the user-agent and `sec-ch-ua-platform`, which is what a
  per-platform profile is for.
- A `capture` workflow that measures Chrome on macOS, Windows and Linux runners
  and offers each profile for download. No Windows profile has been invented in
  the meantime. It names nothing: the version comes from the browser it measured,
  so it captures whatever Chrome is current on the day it runs rather than
  filing a Chrome 152 capture under 151. Each run says which Chrome it was, what
  a third party sees through the profile, and whether the committed profile
  still matches that browser — and refuses to offer a capture that is not
  indistinguishable from the browser it came from.

### Fixed

- `capture --json` and `compare --json` printed a line of commentary on standard
  output ahead of the document, so redirecting either to a file produced JSON
  that would not parse. It goes to standard error now.

- **A place to keep profiles measured on this machine.** `capture --install`
  writes one into the user's config directory, and `--profile` finds it there by
  name, ahead of the profiles that ship. That order is the point: a Chrome
  captured here beats the one shipped, because it is the browser a server will
  compare against. `TLSFORGE_PROFILES` moves the directory, `profiles` marks
  the local ones and prints the path, `--save` given a directory names the file
  after the profile, and `--profile` also takes a path to a file anywhere.

- The **Netscape cookie file** (`cookies.txt`) is read and written: the format
  curl writes with `-c` and reads with `-b`, and what wget, yt-dlp and every
  browser cookie-export extension produce. Checked against curl in both
  directions. `--save-cookies` writes one when the name ends `.txt`, and
  replaces rather than appends, because a cookies.txt is a jar rather than a
  collection of sets.

- An `example/` directory: one of every file the tool reads, in every format,
  with a README of the commands that use them. Every command in it was run
  against those files and the output shown is what came back.

- **Warmed cookies.** `--cookie name=value` hands a request one by hand;
  `--cookies FILE` takes a warmed session from a file; `--cookie-set ID` names
  which one, and without it one is drawn at random; `--save-cookies FILE` writes
  down what a run ended up holding. Shared by `fetch`, `batch` and `daemon`.
- A `cookie` package and a file format: sets rather than cookies, since a
  session is the unit that was warmed. A bare array of sets and a browser
  extension's flat export are read as well, `httpOnly` and `expirationDate`
  included. Expired cookies are left out of a run and counted.

### Fixed

- A usage error printed its message on standard output, where pflag writes, and
  not on standard error with every other diagnostic. It is now said once, on
  stderr.
- `tls-forge version --help` printed the version rather than the usage, because
  that command parsed no flags at all.

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

- **Profiles are laid out as a directory per version holding one file per
  platform**, `chrome_151/macos.json` and `chrome_151/linux.json`, and
  `capture --install` writes into the same shape. `chrome_151` now means the
  variant for this machine's platform, `chrome_151_macos` names one outright,
  and a flat `<name>.json` still works for one written by hand.
- `profiles` groups the listing by version, prints every line as a name that
  can be copied into `--profile`, stars anything kept on this machine, and
  marks the one a run lands on when no profile is named. It lists names rather
  than user-agents: the question it answers is what is there and which one you
  get. What shipped and what is local are shown together, since both resolve.

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
  red where they do not, exiting 3 on a difference so it can gate a release.
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
  `tls.browserleaks.com`: JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`, HTTP/2
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
- A mistyped flag now exits **2** rather than 1. `compare` uses 3 for "the
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
