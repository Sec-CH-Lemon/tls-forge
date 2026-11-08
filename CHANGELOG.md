# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

A note specific to this project: **a new profile is not a breaking change, but a
changed default profile can be.** `WithProfile("chrome")` resolves to the newest
measured Chrome, so adding a profile for a newer browser changes what that name
means. Pin the exact name — `WithProfile("chrome_151")` — when that matters.

## [Unreleased]

- `published-e2e.yml` asks for the Go module by the path its version has:
  unsuffixed for v0 and v1, `/vN` from v2 on. It asked for `/v4`, a label of
  an unpublished engine snapshot, and its check of 1.0.1 failed before the
  Node.js and Python packages were tried; on macOS all three passed against
  the published 1.0.1.

## [1.0.1] - 2026-11-08

The first release of engine major 1 published in full: 1.0.0 with what
stopped its release at npm fixed. 1.0.0's release reached PyPI alone, and
its set, which can never be built again, was let go of as RELEASING.md says:
the engine, the CLI and the Node.js and Python packages are 1.0.1, and
nothing else changed.

### Fixed

- Fix: a release gives npm its packages as files. `release-publish.mjs`
  named each `set/tls-forge-….tgz`, its path joined to the workflow's
  `--dir set`, which npm reads as a GitHub repository (one slash, as
  `user/repo`) and asks git for: 1.0.0's `publish-npm` failed so, before
  publishing anything. Each is given by its whole path now. A dry run never
  calls `npm publish`, and the tests' npm was given paths of a temporary
  directory, which npm reads as files: it reads every spec it is given with
  npm's own npm-package-arg now, and a set named as the workflow names it is
  published through it.

## [1.0.0] - 2026-11-08

Published to PyPI alone: its release stopped at npm, before any of it
reached npm, GitHub Releases, Homebrew or the container registry; 1.0.1 is
this release with that fixed. The first release of engine major 1, after
0.2.2. The compiled engine, the CLI
and the Node.js and Python packages are 1.0.0.

### Breaking changes and migration

- Every executable JSON profile requires an exact integer `engine_major: 1`.
  Missing, malformed, older or newer metadata is rejected before DNS, sockets,
  proxy setup or origin traffic. The gate also covers programmatic profiles,
  catalogue entries, clones, SDK requests and daemon replacement processes.
- Profile format is schema4 and daemon protocol is3. Update the CLI and SDKs
  together. Legacy daemon compatibility is refused. Use `profile.Inspect` for
  offline archives; explicit migration creates a separate candidate requiring
  validation and preserves the original profile and capture provenance.
- The Go module remains `github.com/Sec-CH-Lemon/tls-forge`, without `/v1`.
  Release tags and package stamps must equal `engine/version.json`; further
  changes before publication remain in this single pending engine major1.
- The default `chrome` profile selects 157 for the host platform. Pin an exact
  profile name when changing the default would change an application's contract.
- By default each logical `Client.Do` starts an isolated browser instance:
  cookies, cache, transport/TLS/QUIC sessions and network observations belong to
  that request. Redirects and Critical-CH restarts retain their own chain state.
  Profile scope choices are explicit; a raw transport option cannot replace the
  owner-selected profile adapter with an unversioned preset.

### Added and changed

- Record the complete 1.0.0 release dry-run: 30 successful CI jobs, 19 successful
  release jobs and 5 expected publication skips. All 3 native Chrome 156 gates and
  all 8 fork graphs passed; exact source/set and limitations are in the
  [readiness receipt](research/releases/1.0.0-readiness.json). It published nothing.
- Preserve original Go coverage profiles after success or failure as
  `go-coverage`/`release-go-coverage` artifacts for7days; coverage stays100%.
- Require the complete413response in the proxy body-limit test before
  closing its caller/server. Preserve the body bound and100%coverage gate.
- Fix an HTTP/2 preface PING being suppressed by a fast peer response during
  HEADERS Write. Decide before HEADERS I/O, keep the separate PING after it.
  JSON timers/IDs and existing wire/deadline checks remain unchanged.
- Use a Windows release-browser reference for the two measured SSPI auth
  scenarios: two independent Chrome156.0.8078.80/Windows26100 cohorts agree
  exactly. Preserve the other226scenarios, all228perOS and all174decodings;
  token/request mutations remain strict failures. Original macOS fixture unchanged.
- Allow the registered capture workflow to call the same release-auth oracle
  explicitly; default capture and every strict release gate remain unchanged.
- Calibrate Windows release-browser auth fixtures in two native cohorts,
  retaining every scenario, exact SSPI bytes and the original15s observation.
  Add an encrypted, manual-only evidence workflow and explicit fixture
  `observation_ms`; unfinished or silent measurements cannot become fixtures.
- Refresh only Chrome156 full-version/full-version-list hints from measured
  Google Stable builds:156.0.8078.79 on Linux and156.0.8078.80 on macOS/Windows.
  Keep close_notify variants aligned. Preserve exact prior bytes and append
  an explicit derivation; original capture and A13 hashes stay unchanged.
- Render Python API defaults from their source expressions, preserving host
  dependence such as `sys.platform` without freezing the documentation builder's
  OS. Require identical actual-SDK reference output for three platform contexts
  and retain detection of source/default changes.
- Rebuild public documentation in `docs/` with installation paths, task guides,
  CLI/Go/Node.js/Python examples and source-generated reference pages. Move
  historical reports and evidence to `research/` without including them in the public MkDocs site.
- Style the documentation with the landing page's glass panels, colors and
  local Inter font. Use Stripe-inspired UX with sticky section tabs, a
  contextual desktop sidebar and a three-column grid with equal side rails,
  centered reading column and search, aligned tables and code examples,
  compact mobile drawer and tabbed examples. Match
  Stripe's measured reading and code scale: 16px/26px body copy, 32px/40px
  page headings, 14px table cells and 13px/19px Menlo/Consolas code. Add
  numbered code lines, a distinct code header and aligned mobile table and
  example edges; short tables become labeled cards on phones, while wider
  matrices scroll horizontally. Frame tables and code with symmetric corners;
  center search, repository and copy icons in their controls. The home terminal
  command wraps at spaces, and copy controls sit in code headers so they do not
  cover code. Keep both themes readable across desktop and mobile,
  including full-screen mobile search. Keep the theme override in `docs-theme/`
  and the styles in `docs/assets/extra.css`; check rendered HTML-card links
  before deployment.

- Browser JSON owns supported values, vectors, ordering, header templates,
  generation rules, protocol policies, limits, retries and timers. The engine
  implements generic parsing, state transitions, cryptography, I/O and resource
  bounds. Strict unknown/duplicate/type/range checks apply before execution.
- Add profile-driven dynamic QPACK, HTTP/3 stream setup and feedback, QUIC
  transport/layout/ACK policies, TLS/HRR/ECH handling, ALPS, DNS HTTPS and Alt-Svc
  negotiation. Unsupported capabilities fail explicitly rather than falling back.
- Represent the83-entry catalogue and its native QUIC choices as explicit pinned
  JSON. Catalogue support does not establish fresh browser equivalence for every
  historical preset or platform.
- Replace captured RTT/downlink/ECT literals in existing155/156 profiles with
  JSON-selected network observation and generation policies: actual HTTP/TCP/QUIC
  inputs, instance salt, host rounding and isolated lifecycle. Add typed actual
  `NetworkContext` metadata across Go, daemon, Node and Python. Historical151–154
  profiles preserve their previous absence of network hints.
- Align connection ownership, proxy discovery, draining and site-pool lifetime
  with request cancellation and body ownership. Keep concrete transport bodies
  compatible with their existing buffering and drain machinery.
- Improve CLI request/page checks, error classification, capture/compare,
  redacted diagnostics, traces and packet output. The command and flag reference
  is in [README.md](README.md).
- Keep the existing release gates and distribute one verified immutable set of
  five native archives, six npm packages, one Python sdist and five wheels,
  licence notices and a Homebrew formula. Linux race partitions the complete
  compiled root and CLI test/example/fuzz inventories across two runners each
  and retains all other packages. A separate manifest gate requires one
  source, disjoint complete selections and successful execution. Every binary
  retains20m; normal tests retain all three OSes with10m limits. Set storage
  waits for every gate.

### Security and correctness

- Derive strict release-gate network-hint availability from the declared,
  implemented JSON generator. Preserve all original scenario/header checks and
  add canonical syntax, bounds, quantization and ECT-vocabulary validation.
  Missing/disabled generators and malformed values remain failures; actual
  H1/H2 Client.Do controls verify JSON availability and origin opt-in.
  The JSON result retains original generated-hint samples and normalization
  metadata, including on successful comparisons.
- Bound HTTP/2 HPACK/CONTINUATION processing, chunk parsing, content-decoding
  layers and response/header memory. Keep malformed-input controls and bounded
  resource regressions.
- Authenticate TLS Finished/ECH paths, rebuild PSK binders after HRR, bound
  compressed-certificate decoding and revalidate cached certificate chains
  against current trust roots and time.
- Fix URL/IDNA edge cases, cookie validation, HTTP framing, QPACK arithmetic,
  blocked-section cancellation, queue ownership and local SETTINGS ordering.
- Protect capture paths with scoped names and filesystem roots; bind navigation
  tokens to their visitor. Export TLS secrets only by explicit opt-in, strip
  inherited SSLKEYLOGFILE at SDK daemon starts, and redact proxy credentials and
  sensitive diagnostic URLs without altering the transmitted application data.
- Preserve complete bodies and actual protocol/connection counts in test peers;
  Alt-Svc readiness waits for client pool publication, not peer handshake alone.
  Python backpressure controls complete offline hello before timing a body write
  and require an actual blocked writer at stop; the0.2s request deadline,2s
  elapsed bound, cleanup and SessionReset assertions remain.

### Validation and limits

- The completed product acceptance includes native Linux/Windows/macOS CI,
  Linux100% statement coverage across24 packages, full Linux race coverage and
  eight exact-source fork graphs. Existing fork skips remain explicit. See the
  [native acceptance report](research/remediation/2026-11-01/Network-hints-native.ru.md).
- The finite Chrome156.0.8078.80/macOS comparison covers network hints, cold
  TLS/H1/H2 and selected H3/QPACK and request sequences. It is not a claim of
  universal browser indistinguishability, RNG distribution equality or new
  historical/all-platform browser acceptance. See the
  [browser comparison](research/remediation/2026-11-01/Network-hints-final.ru.md).
- Default request isolation is preserved. Physical network-change notification
  and complete process-wide network-quality estimation remain outside this
  accepted scope; profiles cannot replace the host TCP/IP implementation.
- Browser profiles preserve owner-selected deviations for TLS close_notify,
  macOS delayed ACK, early QUIC application close and replay policies. Explicit
  alternatives and their consequences are documented in
  [support boundaries](research/support.md). Browser fidelity does not imply complete
  RFC compliance or make a non-idempotent replay safe.
- A retained macOS ACK timing-control failure has an unconfirmed cause; the same
  full job passed one unchanged repeat. This is not reported as a fixed cause.
- Release-specific acceptance, including the strict three-platform browser gates
  and the exact built set, is tracked in the
  [release readiness receipt](research/releases/1.0.0-readiness.ru.md).

### After the candidate of 1 November

- The release dry run (run 42477990184, 19023de9) passed every job at the
  first attempt, the three pinned gates among them, `chrome` (Chrome 157) on
  Google Chrome Stable of each platform. CI on `main` after it (runs
  42503015111 and 42503015118) found what the entries below fix.

- Fix: what an HTTP/2 connection writes while a write its server does not
  take is held no longer holds up the client's other requests. The fork of
  fhttp took the server's SETTINGS, a body read's WINDOW_UPDATE, a body let
  go of, what it frees at once of a frame and a shutdown's GOAWAY under the
  connection's lock while each waited for the held write; the pool asks every
  connection under its own lock whether it takes a request, so a request to
  any host waited too, and nothing bounded it while the server kept sending.
  Each is decided under the lock and written without it now, as in x/net, and
  the SETTINGS are taken in the turn of the connection's header blocks, so
  that a block encoded before them goes before them and none encoded for them
  goes before their acknowledgement.

- Fix: `fetch --pcap` keeps the secrets of a QUIC connection that the key log
  wrote before the capture had the connection's hello. A QUIC socket tells
  the capture of a datagram once it went, by when the server may have
  answered and the handshake written its secrets: an accepted ECH offer's
  inner hello lost its four lines so, now and then. The lines of a random no
  connection has sent yet wait for one, 64 at most, as an ECH offer's did.

- Two tests timed on a loaded runner now leave room for it: a Python request
  waiting behind one that times out starts half the timeout after it, and a
  QUIC ACK on its timer is looked for in eight runs, not three.

- Add Chrome 157: `chrome_157_macos`, `chrome_157_linux` and
  `chrome_157_windows`, captured headed on Google Chrome Stable 157.0.8103.39
  (macOS, Windows) and 157.0.8103.38 (Linux), with the Chrome 156 profile of
  each platform as the policy basis. `chrome` is Chrome 157 now; pin
  `chrome_156` to keep 156 (see the note above). What the capture measured is
  its handshake, which offers the extensions 156's does, and its headers:
  the brands `"Not-A.Brand";v="99"`, `"Google Chrome"` before `"Chromium"`,
  and the build. Everything else, timers, limits, HTTP/3, the cache and the
  rest of `behavior`, is 156's unchanged, as its provenance in
  `profile/provenance/chrome_157/` says field by field: carried over, not
  measured again.

- Chrome 156 captured again, on the last build of 156 of each platform:
  `chrome_156_macos` and `chrome_156_windows` on Google Chrome
  156.0.8078.80, `chrome_156_linux` on 156.0.8078.79, headed, from the
  pinned installers (`capture.yml`, runs 42463760501 and, for Windows,
  42463984662), with the `chrome_156` they replace as their policy basis.
  They were captured on 156.0.8078.74 (Linux .73) and said a later build
  since; now the build they say is the one they were captured on. The
  handshake is the one captured before, its draws aside, and the headers
  are; the client hints are, but macOS's platform version, 26.7.2. Every
  policy is the replaced profile's, unchanged. The replaced files, their
  capture provenance and the `close_notify` variants of
  `example/profiles/` are kept by their hashes in
  `profile/provenance/recaptured/` (`recaptured.json`), where the layers of
  provenance before the capture end; the variants are made again of the new
  profiles.

- Hold Chrome 157 to the bench as it behaves. The bench (`internal/harness`)
  runs the scenario of a cached preflight with its certificate trusted:
  Chrome 157 keeps no preflight answered over a certificate it took with an
  error (`PreflightController`), which `--ignore-certificate-errors` alone
  left it, and so asked a second OPTIONS within Max-Age where a site's
  certificate gets none. A URL typed that the browser connects for and then
  sends nothing to is `blocked`, where it stopped the measurement of URLs:
  Chrome 157 shows a warning (HTTPS-First, on by default since 157) where 155
  fell back to http once https failed. One it does not even connect for still
  stops it. `testdata/chrome157-urls.json` is what Chrome 157 sends for each
  URL case, and what `measure` holds a browser to unless told otherwise: the
  two cases of a name whose https fails are `blocked`, the other 56 as Chrome
  155's. tls-forge sends what it is asked, as before: it does not model
  HTTPS-Upgrades.

- Require `github.com/andybalholm/brotli` v1.2.7 and
  `github.com/klauspost/compress` v1.20.2, which fix what govulncheck found
  reachable from the decoding of a compressed answer: GO-2026-6888 (a crafted
  Brotli stream made the decoder allocate without bound) and GO-2026-6865 (a
  Zstandard frame of two blocks made it panic).

- Run the CLI's tests under race, as the root's, in two Linux partitions of
  its complete compiled inventory, each on a runner of its own, in CI and in
  the release; the go-root-inventory gate holds them to that inventory as it
  holds the root's. In one run they had passed the 20 minutes every test
  binary keeps, beside every other package on one runner.

- Run the checks on the oldest Python, 3.9, on Ubuntu 24.04 in CI and in the
  release: `ubuntu-latest` is Ubuntu 26.04 now, for which no Python 3.9 is
  built, and the package smoke test of the release stopped there.

- `capture.yml` takes `gate`: it captures nothing, and holds the shipped
  profile of the browser's major to it as the release's pinned gate holds the
  newest Chrome to Stable, on Chrome Stable or on the pinned Chrome 156
  installers (`browser: 156`), so that `chrome_156` can be held to Chrome 156
  now that Stable is 157 ([research/pinned.md](research/pinned.md)).

- The pinned Chrome 156 installers are the last builds of 156,
  156.0.8078.80 on macOS and Windows and 156.0.8078.79 on Linux: the builds
  `chrome_156` says in `sec-ch-ua-full-version`, which the gate holds it to.
  They were 156.0.8078.74 and .73, older than the profile, and the gate
  failed on the build alone. `capture.yml` takes `policy-from`, the profile
  whose unmeasured policies a capture inherits (`capture --policy-from`);
  without it, the newest shipped of the family and platform, which for a
  Chrome 156 capture is now Chrome 157's.

- Changed: without `--profile`, `fetch`, `proxy` and `daemon` wear `chrome`,
  the newest Chrome, shipped or kept on this machine under its version. A
  browser measured here with `capture --install` was worn whenever it was
  there, which left a run on the Chrome of the day it was measured once newer
  ones had shipped; it is worn now when it is named, `--profile local`. The
  SDKs, which start the daemon without a profile unless one is given, change
  with it, and the `profiles` listing marks the newest Chrome.

- Add `fetch --random-profile`: each request wears a profile drawn for it from
  every browser measured, shipped or kept on this machine, that this build can
  wear (one made for another engine major is left out, as are the handshakes
  of tls-client's catalogue). A request keeps its profile for all of its
  tries; each repeat draws its own. The run's header lists what it draws
  from, and how many are another platform's, whose TCP/IP a server can tell
  from this machine's; each result line (`profile`), the run log, a kept
  request and both reports say what each request wore. Profiles that cannot
  send the run's requests as the newest Chrome sends them are left out of the
  draw. It refuses `--profile` and `--reuse-connection` as usage errors.

- Write the Node.js package in TypeScript. Its sources are `node/src/*.ts`,
  published compiled into `dist/` with the declarations the compiler writes
  from them, so `dist/index.d.ts` is what the code is rather than a copy kept
  by hand beside it: the old one gave `ENGINE_MAJOR` the description of
  `Hello` and `networkContext` none. What the package exports, does and runs
  on, Node 20.12 and newer, is unchanged; `main`, `types` and `exports` name
  `dist/`, which a release compiles afresh with `node/scripts/compile.ts`.
  That script also writes the declarations' imports of one another as `.js`,
  which TypeScript before 5.0 needs. The tests are TypeScript as well, run as
  they are written by Node 22.18 or newer, and `npm test` type-checks the
  sources, the tests and the script in strict mode before it runs them; CI's
  Node 20.12 leg runs the suite compiled in place. Working on the package
  needs `npm ci` in `node/` first (TypeScript 5.9.3, `@types/node` 20).

- Security: keep what a caller gave at the origin it asked for when a page is
  reloaded. `Request.Reloaded`, and so `fetch --retry-as-browser`, reloaded a
  page that a redirect had taken to another host. It then filed the request's
  cookies and the client's warmed ones (`Request.Cookies`, `WithCookies`, `-b`)
  for that host, and sent the client's credential fields (`WithHeaders`)
  there. The redirect's own hop had carried none of them. A reload now
  remembers the URL first asked for, through reloads of reloads; a reload back
  at that origin carries them again.

- Fix a TCP connection that lost the race to QUIC taken for alive after its
  server closed it, where it was dialed with ECH or under `fetch --pcap`.
  tls-client looks at the socket of a connection waiting to be taken up
  through `NetConn`, which tls-forge's ECH connection and the wire's lacked:
  a closed one waited out its minute and could be handed a request, which then
  went again on another.

- Keep responses in a browser context's cache as Chrome keeps them, and for
  as long, as measured on Chrome 156: a response of any status that says it
  may be kept; a 300, 301, 308 or 410 with no freshness of its own fresh for
  ever; a 200, 203 or 206 with none fresh for a tenth of the time since its
  Last-Modified, unless it says must-revalidate; a response's
  `Pragma: no-cache` taken as its `no-cache`; only a kept 200 asked again
  conditionally; and a request's `Cache-Control: no-cache` or
  `Pragma: no-cache` sent with no condition, its answer kept, where it was
  sent conditionally. The Chrome profiles say it in eight `cache.` keys. utls
  4b54ea5.

- Fix `--pcap`, `--keylog` and `WithKeyLogWriter` for a connection whose
  Encrypted Client Hello the site accepted, over TCP and QUIC: its secrets
  went by the inner hello's random, which nothing in the file opened, so
  Wireshark read none of it, and `--pcap` left them out. The key log now says
  what opens the inner hello, by the outer hello's random, as NSS writes it
  (`ECH_SECRET`, `ECH_CONFIG`), and `--pcap` opens it to keep the inner
  hello's secrets with the connection; Wireshark 4.6.9 reads such a capture
  whole. The ECH configs from DNS that the Chrome profiles offer made every
  such run's capture unreadable. utls cacbae0.

- Keep a cookie its host's alone apart from one of a `Domain` naming that
  host, as Chrome keeps them: both are sent, in the order they were set, and
  each is replaced and removed by its own kind alone. Go's jar took them for
  one cookie, the second replacing the first, so a site that set both got
  one back. The Chrome profiles say `cookie.identity`; a jar of the caller's
  keeps its own rule. utls 5d91e3d, fhttp 6959ccf.

- Refuse a ServerHello with an extension BoringSSL does not take of it, as
  Chrome refuses it: one the client did not offer, one of TLS 1.2 in a TLS 1.3
  ServerHello, one twice, or a list that does not read, each with the
  profile's alert, in a record of the version as BoringSSL writes it. A
  ServerHello whose legacy version is not TLS 1.2 is that version, whatever
  supported_versions says. crypto/tls passed over what it does not parse, so
  a server could tell tls-forge from Chrome by an extension it took. The
  Chrome profiles say `tls.validate_server_hello_extensions`. utls e05e87a,
  b2148a9, 5d680c3.

- Keep a TLS session by the host and port it came from, as Chrome keeps it,
  over TCP, QUIC and a websocket. A ticket a server gave on one port was
  offered on another of its name, which Chrome never does. The Chrome
  profiles say `tls.session_cache_key` and `quic.session_cache_key`. utls
  61d479e, tls-client 34dec9b.

- Keep two TLS sessions a server, as Chrome keeps them, over TCP and over
  QUIC. A server's second ticket replaced its first, so a second connection
  opened at once went as a full handshake where Chrome's resumes. The Chrome
  profiles say `tls.session_cache_sessions_per_entry` and
  `quic.session_cache_sessions_per_entry`.

- Close an HTTP/3 connection whose server opens a bidirectional stream, as
  Chrome closes it: H3_STREAM_CREATION_ERROR with quiche's reason, "154:Server
  created bidirectional stream." HTTP/3 lets no server open one; the stream
  was passed over and held against the connection's window, and the
  connection stayed up, which tells a server it is not speaking to Chrome.
  The Chrome profiles say `h3.server_bidi_stream_close_reason`.

- Write a request's cookies over HTTP/3 a field a crumb, as Chrome's QPACK
  encoder writes them (quiche's ValueSplittingHeaderList, CookieCrumbling
  kEnabled): cut at each `;`, the space after it dropped. HTTP/3 sent the
  value in one field, where HTTP/2 crumbled it already, so a request of two
  cookies or more went in other field lines and other dynamic table inserts
  than Chrome's. The Chrome profiles say `h3.cookie_crumbs`.

- Fix an HTTP/1.1 answer failing whose chunked body ends its lines in LF
  alone. Chrome 156 reads it (HttpChunkedDecoder): a line ends at LF, a size
  is cut at its extension and trailing spaces, and a chunk's data and the
  trailer's lines end in an empty line of LF or CRLF. fhttp refused it as RFC
  9112 does, so a page Chrome shows failed. The Chrome profiles say
  `h1.chunked_bare_lf`; their bytes before it are kept in
  `profile/provenance/policy-additions.json`.

- Fix HTTP/2 streams reset other than Chrome resets them. A response body let
  go of (a redirect's, a 401's or a preflight's, and the timer of its drain)
  was closed twice, and each close sent RST_STREAM(CANCEL): two where Chrome
  sends one. A request given up while its body was going sent none, as fhttp's
  test had been turned round since 2021. A server's reset and a body closed at
  the same moment raced. A stream ended on both sides gets none, as Chrome
  sends none for a stream it has closed. fhttp 2b67fc1, 64d6de4.

- Fix an HTTP/2 request sent again with an empty body. A request whose attempt
  had closed its body (its HEADERS refused by a connection that went away)
  went out again on another connection with nothing in it, and waited for an
  answer. Only an attempt on a connection that took no stream sends the body
  again now; any other says to define `Request.GetBody`.

- Fix HTTP/3 connections and requests that outlived what they were for. A
  connection a request failed on was closed by neither `Close` nor
  `CloseIdleConnections` and stayed up, with no CONNECTION_CLOSE, until its
  idle timeout. A request given up while its connection was dialed kept that
  connection from counting as idle. A request on a connection still shaking
  hands (0-RTT) waited for good when the handshake failed. A trailer section
  that waited for an insert went on waiting after its body was closed. And
  every request read to its end left a decoding context as long-lived as its
  own context. quic-go-utls 301d6b0c.

- QPACK feedback as quiche's: with `h3.qpack.decoder_feedback: on-section`
  (the Chrome 155 and 156 profiles), an Insert Count Increment follows each
  section for the inserts no acknowledgement told of, a section of the static
  table alone too, as QpackDecoder::OnDecodingCompleted sends it. Before, such
  a section told the encoder nothing, so it could not refer to those inserts.

- TLS 1.3 alerts a protocol the server says it chose and the client did not
  offer with the profile's `tls.alpn_mismatch_alert` (illegal_parameter in
  every Chrome profile, as BoringSSL), as TLS 1.2 did. crypto/tls sent
  no_application_protocol whatever the profile said. utls 4b8e3e1.

- A request forwarded through an HTTP proxy says the profile's
  `proxy.connection_value` in `Proxy-Connection`, as the CONNECT already did.
  It said `keep-alive` whatever the profile said. tls-client 55381c2.

- Fix `compare` holding HTTP/1.1 to what the echo server made of a request
  rather than to how it was written. Spaces around a value were taken off, a
  line ending in LF alone read as one ending in CRLF, and the target's form
  was not kept, so a client writing `Name:value`, `Name:  value`, LF line
  endings or a whole URL for its target matched Chrome. A capture now keeps
  its request's `layout`, and `compare` holds the client to the browser's
  (`http1_layout`); against a capture made before, it is not checked.

- Fix the Akamai HTTP/2 fingerprint writing a PRIORITY frame's weight as its
  byte on the wire: Firefox's frames came out `3:0:0:200`, where Akamai's
  format and tls.peet.ws say `3:0:0:201`, the weight RFC 9113 counts.
  Captures' `akamai_fingerprint`, the log's `akamai` and `compare` say it so
  now. Chrome sends no PRIORITY frame, and its fingerprint is as it was.

- Fix `compare` saying more than it shows. A match said "the client is
  indistinguishable from the browser", of one cold ClientHello and the first
  request of each protocol. It now says every field compared matches, and
  that later connections, resumed handshakes and later requests are not
  compared there.

- Fix `compare` taking a key it cannot check for a match. A key share of a
  group it reads no key of (X448, say), or an ECH key of a length no KEM has,
  was shown as `not checked` on both sides and counted as alike. Both sides
  sending one is now reported as not checked, and `compare` exits 3.

- Fix `compare` passing over bytes Chrome sends alike every time. GREASE was
  held to its lengths alone, though BoringSSL writes the second GREASE
  extension's single zero byte and the GREASE key share's every time; a
  field read an extension's list and passed over what followed it; and
  `server_name`'s contents were left out whole. A client with another byte
  there, a byte past `supported_groups`' list, a protocol name cut short or a
  second server name matched. `grease` now says what a body or key of up to
  16 bytes holds (`extensions last, 1 byte 00`), and `framing` names each
  extension a field reads whose bytes do not read whole by its grammar, and a
  `server_name` of other than one host_name; a browser's has none.

- Fix `compare` taking an ECH payload of any length for Chrome's. Chrome
  draws the length for every connection from four, so it was shown and never
  compared, and a client sending 300 bytes, or 145, matched. `ech_grease` now
  says, of a hello with GREASE cipher suites, BoringSSL's, whether the payload
  is one of its four (144, 176, 208, 240), and a client is held to that where
  the browser's is. A Firefox hello, which has no GREASE and draws lengths of
  its own, is held to none.

- Fix the HTTPS records asked on Windows of servers the addresses do not
  come from. tls-forge took the DNS servers of every adapter that is up,
  where Go's resolver, which looks up the addresses, takes only an adapter's
  with a gateway and passes over `fec0` ones, the site-local servers Windows
  names where none is set. Where every adapter was such, Go asked
  `127.0.0.1:53` for the addresses and nothing resolved. The records are now
  asked of Go's servers, and where Go has none the machine's resolver finds
  the addresses, as where the machine names no server.

- Fix a script's request asking a preflight for a header Chrome sends
  without one. tls-forge let the Fetch standard's four through alone;
  Chromium 156's CORS also lets through a simple `Range` (`bytes=0-100`,
  `bytes=5-`), `Save-Data: on`, `Intervention` and the client hints, those a
  script can say held to what they say (`DPR: 2`, `RTT: 50`, `ECT: 4g`). A
  cross-origin `fetch()` or XHR with them was sent after an OPTIONS Chrome
  does not send. A no-cors `fetch()` is still given the four alone, as
  Chrome's no-CORS safelist has them, and a Range or a client hint there is
  refused.

- Fix the site of a name that ends in a dot: the public suffix list cannot
  read one, so `www.example.com.` was a site of its own and
  `api.example.com.` cross-site to it. Its site is now its registrable
  domain with the dot, `example.com.`, as Chromium's `GetDomainAndRegistry`
  keeps it, and so another of that domain is same-site.

- Fix a cookie's `Expires` read by Go's two layouts alone: a cookie deleted
  with `Expires=Thu, 01-Jan-70 00:00:01 GMT`, as many servers write it, lived
  on as a session's. A Chrome profile's jar now reads it as Chromium's
  `ParseCookieExpirationTime` does: its words in any order, a two-digit year
  1970 to 2069.

- Fix the cache answering a request with `If-Match` or `If-Unmodified-Since`
  itself, from what it kept, where its server would have said 412. Such a
  request now goes to the origin and its answer is not kept, as Chromium's
  `kPassThroughHeaders` make it bypass the cache.

- Fix a fresh answer coded with deflate never kept by the cache over HTTP/2.
  zlib's decoder stops at its checksum, before the stream's end, so the body
  was never read to its end and the cache never saw it whole. What a body
  has past its coding's end is now read and passed over, as Chromium's
  `GzipSourceStream` does.

- Fix an answer the cache would keep, left unread at a Critical-CH restart,
  drained as no body of the transport's: its HTTP/2 stream stayed in the
  priority lists, and its request's end cut the drain over HTTP/1.1, closing
  the connection. The cache's body now tells the transport's it is let go
  of, as a redirect's already did.

- Fix a client's preflight cache keeping every allowance it was ever given:
  what has expired is dropped as another is kept, so that a session holds no
  more than a Max-Age (2 hours at most) of them, as Chrome erases a stale
  entry when it is looked up. Chrome's own limits on the cache (1024 entries,
  a URL of 1024 bytes) are not modelled.

- Fix the noise of the network client hints (`rtt`, `downlink`) of an IPv6
  address drawn from it without its brackets: Chrome draws it from the host
  as GURL says it, `[::1]`, and the hints of such an address now are those.

- Fix a `Host` a request without a browser context was given reaching only
  HTTP/1.1: over HTTP/2 and HTTP/3 the request still said the URL's host as
  its `:authority`. It now says the given one there too, for its URL's
  origin; the connection and its TLS name are the URL's, as before.

- Fix a Referer a request was given going whole to the other origin a
  redirect led to. Chrome works it out again for each hop, as for a page's
  referrer: on a hop to another origin it says its origin alone (measured on
  Chrome 156, HTTP/2 and HTTP/1.1, `testdata/chrome156-given-referer.json`).
  A request without a browser context, and one in a context, now do too.

- Fix a DNS answer taken for the query's by its ID and response bit alone.
  tls-forge's own client now also holds it to the query's question, one
  question of the same bytes, as Chromium's `DnsResponse::InitParse` does:
  over UDP an answer to another question is passed over for the next
  datagram, over TCP the query fails.

- Fix the wait for a name's HTTPS records read differently from Chromium's
  for values other than Chrome's own (20 %, 5 to 50 ms, which wait as
  before). A percent now waits a millisecond at least; a percent of 0 waits
  the larger of `dns.https_wait_min_ms` and `dns.https_wait_max_ms`, not the
  floor; and all three 0 wait for the records as long as they take, as
  Chromium starts no timer then, where tls-forge waited for none.

- Fix the Node package sending a request direct that asked for a proxy.
  `request()`, `get()` and `post()` put every field they were given on the
  protocol's line, and the transport passes over a field the protocol does
  not have: `get(url, { proxy })` went out without it. A field a request does
  not have is now a `TypeError`, before anything is sent; a proxy is the
  client's (`new Client({ proxy })`).

- Security: what a proxy, a server or a visiting browser said reaches a
  terminal as text. A proxy's refusal (`proxy responded with non 200 code:
  …`) carried its status line's reason as it came, and `capture` and
  `compare` printed a manual visitor's user agent and navigator fields as
  sent: an escape sequence in them could clear the screen or set the
  window's title. Every control character but a tab is now written as Go
  writes it in a quoted string, in errors, a request's line and those fields
  (`redact.Printable`).

- Fix `--clear-output-dir` emptying a git repository's own directory. It
  refused a directory holding a `.git`, but not a `.git` itself, a directory
  in one, nor a bare repository (`HEAD`, `objects/`, `refs/`) or a directory
  holding one. Each is now a usage error, before anything is removed.

- Fix `fetch --exit-lookup` asking a site's probe (`/cdn-cgi/trace`) it could
  never believe. With a profile whose `http.instance_scope` is `request`,
  every shipped one, each request has connections of its own, so the probe
  never went over the request's connection and its answer was thrown away,
  but the site was still sent a request no browser makes. No probe is asked
  then, and the exit's reason says why.

- Fix the log's `redirect not followed` saying a `limit` of 20 for every
  request: a navigation, a form and a request without a browser context
  follow 19 redirects, `fetch()` and an XHR 20, and the record now says the
  limit of the request it stopped.

- Security: keep a URL's password out of the log where a header field quotes
  it. A redirect's `Location` (and `Referer`, `Content-Location`, `:path`) had
  its query masked but its `user:password@` written as it came, in the
  library's log and `fetch`'s run log; so did the `location` of a redirect
  given with no scheme (`//user:password@host/`). Both now say the username
  alone.

- Security: a header value no server may be sent (a control byte in it) is
  refused without being quoted. fhttp quoted it whole in the error
  (`invalid HTTP header value "Bearer …" for header "Authorization"`), which
  reached standard error, the log and the daemon's answer. The error names
  the field alone, as net/http and x/net say it.

- Fix a CONNECT over an HTTPS proxy's HTTP/2 connection counting as part of
  the request it opened a tunnel for. The request's `Trace` and log saw the
  CONNECT's connection and first byte as their own (two `GotConn`, two
  `FirstByte`), its fields could reach the request's hooks, and its retries
  spent the request's `h2.retries`. The CONNECT now has a context of its own.

- Fix `fetch` deleting or overwriting the profile it wears.
  `--clear-output-dir` emptied an `--output` directory that held the
  `--profile` file, or the profiles directory's, and `--trace`, `--report`,
  `--log` or `--save-cookies` could name that file and write over it. The
  profile's file is now one the run reads: such a run is a usage error (exit
  2) before anything is removed or written.

- Fix a request failing where a name's HTTPS record gives ECH configs that
  read but that the profile can use none of: a P-256 or P-384 key, a KDF or
  AEAD it does not name, a newer ECHConfig version, a mandatory extension. utls
  ended the connection before its ClientHello. It now goes as one of no list,
  to the name itself with the profile's GREASE ECH, as Chrome 156 does
  (measured). A list that does not read as BoringSSL reads it still fails, as
  Chrome's ERR_INVALID_ECH_CONFIG_LIST does. Over TCP and HTTP/3 alike.

- Fix an HTTP/2 connection whose peer stops reading holding up every HTTP/2
  request of the client, other hosts' included. fhttp (97f9b95) held the
  connection's lock while a request's HEADERS waited for a write the peer did
  not take. A failed preface PING then could not free that write, and the
  pool, which asks each connection under its own lock, waited too. Header
  blocks now take turns without that lock. A request waiting for its turn
  ends with its own context. A failed PING gives the connection up, and its
  requests go again as `h2.retries` says. The request right behind the held
  write still ends only once the PING fails.

- Correct the landing at phone and tablet widths: contain the GitHub badge in
  the header, complete feature and footer rows, wrap terminal commands, and
  tighten the limits heading. Verify screenshots and open-menu/FAQ states.

- Add GitHub icons to the landing's repository links and a cached, background
  star counter in the header with a visible fallback when the API is unavailable.


- Rework the landing around its primary workflows: `fetch` for HTML/API
  collection and `proxy` for browser-profiled outbound requests from existing
  clients, with SDKs, capture/compare, request diagnostics and clear limits.

- Loosen landing headline tracking, use a self-hosted Inter Variable subset,
  and increase feature, workflow and FAQ reading text while retaining mobile
  and desktop Lighthouse 100. Use optional font display to avoid late swaps
  on slower connections.

- Redesign the landing with a frosted-glass visual system, an illustrative
  animated request path, decorative scroll parallax, reduced-motion support
  and a matching Open Graph image.

- Add a static open-source project landing page in `web/landing` with responsive
  layout, semantic content, quick start, project scope, social metadata and
  sitemap; add a tag-triggered GitHub Pages workflow gated by mobile/desktop
  Lighthouse 100.

- Fix the documentation's search and narrow layouts. From 1220px up, the
  header title lay over the centered search field, so a click on the field
  did nothing and only `/` opened search. Results now open directly under
  the field, and the backdrop covers the section tabs: the header's
  `backdrop-filter`, which had no visible effect on its opaque background,
  kept the tabs above it. On phones, long names in table cards wrap instead
  of being cut at the card's edge, and short inline code such as
  `--request-kind` no longer breaks after a hyphen.
- Fix the documentation's section navigation. The current page's name, set
  in bold, wrapped onto a second line where the regular weight fit (the
  sidebar entry "Profiles and compatibility" grew from one line to two when
  opened). Sidebar entries now span the column, lined up with the header
  panel, and a highlighted entry no longer touches the next one. A section
  title has one size and place in every section: where it links to the
  section's overview it was larger, set further in, and pushed the entries
  19px down. The section tabs sit on the page background under the header
  panel instead of on a second, square-cornered bar.
- Show the generated reference one symbol at a time, as Stripe's reference
  does. The CLI, Go, Node.js and Python pages were whole dumps of `--help`,
  `go doc -all` and `index.d.ts` with numbered lines, and Python signatures
  were set as headings, `:param` fields and all. Now each command,
  declaration, method and export has a heading of its own and a signature in
  a code panel without line numbers, one parameter a line when it is long.
  After the panel come its documentation as text, then its flags,
  parameters, fields, keys or properties as a list. Each entry gives a name,
  type, default and description, and raised errors link to their sections.
  `scripts/generate-docs.py` fails on a construct it cannot read rather than
  leaving it out. Two code blocks in a row no longer touch on wide screens.
- Lay the documentation out on a grid of 12px. Sizes and spaces had grown
  from Material's defaults and ours one value at a time: menu entries of
  35.6px, a 56px header over 44px tabs, paddings of 6.4, 9.6 and 13.6px,
  text on lines of 26px, and every border adding a pixel to its box. Now
  every height, margin, padding, gap and line height is a multiple of 12px:
  the header is a 60px panel and 48px tabs, menu entries are 36px and 12px
  apart, text runs on lines of 24px, code panels have a 48px title row, and
  the search results, tables, cards and the phone menu follow the same
  steps. Borders and dividers are drawn as outlines and inset shadows, which
  take no room. Hovering anything moves nothing.
- Lay the reference out as Stripe's is, and give every page a map. From
  1440px wide, a section's code stands to the right of its text: the
  signature, an example and, where the example prints something, what it
  printed, a mark of "…" for each run of lines left out. Whichever of the
  two is shorter stays in view under the header while the other scrolls
  past: the code beside a long text, scrolling in its column when it is
  taller than the window, and the name and text beside long code. On the
  right, a map of the page marks the section being read and jumps to any
  other. Every page has the same frame, up to 1728px: the header, menu and
  map stand in one place from page to page, and a guide's text keeps its
  864px column, in the middle between them. The examples are real runs of
  the CLI and the Go, Node.js and Python packages, kept in
  `scripts/reference-examples.json`. A link to a section put its heading
  93px further down than the step under the header: Material's scroll
  margin on headings came on top of the page's own. `make docs-check`
  reads a heading's attribute list as MkDocs does: since the reference's
  headings carried one, the link to `cli.md#proxy` failed it. In a code
  panel without a title, the copy button covered a line too long for the
  panel, at every width (813 places over the 46 pages at eight widths): the
  code now scrolls left of the button, never under it.

### Development provenance

The [unpublished development log](research/releases/1.0.0-development-history.md)
preserves the complete earlier engineering journal. Internal engine2 through7
labels there identify unpublished experiments; they are not released versions.

## [0.2.2] - 2026-10-12

### Added

- Profiles of Chrome 154 and Chrome 155, for Linux, macOS and Windows.
  `chrome` names Chrome 155 from this release.

### Security

- Builds use Go 1.26.9 and `golang.org/x/net` 0.60.0, which fix nine advisories
  that `govulncheck` reports as reachable from this code: HTTP/2 HPACK, flow
  control and trailer handling, HTTP/1.1 `CONNECT` and MIME header parsing,
  malformed ECH extensions in `crypto/tls`, and escaping contexts in
  `html/template`, which renders the `batch` report. Go 1.26.9 is now the
  minimum toolchain.

## [0.2.1] - 2026-09-21

### Fixed

- The release workflow has the `id-token: write` permission, which
  publishing to npm and PyPI with provenance asks for. The code is 0.2.0's.

## [0.2.0] - 2026-09-21

### Added

- A registry-facing end-to-end workflow installs an exact released version of
  the Go, npm and PyPI distributions on Linux, macOS and Windows, makes requests
  through every SDK, runs the published amd64 and arm64 container images, and
  installs and tests the current stable Homebrew formula. It is a separate,
  manually dispatched check for any chosen version.
- A profile of Chrome 153, for Linux, macOS and Windows. `chrome` names
  Chrome 153 from this release.

### Fixed

- Stable releases fail visibly when the Homebrew tap credential is absent,
  instead of silently succeeding without publishing a formula. The published
  E2E check now diagnoses a missing tap formula directly.
- Generated Homebrew formulae let Homebrew infer the stable version from their
  release URLs instead of repeating it in a redundant `version` stanza rejected
  by `brew audit`.

## [0.1.0] - 2026-09-08

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

- Captured Chrome 152 profiles reproduce the new `trust_anchors` ClientHello
  extension. The measured IDs are validated and reordered once per process,
  matching Chrome's process-stable hash-set order instead of replaying one
  capture forever; malformed and unknown extensions are still rejected.
- npm publishing is safe to resume after a partial registry upload: an existing
  tarball is skipped only when its SHA-512 integrity matches exactly. npm's
  required `latest` tag is left in place during prereleases and the first stable
  publish will replace it.
- The Windows npm binary package is named `tls-forge-windows-x64`; its manifest
  still uses npm's required `win32` OS selector. This avoids a false positive in
  npm's package-name spam detector without changing platform selection.
- GitHub Release creation names its repository explicitly, so the artifact-only
  job no longer tries to discover it through an absent local `.git` directory.
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

- Updated the Go transport stack to `tls-client` 1.16.0, `fhttp` 0.6.9 and
  uTLS 1.7.8, including upstream fixes for HTTP/2 flow control, ALPN transport
  reuse and per-connection signature GREASE. Runtime cryptography and
  compression dependencies are current as well.
- `npm test` runs every `test/*.test.js` rather than one named file, so a new
  test file cannot be added and silently never run.

### Documentation

- `research/protocol.md` said the whole header sequence could be dictated by naming
  every header in `order`. It cannot: the merge keeps the profile's position for
  every name the profile already has. Documented as the deliberate behaviour it
  is, since the profile's order is the fingerprint being impersonated.
- `research/profiles.md` told maintainers to refresh the shipped profile with
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
  platform-specific optional dependency — `tls-forge-<platform>-<arch>`
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
