# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

A note specific to this project: **a new profile is not a breaking change, but a
changed default profile can be.** `WithProfile("chrome")` resolves to the newest
measured Chrome, so adding a profile for a newer browser changes what that name
means. Pin the exact name — `WithProfile("chrome_151")` — when that matters.

## [Unreleased]

- `Close` waits for the close of a site evicted before it that is still
  going, and for the sites another `Close` is closing: it returned while
  their connections were being closed, a site no request held being kept in
  no list it looked at.
- What a race of a name's HTTPS record goes on making after its request, the
  TCP connection QUIC beat or the QUIC one TCP beat, is ended and waited for
  by `CloseIdleConnections`, and so by `Close` and an evicted site's close,
  before they close what is idle: it came up after them and was kept open.
  Requires the tls-client fork's `apartWork`, at 62deb6d.
- A plain-http request through an HTTPS proxy whose HTTP/2 connection, taken
  behind the proxy's dial gate, turns it away dials the proxy again behind
  the gate, taking first a connection another request dialed meanwhile: it
  dialed without the gate, so that requests at once each opened an HTTP/2
  connection to the proxy. A proxy connection that could not be adopted for
  HTTP/2 fails its request and is kept by no transport: every later request
  through the proxy had its error, and none dialed again.
- `capture --manual` gives session tickets to the host whose page asked for
  them, and only it: one window for every visitor let another host's visit
  open it, so that its next connection resumed and the visit measured was a
  resumed one, or close it under a page that was waiting for its resumed
  hello. Past the pages, visitors and waiting navigations it keeps, the
  busiest host's oldest goes first: one host opening page after page made
  another's navigation unknown before it reported back. Two browsers on one
  host still share its tickets, as a handshake says no more than its host.
- Hold a response's Content-Encoding chain to the profile's limit whether it
  has a body or not: a HEAD, a 204 and a 304 of more layers than
  `http.max_content_codings` came back, where Chrome 156 refuses them as it
  refuses a 200 (measured: eleven gzip layers on each, H1 and H2).
- `Save` of a profile of schema 0-2 that this engine does not run writes the
  frozen data it was read with: it added this engine's content-coding and
  cookie-prefix rules, which only an explicit `Migrate` gives. `Migrate` gives
  an archive of another browser than Chrome the generic data's rules (64
  layers, identity passed over), as such an archive of an older schema runs
  with: it gave every archive the values measured of Chrome 156.
- A second ClientHello carries a HelloRetryRequest's cookie where BoringSSL's
  permutation puts it (read in its source, not measured): among the
  extensions it permutes, each place as likely. It went before the opening
  GREASE extension of about one in 17 of a Chrome profile's second hellos,
  which Chrome's never are, and never just before the closing ones. A
  HelloRetryRequest after a spec's own pre_shared_key bytes
  (`FakePreSharedKeyExtension`) is an error, not a nil dereference, and
  utls's QUIC server refuses handshake bytes left before its 0-RTT read key,
  as Go 1.26.10's does (CVE-2025-61730). Requires the utls fork at 8131c6b.
- Keep a request's credentials at its origin under a redirect policy of the
  caller's too (`WithTransportOption` with `tls_client.WithCustomRedirectFunc`):
  fhttp copied `Authorization`, `Cookie`, `Proxy-Authorization` and the other
  credential fields to a subdomain of its host, as net/http does, and on back
  to the origin after it. A hop such a policy followed and its server answered
  421 or 401 was sent again with the fields and URL credentials tls-forge had
  laid out for the first request, to wherever the hop went; its answer is now
  the policy's, sent again for neither. Requires the fhttp fork's
  `WithCredentialsKeptToOrigin`, at e514e87.
- A hop a redirect took away from a request's own `Authorization` is
  authenticated on its own again, with its Location's credentials or those the
  session keeps for its realm, as the redirect documents said: tls-forge left
  every 401 of the chain to the caller, the hop's included, once its
  `Authorization` was left behind.
- Bound an HTTP/2 header block on the wire as well as by its field list: at
  twice MAX_HEADER_LIST_SIZE, each frame's nine-byte header counted. Empty
  CONTINUATION frames, and fragments of nothing but table size updates, spent
  none of the CVE-2023-45288 bound and were read for as long as a server sent
  them. fhttp's bundled HTTP/2 framer, its Server's and that of a Transport
  left to set HTTP/2 up itself, had no such bound at all and has both. An
  invalid field value in an HTTP/2 or HTTP/3 answer is refused with an error
  that names the field and not its value, which may be a secret. Requires the
  fhttp fork at 0aca37e and quic-go-utls at 69430008.
- Refuse a profile whose `http.zstd_window_bytes` is past 134217728 (128 MiB)
  before anything is sent: the registry allowed 2147483647, so a profile could
  let one zstd layer of a body keep a 2 GiB window. Every shipped, catalogue
  and frozen legacy profile says 8388608. Requires the utls fork's
  `MaxZstdWindowBytes`, at ce7eff0.
- Tell a secret query parameter by the words of its name, in logs, traces,
  reports and errors: a signed URL's `sig` and `X-Amz-Signature`, `pass`,
  `pwd`, an OAuth `code`, `otp`, `jwt` and session ids (`PHPSESSID`,
  `session_id`) were written out, while `keyword`, `monkey` and `pageToken`
  were masked for a word they only contain. A URL's fragment is masked as its
  query is: an OAuth implicit flow's `#access_token=...` was written out.
- Refuse an HTTP/2 profile whose `SETTINGS_HEADER_TABLE_SIZE` is past 1048576
  or whose `SETTINGS_MAX_HEADER_LIST_SIZE` is past 16777216, before anything is
  sent: the transport sizes its HPACK decoder and its header-list limit by them,
  so up to 4294967295 a server could make a client keep that much of its
  headers. HTTP/3's QPACK table already had the same bound. Every shipped and
  catalogue profile asks for 65536 and 262144 at most.
- Cut a brotli-compressed certificate's window to the least its declared
  length needs (2^18 bytes, or 2^19 past 262,128): four bytes claiming a 2^24
  window and a 2^24-byte meta-block allocated 16 MiB before any data came, and
  now about 0.6 MiB at most; what a stream of that length decodes to is
  unchanged. utls also requires brotli v1.2.3, which refuses a stream cut short
  before its last meta-block, as tls-forge's own build already did. Requires
  the utls fork at 2477e72.
- A profile the profiles directory holds as a symbolic link tls-forge does not
  follow (absolute, even to a file inside it, leading out of it, or leading
  nowhere) is refused with an error naming it; the shipped profile of the same
  name was worn in its place without a word.
- Take the password out of a URL the URL Standard reads with one, however it is
  spelt: one slash or three after a special scheme (`https:/u:p@host`), none,
  backslashes, capitals, tabs or newlines inside. CanonicalURL, Validate, Do,
  OwnPage, CookiesFor, a browser context's initiator and fetch's list of URLs
  quoted it whole in their errors.
- Refuse a chunked answer whose chunk-size line is empty, as Go 1.26.10 does:
  the body ended there with no error. A chunk cut short in its data, or before
  its CRLF, is io.ErrUnexpectedEOF in fhttp's chunked reader too, as in Go.
  Requires the fhttp fork at a31fd70.
- A request's PRIORITY_UPDATE goes in its first packet with its HEADERS
  (`h3.request_writes: one-flush`) even when the control stream still has its
  SETTINGS to send: a write is held for its bundle as it is given, before a
  packet can take it. The F09 gate's flaky
  `TestARequestsWritesGoInOnePacketAsItsProfileSays`. Requires the
  quic-go-utls fork at 4e96d6e8.
- `Request.Reloaded` (and `fetch --retry-as-browser`) leaves the caller's
  Authorization, Cookie and proxy/challenge credential fields behind when a
  redirect took the page to another origin, as the redirect did; a reload at
  the origin they were given for keeps them. A URL that cannot be read counts
  as another origin.
- Mask secret query parameters in the URL-valued fields logs and traces write
  down (`:path`, `Referer`, `Location`, `Content-Location`) and in the URLs of
  the authentication records, over HTTP/1.1 and HTTP/2 alike.
- `CloseIdleConnections` no longer passes over a site with a request in flight:
  that site's idle connections close once its last request or response body is
  done, once, and the site stays resident with its TLS sessions.
- Require `http.max_content_codings`, `http.content_coding_overflow`,
  `http.ignored_content_codings` and `cookie.prefixes` of every executable
  current-engine profile, whatever its schema: an explicit `behavior` of an
  older schema without them is refused before any I/O, as schemas 3 and 4 are.
  A legacy profile with no `behavior` runs on the frozen data, which has them.
- Refill an HTTP/2 connection window whose `connection_flow` is below RFC 9113's
  initial 65,535 bytes when the profile has no `h2.window_update_delay_ms`: the
  client refilled to the increment itself, so 0 and 1 left a body past 64 KiB
  waiting for the deadline and other small values ended in FLOW_CONTROL_ERROR.
  Requires the fhttp fork at aa8d85b.
- Hold a release to Google Chrome Stable as Google ships it. The pinned gate
  installs Chrome from Google on a macOS, a Linux and a Windows runner, with
  the steps `drift.yml` uses (`.github/actions/google-chrome`), and refuses
  Chrome for Testing, Chromium, another channel or a major the profile is not.
  `internal/pinned` takes `--browser`, `--profile` and `--browser-arg` instead
  of a manifest, and the publishing jobs check the gates with
  `release-set.mjs gated`. `reference/chrome.json`, the private installer
  archive, its secrets, `internal/reference` and `scripts/pinned-restore.mjs`
  are gone.
- Validate executable profile semantics before DNS/transport/proxy activity at
  every entry. Reject ambiguous JSON, invalid H2 settings/streams/dependencies,
  unsupported repeated-setting representation and connection-window overflow.
  Preserve explicit zero stream/connection windows and the final legal stream.
  Wake body readers on terminal flow errors; queue large valid H3 setup outside
  the QUIC run loop, preserving small setup composition and the SETTINGS barrier.
  All changes share unpublished engine1; the15 profile JSON files are unchanged.
- Add source-pinned full-suite fork regression gates for standalone and actual
  production dependency graphs, named inherited failures, executed QUIC self
  integration, loopback-only test traffic and retained raw evidence. CI targets
  development and cancels obsolete runs. F09 stage2 remains open; remote CI
  activation still requires verification.

- Release HTTPS-proxy discovery locking at connection acquisition rather than
  response arrival. Remember observed H1 per partition, retain actual ALPN on
  new connections, and allow simultaneous H1 forwarding/CONNECT while preserving
  H2 reuse, request tracing and canceled-waiter isolation.

- Keep active H3 response bodies leased until completion. Reserve idle-close
  I/O before releasing the registry mutex, excluding concurrent new readers of
  the same site without blocking other sites or resetting session state.

- Track evicted top-level-site pools until requests and detached response
  drainers finish; release their connections on completion and client Close.
  Snapshot pool ownership under the registry mutex and perform close/reap I/O
  outside it. Keep resident pool limits in profile JSON.

- Require explicit TLS key-log destinations; ignore `SSLKEYLOGFILE` in utls
  and strip only that variable from Node/Python daemon starts and restarts.
  Preserve explicit keylog/pcap support. JSON QUIC layout overrides ambient
  scrambling switches; profile HTTP/2 stays independent of `http2client=0`.
- Mask forward-proxy authorization across write cuts and reused HTTP requests
  in pcap snapshots, preserving body/tunnel bytes and lengths. Redact additional
  auth headers and sensitive query parameters in diagnostics, including final
  URLs, and passwords in Validate/CanonicalURL/OwnPage/CookiesFor errors.

- Confine captured profile paths and registry reads to their root, validate
  identifiers and browser majors, and put implicit manual captures under
  `manual_` so visitor data cannot change default profile selection. Bind random
  128-bit navigation tokens to remote host and User-Agent across all endpoints.

- Authenticate TLS1.2 Finished before rejecting an actual ECH offer; GREASE ECH
  retains normal False Start behavior. Bound compressed-certificate resources
  and require exact decompressed length. Port Go1.26.10 read-key boundary and
  cached-chain revalidation fixes (CVE-2025-61730, CVE-2025-68121), including
  client/server TLS1.2/TLS1.3 regressions. All share unpublished engine1.

- Resume TLS1.3 sessions after HelloRetryRequest with profile-shaped ClientHello2
  and a binder over its actual serialized bytes and HRR transcript. P-256/P-384
  peers and independent Chrome156/macOS observations cover full and resumed
  handshakes. The separate real-ECH retry path is unchanged; profile values and
  the unpublished engine1 major remain unchanged.

- Declare cookie-prefix storage rules in `cookie.prefixes`: spelling, case
  matching, rejection of protected nameless values and required attributes.
  Production cookie reception matches the 48-case Chrome156/macOS witness
  over plain HTTP and TLS H1/H2. Ordinary nameless cookies remain supported.
  Missing or malformed rules fail before I/O; old archives need explicit migration.

- Bound content-decoder depth before allocation and create decoder layers only
  when read. Profiles own the depth, overflow action and ignored coding tokens;
  Chrome uses ten layers and treats identity as unsupported, confirmed on
  headed Chrome 156 H1/H2. Empty over-depth bodies fail too. Historical migration
  templates remain unchanged; explicit current-engine additions are separate.
  Inspect/Save preserve old archives without granting execution compatibility.

- Bound hostile response framing: defer HPACK string decoding until a complete
  literal is available, stop excessive HTTP/2 CONTINUATION processing, reject
  bare LF in chunk-size lines and bound chunk-extension overhead. Redirects
  cannot restore stripped caller credentials or forward proxy credentials to
  another origin. Jar cookies retain their independent scope. These engine
  fixes share the existing unreleased 1.0.0 candidate; profile values are unchanged.

- A Chrome profile's QUIC handshake is Chrome 155's, measured on macOS
  against an own bench (tshark opening the packets): one packet number
  counter for the three spaces from 1, a number as long as quiche's window
  rule makes it (the first Initial's one byte, the second's two); the first
  flight laid out as quiche's chaos protector lays it out, the hello's first
  55 to 86 bytes and its end in the first Initial, its middle in the second,
  each with 2 to 10 PINGs, its CRYPTO split and its padding spread; into
  silence one probe 300 ms after the first flight, doubling, a number skipped
  before each, every alarm as late as Chrome's on macOS (below); at 4 s of
  quiet a `CONNECTION_CLOSE`
  with quiche's reason (`25:No recent network activity after 4008694us.
  Timeout:4s num_undecryptable_packets: 0 {}`); no ACK of the server's
  Initial when the handshake ends within a millisecond; a UDP socket
  connected to the server, so that a port that answers ICMP unreachable ends
  QUIC at once. Before, quic-go's: numbers from 0 in each space, two probes
  200 ms after, a silent end at the handshake's timeout, QUIC going on to a
  closed port until it. Its ClientHello offers ALPS for `h3` (12 extensions,
  as Chrome's), and what a server gives in it is read as Chrome reads it,
  measured over 51 variants in two cohorts: its SETTINGS taken, so that the
  first request writes into the QPACK table it gives; ACCEPT_CH's hints on a
  page's request; a frame ALPS may not carry, a field that does not read, a
  second SETTINGS frame or a frame cut short closing the connection before
  its Finished goes with PROTOCOL_VIOLATION and quiche's words; the server's
  settings, ALPS's and the control stream's, taken as quiche takes them, a
  refusal an application close with SETTINGS_ERROR and quiche's words, in the
  Initial and Handshake packets too, as Chrome sends it (RFC 9000 would make
  it `APPLICATION_ERROR`). The close of a client's coalesced packets now
  fills its datagram to its size, where quic-go's went 16 bytes past it. An
  ORIGIN frame in ALPS crashes Chrome 155's network service; tls-forge
  abandons the QUIC connection without a word, and its TCP one takes the
  request. A request a QUIC connection of a record's `h3` failed before its
  answer, its stream reset or its connection closed by either side, now goes
  again over TCP, its body again, and QUIC to the origin is broken once TCP
  answered, as Chrome's did (`HTTP_TRANSACTION_RESTART_AFTER_ERROR`,
  `ERR_QUIC_PROTOCOL_ERROR`); before, it failed with QUIC's error or
  `http3: no cached connection was available`, and the next request made
  another QUIC connection. New profile fields `quic.packet_numbers`,
  `quic.first_packet_number`, `quic.packet_number_length`, `quic.pto_skip`,
  `quic.pto_probes`, `quic.pto_initial_rtt_ms`,
  `quic.pto_no_sample_multiplier`, `quic.pto_no_sample_min_ms`,
  `quic.pto_rttvar_multiplier`, `quic.alarm_slack_ms`,
  `quic.handshake_idle_timeout_ms`, `quic.handshake_timeout_ms`,
  `quic.handshake_ack_timer_ms`, `quic.idle_close`, `quic.idle_close_code`,
  `quic.idle_close_reason`, `quic.handshake_idle_close_reason`,
  `quic.undecryptable_level_names`, `quic.initial_layout`, `quic.chaos_*`,
  `quic.padding_position`, `quic.connected_socket`, `quic.alps_protocols`,
  `quic.close_early_application`, `quic.retry_over_tcp`, `h3.alps_reader`,
  `h3.alps_origin_frames`, `h3.alps_close_*`, `h3.alps_errors`,
  `h3.peer_settings`, `h3.settings_*`, set in every shipped Chrome profile,
  with 17613 kept in
  `quic.preserve_extensions`; without them a profile's QUIC is quic-go's, as
  before.

- What a Chrome profile's QUIC client sends after its handshake is Chrome
  155's, measured on macOS against the same bench (tshark opening the
  packets with the runs' secrets): no packet marked for ECN (quic-go marked
  1-RTT packets ECT(0)); no path MTU probe (quic-go sent probes of 1359 to
  1447 bytes 26 to 103 ms after the handshake), its packets no larger than
  1250 bytes; the server's first connection ID kept until the server retires
  it (quic-go retired it for the next at once, a `RETIRE_CONNECTION_ID` in
  its first 1-RTT packet); the HTTP/3 control stream in the datagram that
  carries the Finished, as quiche's `SendInitialData` writes it once
  encryption is established (a second flight of 154 to 161 bytes, Chrome's
  156 and 157; before, 116 bytes and the control stream in the packet
  after); and on a request stream the server resets, nothing more but the
  QPACK decoder's Stream Cancellation, its read side alone closed (quic-go
  reset its own side too, `RESET_STREAM` H3_FRAME_ERROR); a request still
  sending then is cancelled with H3_REQUEST_CANCELLED, as Chromium's
  `QuicHttpStream::Close` cancels it (read in the source). New profile
  fields `quic.ecn`, `quic.mtu_probes`, `quic.connection_id_change`,
  `h3.control_stream`, `h3.peer_reset`, set in every shipped Chrome profile;
  without them a profile's QUIC is quic-go's, as before.

- A Chrome profile's HTTP/3 client puts its writes in packets as Chrome 155's,
  measured on macOS against the same bench: a request's PRIORITY_UPDATE, its
  QPACK encoder's instructions and its HEADERS with its FIN go in one packet,
  as Chromium's `QuicHttpStream::DoLoop` writes them under one flush
  (`STREAM(2) STREAM(10) STREAM(0)`, as Chrome's in each of 121 requests;
  before, the PRIORITY_UPDATE went in a packet of its own and the HEADERS in
  the next), and the QPACK decoder's instructions only in packets the connection
  sends for something else, as quiche bundles them, a Stream Cancellation of
  a request the server resets in the packet that acknowledges the reset
  (before, at once in a packet of its own). New profile fields
  `h3.request_writes`, `h3.qpack.decoder_writes`, set in every shipped Chrome
  profile; without them a profile's HTTP/3 writes go as quic-go's, as before.
  The fork of quic-go has `Conn.BundleWrites`, `Conn.BundleOpportunistically`
  and `Stream.SetResetHandler` for them.

- A Chrome profile's QUIC client acknowledges a lone 1-RTT packet as late as
  Chrome 155 on macOS: its 24 ms ACK timer and `quic.alarm_slack_ms`, which
  delayed only its probes and idle close before, as Chrome's network thread
  has its every alarm late. What makes Chrome's late is the macOS kernel's
  coalescing of that thread's timer, not Chromium's task leeway (2, 8 and
  20 ms of it left Chrome's ACKs as they were; a latency tier set with
  `taskpolicy` moved them), and it varies: measured on 2026-10-26 by turns
  with the library, Chrome's delayed ACKs said 25.3 to 30.0 ms, a median of
  28.9, its probes and idle close 3 to 5 ms late; on 2026-10-25 all its
  alarms were about 8 ms late (ACKs a median of 33.1 ms). The macOS profiles
  now say 4 ms (they said 8), and the Linux and Windows profiles say none,
  their alarms on time: the macOS value is its kernel's, and neither is
  measured. The library's ACK went at 24.1 to 25.1 ms before, at 28.5 to
  29.2 ms now (a median of 29.1), its probes at 305.2, 910.2 and 2115.3 ms
  where Chrome's went at 304.5 to 305.0, 908.6 to 909.7 and 2112.8 to 2113.2
  that day; a Stream Cancellation that waits for such an ACK goes with it.

- A Chrome profile's QUIC client acknowledges a long download as Chrome 155
  does (quiche's `QuicReceivedPacketManager` and `QuicConnection` at Chrome
  155's DEPS revision): every second ack-eliciting packet until the server's
  packet numbered its first plus 100, and every tenth after, a packet so
  numbered waiting a quarter of the least round trip, a millisecond at least
  and the ACK timer at most, from the first one not acknowledged (quiche's ACK
  decimation; `quic.ack_decimation_after`, `quic.ack_decimation_packets`,
  `quic.ack_decimation_rtt_percent`, `quic.ack_decimation_min_ms`); each of
  the four packets after a gap at once, where quic-go acknowledged a gap once
  (`quic.ack_gap_packets`); each ACK sent before the next packet is taken,
  where quic-go read up to 32 first and acknowledged two to 32 at a time
  (`quic.ack_sent_after`); the twentieth ACK-only packet in a row made
  ack-eliciting with MAX_DATA of the connection's window, where quic-go sent
  a PING (`quic.ack_only_max`, `quic.ack_only_frame`); and, in the macOS
  profiles, its ACK alarm a fifth of its delay late at most, as that kernel
  coalesces a timer by a part of how long it waits
  (`quic.ack_alarm_slack_percent`, which needs `quic.alarm_slack_ms`).
  Measured on macOS against an own bench (2026-10-26, a megabyte over HTTP/3,
  on loopback and 50 ms and 1 s away; Chrome's two cohorts, the library's
  three by turns): alike in each count (on loopback 97% of two before the
  mark for both, 86% to 91% and 89% to 93% of ten after it, none of more),
  each gap's four at once (12 of 12, 18 of 18), MAX_DATA after 19 ACK-only
  packets every time; their alarm ACKs a quarter of the least round trip
  after the first packet they waited for, a millisecond on loopback, the
  library's 0.1 to 0.9 ms later, as macOS coalesces Go's timers too. The fork
  of quic-go has `ReceivedPacketHandler.SetAckDecimation`, `SetGapPackets`,
  `SetAlarmSlackPercent` and `AckQueued` for them.

- A direct `https://` request to a name whose HTTPS record names `h3` goes
  over HTTP/3 as Chrome 155's does, measured on macOS against an own bench
  (two cohorts of 18 scenarios, and of 3 more): its QUIC connection to the
  name's first address, offering the record's ECH, and its TCP one after
  QUIC's first packet has gone, at once while QUIC has not worked in the
  session, else 150% of the server's last QUIC round trip (300 ms where none
  is known, 3 s at most), at once when QUIC fails; the first up takes the
  request, the other is made all the same, a QUIC connection taking the
  requests after it until it goes away (idle 30 s, or closed by the server:
  the next request races again, where HTTP/3's transport handed it the
  closed connection, and it failed with `no cached connection was
  available`), a TCP one kept unused for a minute, read as it waits (its
  session ticket cached as it comes, as Chrome's `DoPeek` reads a
  connection), and closed by the next request after that which asks for a
  connection, as Chrome's pool cleans up when a socket is asked of it (past
  its time, or closed by its server, it holds no TCP back: a new one is made
  at once beside QUIC); an origin with a TCP connection already sends a
  request on it at once and makes its QUIC connection apart; QUIC that
  failed where TCP did not is not tried again for 5 minutes, twice as long
  for each break before it lately, 2 days at most. A record of `h2` alone,
  records that all say `no-default-alpn`, none, or one later than the wait:
  TCP alone. What a session knows of QUIC its `Fresh` clients share. New
  profile fields `dns.https_h3`, `quic.tcp_wait_cold_ms`,
  `quic.tcp_wait_broken_ms`, `quic.tcp_wait_rtt_percent`,
  `quic.tcp_wait_default_ms`, `quic.tcp_wait_extra_ms`,
  `quic.tcp_wait_max_ms`, `quic.tcp_waits_with_connection`,
  `quic.broken_ms`, `quic.broken_doublings`, `quic.broken_max_ms`,
  `quic.broken_recent_max`, `quic.server_rtts_max` and
  `http.unused_idle_connection_timeout_ms`, set in every shipped Chrome
  profile; without them a profile goes over HTTP/3 only with
  `WithProtocolRacing`, as before. Through a proxy, or with transport options
  of the caller's, nothing changes. At cloudflare-ech.com over a home router,
  by turns with Chrome 155: tls-forge over HTTP/3 with ECH in 4 visits of 4,
  Chrome in 2 (in the other 2 its record came after the wait). `--keylog`
  and `WithKeyLogWriter` now take the secrets of QUIC connections too, and
  `--pcap` keeps a QUIC connection's datagrams, one UDP packet each (a write
  the system segmented as the datagrams it sent), with its secrets in the
  file: Wireshark opens HTTP/3 decrypted as it is (tshark 4.6.9, measured).

- An answer whose `Alt-Svc` advertises `h3` (RFC 7838) sends its origin's
  later requests over HTTP/3 to that alternative as Chrome 155's alternative
  job does, measured on macOS against an own bench (17 scenarios, two or
  three cohorts each): a QUIC connection to the alternative's port, and host
  where it names one, the origin's name in its hello, the request's TCP
  connection held back as for a record's `h3` by the wait the origin's QUIC
  connections measured, but the request at once on an HTTP/2 connection the
  origin has, the QUIC connection made apart for the next. The value is read
  as Chrome's quiche reads it (one it cannot read whole is not taken,
  `clear`, `ma`, the fields joined); each answer but a 421's replaces what its
  origin advertised; only `h3` is taken, the first the profile allows that is
  not broken; a request the alternative's QUIC connection failed breaks the
  alternative. Alternatives are the session's, kept for the origin and the
  top-level site. New profile fields `quic.alt_svc`,
  `quic.alt_svc_user_ports`, `quic.alt_svc_remote_hosts` and
  `quic.alt_svc_tcp_waits_with_h2`, set in every shipped Chrome profile;
  without them `Alt-Svc` is not read, as before.

- A direct connection to a name asks its addresses and its HTTPS records
  (RFC 9460) of the machine's DNS servers itself, at the same time, as
  Chrome's built-in DNS client does (`*.local`, and `localhost` and names
  under it, stay the machine's resolver's, as Chrome's do; a machine that
  names no DNS server answers with its resolver, and no record is asked),
  and offers real Encrypted Client Hello (RFC 9849) with the configs a record
  gives, as Chrome 155 does, measured on macOS against servers that opened
  every inner hello (testdata/chrome155-ech-dns.json): the record of
  `_PORT._https.NAME` for a port other than 443, its TargetName the name (or
  `.` without a port before it), waited for once the addresses are in no
  longer than 20% of the lookup's time, 5 to 50 ms; the outer hello the
  profile's to the config's public name with no `pre_shared_key`; the inner
  one of the profile's own extensions, the server's name, TLS 1.3 and its
  inner marker written for it, the rest of the outer's by reference but
  ec_point_formats, extended_master_secret, session_ticket and
  renegotiation_info, a session's PSK last, padded as RFC 9849 says; the
  first config with an X25519 key and the first of its suites; one retry with
  the configs a refusal sends, without ECH when it sends none or the server
  speaks TLS 1.2, a second refusal the request's failure. An `http://`
  request whose name has a record goes to `https://` as an internal redirect
  (307, `Non-Authoritative-Reason: DNS`), never sent, its next hop's fields
  in a redirect's order, as Chrome's. At cloudflare-ech.com over a home
  router, by turns with Chrome 155, both took ECH in 8 visits of 8. New
  profile fields `dns.resolver`, `dns.https_records`,
  `dns.https_wait_percent`, `dns.https_wait_min_ms`, `dns.https_wait_max_ms`,
  `dns.https_upgrade`, `tls.ech`, `tls.ech_inner_own`,
  `tls.ech_inner_omitted`, `tls.ech_inner_min_version`,
  `tls.ech_padding_block`, `tls.ech_kems`, `tls.ech_kdfs`, `tls.ech_aeads`,
  `tls.ech_chacha_without_aes`, `tls.ech_outer_psk`, `tls.ech_retries` and
  `tls.ech_retry_without`, set in every shipped Chrome profile; without them a
  profile asks for no record and offers GREASE ECH alone, as before. Through
  a proxy nothing changes. `--dns-server` (fetch, proxy, daemon) and
  `WithDNSServer` look names up with another server, addresses too; the run
  header says `dns` and the log's `run` record `dns_server`. A refused ECH
  offer is checked against the config's public name, which the outer hello
  named (it was checked against the server's own).

- `fetch` without `--request-kind` sends another method than GET, or `-d`, as
  an XHR of the root of the URL's own origin, as the site's own script sends
  it (owner decision, 2026-10-24), where it refused it with exit code 2:
  `Sec-Fetch-Mode: cors`, `Accept: */*`, `Priority: u=1, i`, `Origin`, the
  page as its Referer, and what `-H` gives where a script's fields go. `fetch
  --form` sends it as the form a person's click submits on that page, or on
  the one `--initiator-url` names (`Sec-Fetch-Mode: navigate`,
  `Sec-Fetch-User: ?1`, `Cache-Control: max-age=0`): a POST of a form's fields,
  or a GET with them in the URL; with `--request-kind` it is a usage error.
  The run's header says which (`sent as ...`). A GET with `-d` is still
  refused (no page sends one), a field a script cannot set too, and a profile
  of the transport's catalogue sends such a request as it is given. Library:
  `OwnPage(url)` (the root of a URL's own origin) and
  `Request.FromItsOwnPage()` (the request as that page's XHR); `Client.Do`
  itself still refuses a request without a context that no typed navigation
  is (`ErrNeedsContext`).
- `fetch --retry-as-browser` (with `--retry`) makes each try after the first
  as a person makes it again in Chrome, by reloading the page (Ctrl+R): to the
  URL the answer is at, where a redirect led (the redirect is not asked again),
  on the connection the page came on, which is kept for the request's tries
  (`--retry` alone opens one for each), asking for it afresh with
  `Cache-Control: max-age=0` and saying the person asked
  (`Sec-Fetch-User: ?1`), with the cookies the answer set and the client hints
  it asked for, from the page the request came from (`Referer`, `Origin`,
  `Sec-Fetch-Site`) as before. A form posted to the end is posted again with
  its body, its Content-Type after Origin; one a redirect made a GET is
  reloaded as that GET. A `fetch` or `xhr` is sent again as its page's script
  sends it, on the connection it went on. The run's header says it (`tried
  again`), a try made again says `reloading`, and the log's `retry` record
  `"as": "reload"`. Library: `Request.Reload`, `Request.Reloaded(res)` (the
  request that reloads the page `res` is at), and `Response.Method` (the
  method the answer is to: GET after a redirect made a POST one). Profile keys
  `headers.reload_cache_control` and `headers.form_reload_order`, said with
  `headers.navigation_fetch_user` (the 15 shipped Chrome profiles). Measured
  on Chrome 155.0.8059.85 on macOS over its DevTools port (Page.reload, which
  Ctrl+R's chrome::Reload calls the same way, the repost dialog aside): 12
  scenarios over HTTP/2 and HTTP/1.1, two runs each, alike
  (`testdata/chrome155-reload.json`), against which
  `TestAPageIsReloadedAsChromeReloadedIt` holds tls-forge; a reload that
  bypasses the cache (Ctrl+Shift+R) is measured and not modelled.
- `fetch --clicked`, `BrowserContext.Clicked`: a person's click on the page
  sends the navigation or the form, which Chrome says in `Sec-Fetch-User: ?1`
  on every hop, a form's between `Sec-Fetch-Mode` and `Sec-Fetch-Dest`
  (`headers.form_order` has the slot now). Without it the page's script
  navigated or submitted the form, as before. Refused for `fetch()`, an XHR,
  a navigation typed into the address bar and a request a browser sent.
- A request without a browser context goes as a navigation typed into the
  address bar, where the profile says so (`headers.without_context`:
  `typed-navigation`; the 15 shipped Chrome profiles; absent or `as-given`
  keeps the old way): the profile's headers worked out as a typed navigation
  in a context has them, with the client hints an origin asked for, Accept-CH,
  Critical-CH and the ACCEPT_CH of ALPS, which a request without a context
  ignored. The fields it is given, the client's (`WithHeaders`) too, go each
  in the slot Chrome writes that field in, in place of Chrome's own: a
  reload's Pragma and Cache-Control, then Authorization, before the client
  hints; Referer, Accept-Language, the Cookie (the request's own, the jar's
  after it) and a revalidation's If-None-Match and If-Modified-Since after
  Sec-Fetch-*. One Chrome has no slot for goes where Chrome driven over
  DevTools (Playwright's `extraHTTPHeaders`) writes the extra headers it is
  given: after User-Agent, after Origin in a form's and a redirect's, by the
  bytes of their names as given (`@given` in the orders,
  `headers.given_order`: `bytes` or `as-given`), spelt as given over
  HTTP/1.1. A hop of its redirects goes without the Cookie it was given, as
  Chrome makes each hop's of its jar (`headers.given_redirect_drops`), without
  its Authorization across origins (Chrome sends it on; tls-forge does not),
  and with an Origin it was given said as "null" across origins; one started
  again for Critical-CH keeps them all. A Range it is given makes its
  Accept-Encoding `identity`. Before, the fields the profile has no name for
  went after Priority, the transport's Content-Length last, and a request by
  any method went as a navigation, body and all. Measured on Chrome
  155.0.8059.85 on macOS over its DevTools port (50 runs, 25 scenarios over
  HTTP/2 and HTTP/1.1: `testdata/chrome155-given.json`), against which
  `TestARequestWithoutAContextGivesItsFieldsAsChromeOverDevToolsDid` holds
  tls-forge, the fields Chrome writes in a slot of its own aside.
- A request without a browser context that a typed navigation cannot be,
  one by another method than GET or with a body (an empty one too), is
  refused before anything is sent (`ErrNeedsContext`): give it the context of
  the form, fetch() or XHR that sends it. `fetch` sends it from its URL's own
  page instead (above), the daemon answers it with that error, and the SDKs'
  `post()` takes the request's `browserContext` / `browser_context`. `fetch -H Referer` without `--request-kind` warns that the
  request says `Sec-Fetch-Site: none`, which Chrome sends with a Referer only
  when automation gives it one; the help's `-H` example is an Authorization.
- `proxy`: a request that says what in a browser sent it, with the
  Sec-Fetch-Mode a browser gives every request, goes as the browser sent it
  (`BrowserContext.Sent`): a navigation, typed when Sec-Fetch-Site says none,
  a form's POST, or a page's fetch(), XHR or subresource as fetch() in its
  mode, from the page its Referer or Origin names; with the browser's fields,
  in Chrome's order for its kind, but the profile's user agent, client hints,
  Accept-Language and Accept-Encoding; with the Priority Chrome writes over
  HTTP/2 for what it is for and its HEADERS frame weighted by its urgency,
  which a browser's request over HTTP/1.1, the protocol it speaks to a proxy,
  does not carry (`headers.sent_priority`, `h2.urgency_weights`); a font's
  Origin where its renderer puts it (`headers.renderer_origin_dests`). It is
  given no Origin, Referer, Sec-Fetch-* or client hints of tls-forge's, no
  preflight, no check of CORS, no answer to a 401, no start again for
  Critical-CH, no redirect followed and no answer kept: the browser does each.
  A request without Sec-Fetch-Mode goes without a context, and one that
  cannot is answered 400 with the reason. A request that came without a body
  goes without one: every GET went with `content-length: 0`. Before, every
  request of a browser went as a typed navigation, its own fields after
  Priority. Measured: Chrome 155.0.8059.85 behind `tls-forge proxy` sends a
  site every request of a page with an image, a script, a style sheet, a font
  and a frame, fetch()es, an XHR and a form's POST as it sends them directly,
  11 of 11 over HTTP/2 and over HTTP/1.1 (0 of 9 before):
  `testdata/chrome155-subresources.json`,
  `TestABrowsersRequestsReachTheSiteAsChromeSentThemThere`.
- `capture --headless --install` without `--name` is refused (exit code 2),
  and a capture whose browser says HeadlessChrome in its user agent is not
  kept as `local` (exit code 1, nothing kept): `local` is what every command
  wears by default, and a headless Chrome is told apart by that word alone.
- A request goes again as Chrome sends one again, chosen in profile JSON.
  Over HTTP/2, a stream refused (RST_STREAM REFUSED_STREAM) goes again at once
  on its connection, and one above a GOAWAY with NO_ERROR on another, as many
  times as `h2.retries` says for the failures `h2.retry_errors` names, counted
  together (`refused-stream`, `goaway-no-error`, `goaway-error`,
  `ping-failed`), `h2.retry_delay_ms` after; a request whose reused
  connection is closed or reset under it before any of its answer came goes
  again at once on another, over HTTP/2 and HTTP/1.1, `http.connection_error_
  retries` times at most, by the methods `http.connection_error_methods` says
  (`any` or `idempotent`); a 408 on a reused HTTP/1.1 connection closes it and
  sends the request again (`h1.request_timeout_resend`). The counts are a
  hop's: its answers to a 401 and a 421 share them. `h2.preface_ping_failed_
  retries` goes: a request whose connection is given up for its PING goes
  again as `h2.retry_errors` and `h2.retries` say. The 15 shipped Chrome
  profiles say Chrome's (`kMaxRetryAttempts` 2, refusals, GOAWAY NO_ERROR and
  PING counted together, a GOAWAY with an error code failing the request,
  `kMaxRetryAttemptsOnConnectionErrors` 50, any method, the 408 resent).
  Before, the transport tried a refused stream or a stream above a GOAWAY of
  any code seven times, a second apart and longer each time, failed the
  request of a lost HTTP/2 connection and the POST of a lost HTTP/1.1 one,
  and took a 408 as the answer; a profile without the fields keeps that.
  Measured on Chrome 155.0.8059.85 on macOS (29 runs, an own bench speaking
  HTTP/2 frame by frame), and tls-forge on the same bench (29 runs) does the
  same, but where Chrome's navigation preconnect makes a first HTTP/1.1
  connection count as reused. The forks of utls (the keys) and fhttp
  (`Resends`, the transports' resends) gain it. Same unreleased 1.0.0.

- An answer a request goes on from without reading it is let go of as
  Chrome lets go of it, chosen in profile JSON for each kind and protocol
  (`h1.`/`h2.` `dropped_body`: a redirect followed or refused and a 401
  answered no more; `auth_body`: a 401 answered again; `restart_body`: a
  navigation started again for Critical-CH; `preflight_body`: a CORS
  preflight). `"close"` lets go at once (an HTTP/2 stream reset with CANCEL,
  an HTTP/1.1 connection closed); `"drain"` reads in the background, apart
  from the request, `http.drain_bytes` within `http.drain_ms` (Chrome's
  HttpResponseBodyDrainer, 16 KiB within 5 s) and keeps the connection when
  the body ended; `"read-all"` reads it whole first; `"first-bytes"` sends
  the request on at once and waits for the body's first bytes however long
  (`http.first_bytes_ms` 0), keeping the connection only when the rest came
  with them; what comes within `h1.unread_grace_us`/`h2.unread_grace_us`
  (2 ms, 0.5 ms) of what came counts as come. Before, tls-forge read up to
  2 KiB of a redirect's body (the transport's) and up to 64 KiB of the
  others' before going on, so a body that came 2 s late held the next request
  back 2 s. The 15 shipped Chrome profiles say Chrome's: over HTTP/2 every
  such stream reset at once but a preflight's; over HTTP/1.1 a redirect's
  body drained, a 401's read whole (or its connection closed at once after
  `Connection: close`), a restarted navigation's connection closed, a
  preflight's let go of at its first bytes. `"read"` or no field keeps the
  old behaviour. `CloseIdleConnections` and `Close` end what a client drains
  and wait for it, so the CLI's next try still opens a connection of its
  own. Measured on Chrome
  155.0.8059.85 on macOS (25 runs), and tls-forge on the same bench (21
  runs) does the same; the forks of utls (the keys) and fhttp (`DrainBody`,
  `AwaitBody`, a body's `Detach`) gain it. Same unreleased 1.0.0.

- HTTP/2 stream dependencies as Chrome's, chosen in profile JSON
  (`h2.priority_dependency`): with `"nearest-weight"` a request's HEADERS
  depend, exclusively, on the most recently opened of a connection's open
  streams of the lowest weight not below its own (Chrome's
  Http2PriorityDependencies), so requests open at once form chains (four
  `fetch()`es: 1←3←5←7) where every stream depended on none; a stream
  answered or reset is depended on no more. The 15 shipped Chrome profiles
  say `"nearest-weight"`; `"root"` or no field keeps the old behaviour.
  Measured on Chrome 155.0.8059.85 on macOS with mixed priorities and a
  stream ending midway; the fork of fhttp gains the lists, and its shared
  empty body of an answer without one no longer races when two are read at
  once. Same unreleased 1.0.0.

- A PING of the connection's own, as Chrome's SpdySession sends it, chosen in
  profile JSON: a request's HEADERS (or a DATA frame of its body) to an HTTP/2
  connection that has read nothing for longer than `h2.preface_ping_idle_ms`
  goes with a PING in a TLS record of its own, after the HEADERS and before the
  DATA, a big-endian count from `h2.preface_ping_first_id`; none while one is
  unanswered or its check pending. Unanswered with nothing read for
  `h2.preface_ping_hung_ms`, it gives the connection up: GOAWAY
  `h2.preface_ping_failed_goaway_code`/`_debug`, then the close, and a request
  without an answer yet goes again at once on another connection, as a
  refused one does (`ping-failed` in `h2.retry_errors`, above). The 15
  shipped Chrome profiles say 10 s, 1, 10 s and PROTOCOL_ERROR "Failed
  ping."; other policies keep no PING. Measured on Chrome 155.0.8059.85 on macOS; the forks
  of utls (the keys) and fhttp (the mechanism) gain it. Same unreleased 1.0.0.

- Connection lifecycle as Chrome's, chosen in profile JSON: TCP keep-alive
  (`tcp.keepalive`, `tcp.keepalive_idle_seconds`, `_interval_seconds`,
  `_count`; Chrome 45 s, not Go's 15 s), no TLS close_notify when a connection
  is closed (`tls.close_notify`; Chrome never calls SSL_shutdown), idle
  timeouts per protocol (`h1.idle_connection_timeout_ms` 300 s reaped when a
  connection is next asked for, `h1.idle_reap: "on-request"`;
  `h2.idle_connection_timeout_ms: 0`, no HTTP/2 idle timer) and a connection
  closed as soon as a GOAWAY leaves it no stream (`h2.close_on_goaway`). The
  15 shipped Chrome profiles say Chrome's values (the keep-alive interval the
  system's on macOS, 45 s on Linux and Windows) and drop
  `http.idle_connection_timeout_ms`, which still serves profiles without the
  per-protocol fields; catalogue, legacy and migration policies keep the
  earlier behaviour. Measured on Chrome 155.0.8059.85 on macOS; the forks of
  utls, fhttp and tls-client gain the mechanisms. Same unreleased 1.0.0.

- Preserve absent versus explicit empty uploads and make Content-Length framing
  profile-owned across H1/H2/H3. Chrome155/macOS selects zero-length POST/PUT
  and explicit-empty uploads in JSON, so PATCH without a body omits the field.
  CLI -d "" remains an upload; Fetch GET/HEAD rejects an explicit body before
  origin contact. Keep the single unreleased1.0.0 candidate and exact major1.

- Correct release-anchored versioning: all current engine work is the single
  **unreleased1.0.0** candidate after published major0 (latest remote tag0.2.2).
  Further development before publication keeps major1. Only after publication
  does the next engine change reserve major2. Normalize CLI, Go module path,
  SDKs, profile/catalogue metadata and compatibility fixtures to1; exact-major
  rejection remains strict. Historical internal engine2..7 labels below and in
  saved experiments are not published releases and remain as provenance.


- Correct the inherited fhttp `TestTransportRejectsConnHeaders` fixture: an
  explicit Content-Length is message framing, not a connection-specific field.
  Keep every rejection case and verify exact received fields, complete bodies,
  no handler calls on rejection, and caller-header immutability. Add twelve
  generated/explicit/unknown-length framing controls. Runtime and profile JSON
  are unchanged; this test-only correction retains engine7.

- Unreleased engine1.0.0 (unsuffixed Go module, Node/Python1.0.0) adds required JSON
  `h2.read_loop_start` (`connection`/`first-headers`). The Chrome155/macOS profile
  emits the initial request HEADERS before starting peer-frame processing,
  eliminating the early HPACK table-update race while retaining later SETTINGS,
  ALPS, flow-control and control-operation handling. Original engine6 profiles
  remain archived; older/newer SDK/profile majors are rejected before network I/O.


- Engine6 H3: JSON selects control-frame order, GREASE payload-length vector and
  per-request PRIORITY_UPDATE source/mode. Generate fresh payload bytes with the
  measured frame-N/length relationship and use actual stream IDs/current request
  priority. Both RoundTrip and direct request-stream APIs share the same mechanism;
  legacy policy choices remain explicit in unmeasured profile candidates.


- **Breaking engine release 6.0.0:** profile-selected deferred QPACK stream
  reservation preserves JSON-defined IDs while sending prefixes/instructions
  only on demand. This fixes premature encoder/decoder stream bytes on a cold
  static-only exchange without the ID reversal caused by lazy allocation.
  Chrome155/macOS selects `h3.qpack.streams: deferred`; other choices remain
  explicit data. Go/v6, Node/Python6.0.0,15 engine_major6 candidates; schema4 and
  daemon protocol3 are unchanged. Original engine5 bytes are archived; exact
  compatibility checks and independently captured Chrome acceptance are required.
- Chrome155/macOS QPACK policy permits dynamic Cookie insertion/reference, as
  observed across controlled jar updates. This JSON-only correction removes
  the earlier unconditional exclusion; values still come from current jar state.

- Document the owner-required multi-sample comparison contract: profiles contain
  generation/selection rules and runtime templates, not frozen connection/request
  values. Distinguish invariants, generated values, state and environment; retain
  explicit normalization and uncertainty. Documentation only; engine5 and profile
  data are unchanged.

- **Breaking engine release 5.0.0:** typed QPACK error classes and nine explicit
  JSON diagnostic text/template choices. Relative-index messages use the actual
  request stream ID;capacity excess and zero increments are classified separately
  from other malformed data. RFC close codes, retry budgets and replay guards are
  retained. All15 profile candidates pin engine_major5;original engine4 bytes stay
  in the r19 archive. Go /v5,Node/Python/platform packages5.0.0;schema4 and daemon
  protocol3 are unchanged. Browser acceptance is measured per error/workload.


- **Breaking engine release 4.0.0:** profile-selected QPACK draining/duplication,
  transport versus application critical-stream close (code, triggering frame and
  reason), and bounded H3 protocol-error retries with replay/context safeguards.
  Browser values remain JSON-owned. All15 explicit candidates pin engine_major4;
  original engine3 files remain in the immutable r18 archive. Go module /v4,
  Node/Python/platform packages4.0.0; schema4/daemon protocol3 are unchanged.
  Historical acceptance is not transferred to a new major. Guaranteed-unprocessed
  retry totals are explicit `h3.retry_unprocessed_attempts` (retained value2).


- **Breaking engine release 3.0.0:** RFC9204 dynamic QPACK tables, insertion,
  all field representations, blocked decoding, ACK/cancellation, peer blocked
  credit and critical-stream error handling are implemented. Browser SETTINGS,
  insertion/warmup/base, string coding, sensitive names and stream/feedback
  choices remain JSON-owned. Chrome155/macOS advertises65536/100.
- The Go module was `github.com/Sec-CH-Lemon/tls-forge/v3`; Node/Python and platform
  bundles are3.0.0. Explicit profiles pin `engine_major: 3`. Original engine2
  bytes remain in the r17 archive; both compatibility directions are rejected.
  Schema4 and daemon protocol3 are unchanged. Other missing APIs remain open.
- Engine2 introduced profile-owned static QPACK Huffman choices. That historical
  release did not support dynamic tables; engine3 adds the required mechanism.

- **Breaking engine release 1.0.0 / profile schema 4:** every executable profile
  requires an exact integer `engine_major: 1`. Missing, invalid, duplicate,
  older/newer declarations fail before network I/O across file/embedded/Go,
  registry/catalogue, pooled/Fresh and daemon paths. Raw transport-profile
  overrides are rejected before transport construction; use the validated
  profile selection APIs. Save/Clone preserve identity;
  offline Inspect and explicit Migrate do not imply browser acceptance. All 15
  shipped profiles and catalogue policies are explicitly migrated, with original
  capture provenance retained. Browser configuration remains JSON-owned.
- **Daemon protocol 3 / Node and Python 1.0.0:** hello reports compiled engine
  version/major; every request and proxy init declares its expected major. SDKs
  gate plain and contextual requests and revalidate replacement daemon processes.
  Incompatible PATH binaries fail before receiving a request URL or cookies.
  Canonical compiled identity is engine/version.json; misleading build/release
  stamps are rejected. Future shipped runtime/fork changes require major +1.

- HTTP/3 requests now wait for local control-stream initialization, so the first
  request cannot race ahead of SETTINGS. The barrier covers ordinary and 0-RTT
  requests and direct request-stream opening, and stops on cancellation or setup
  failure. Browser SETTINGS values and ordering remain in the selected profile.

- **Profile-owned network policy (schema 3):** browser-specific TLS, H1/H2,
  QUIC/H3, header, proxy, cookie, redirect and session settings are explicit JSON
  data. Profile names and descriptive User-Agent strings no longer select policy
  for schema 3. Strict key/type/range/capability validation rejects unsupported
  settings before origin traffic. Legacy schemas are materialized on Save;
  existing capture bytes/provenance are preserved. The engine uses the
  policy-aware forks, required at the commits pushed to their branches.
  See `docs/profile-behavior.md`. Generic protocol/crypto mechanisms and host TCP
  remain engine/platform responsibilities, and missing-API scenarios remain open.

- Experimental captured-Chrome HTTP/3 now offers authenticated QUIC v1 version
  information with a fresh reserved version. It rejects malformed peer version
  information and a chosen version inconsistent with the packet version before
  HTTP dispatch. Chrome mode preserves measured Chrome155 error code0x0a and
  its acceptance of a zero Available Version;generic parsing remains RFC-strict.
  Typed QUIC transport errors no longer collapse into INTERNAL_ERROR. The Chrome policy refuses cross-version configurations and
  validates version-negotiation CID reflection. Google `ORIG` remains absent:
  it requests HTTP/3 ORIGIN-frame handling and pooling, which are unavailable.


- Experimental Chrome HTTP/3 uses a dedicated UDP socket per connection,
  eight-byte original destination CIDs and zero-byte source CIDs. Its receive
  policy accepts 1472-byte UDP payloads, advertises 65536-byte DATAGRAM frames
  subject to the packet limit, enforces two active peer CIDs, and schedules
  ACKs inside the default 25 ms limit. Transport parameters use fresh full-range
  GREASE IDs and shuffled complete TLVs. Dynamic QPACK, H3 ALPS and compatible
  version-negotiation APIs remain open; this is not whole-Chrome parity.


- **Experimental HTTP/3 transport corrections** (local transport workspace):
  Chrome profiles apply the measured TLS 1.3 QUIC hello policy. Unsupported
  dynamic QPACK advertisements are refused;captured profiles keep capacity
  and blocked streams at zero. H3 ALPS bootstrap remains unavailable.
  Protocol racing establishes connections before dispatching one HTTP request,
  retains the winning transport and observes the caller's cancellation. A losing
  transport cannot send a duplicate POST. QUIC ECH GREASE without SNI no longer
  stalls the Initial crypto stream. General Chrome QUIC/QPACK/lifecycle parity
  remains unfinished; HTTP/3 is still an explicit SDK transport option.
- **Chrome's bounded TLS connection retry**: selected locally detected TLS
  protocol errors are retried once before any HTTP bytes can be sent. Trust
  failures, remote alerts, cancellation and errors after dispatch do not gain
  an application-level replay. CLI `--retry` remains a separate policy.

### Added

- **`fetch --pcap` keeps what each request's connections carried beside its
  other files, as a pcapng file Wireshark opens decrypted**: with `--output`,
  `NAME.pcapng` holds the connections the request went out on (each try's,
  the probe's, the one to an HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5 or SOCKS5h
  proxy, with the CONNECT or the SOCKS handshake that opened its tunnel),
  every byte each way at the moment tls-forge wrote or read it, and the TLS
  secrets of each in a Decryption Secrets Block, so that no capture, key log
  or root is needed. Its TCP/IP headers are made up by tls-forge, and the
  first packet of each connection says so: TLS and HTTP are exact, the
  system's own handshake and TCP/IP fingerprint are not in it. A connection
  is closed before its request is kept, so its end is in the file; with
  `--reuse-connection` each repeat's capture holds the URL's connection from
  its start. What a proxy was given in the clear is masked, a `*` for each
  of its bytes: a SOCKS5 proxy's password and an HTTP proxy's
  `Proxy-Authorization` past its scheme, as a log writes them. Refused
  without `--output`. JSON lines and both reports name the
  file as `capture`, the request's log as `capture`. README «Reading a run in
  Wireshark».

- **`fetch --keylog FILE` and `WithKeyLogWriter(w)` write the TLS secrets of
  every connection, for Wireshark to read a capture of a run**: in the NSS key
  log format browsers write to the file `SSLKEYLOGFILE` names, the secrets of
  the connections to the sites, to an HTTPS proxy and inside its tunnels, of
  every client `Fresh` makes and of the run's address lookup. Given them,
  Wireshark or `tshark -o tls.keylog_file:FILE` reads a capture of the run
  (tcpdump, dumpcap) as it was sent and read: every HTTP/2 frame and HTTP/1.1
  message, headers and bodies, but for a site's TLS inside an HTTPS proxy's
  tunnel, which Wireshark 4.6.9 does not take apart. The file is added to,
  made with mode `0600`, checked with every other file of the run
  (`--keylog -` is refused), and said in the run's header and its log's `run`
  record; one that cannot be written is said when the run is over, and the
  run exits 1. In the library each line is one write and no two are made at
  once, of any client, so the writer need not be safe for concurrent use; a
  write that fails fails its handshake, as crypto/tls's `KeyLogWriter` does.
  README «Reading a run in Wireshark», GO.md «Reading a client in Wireshark».

- **The weekly drift check holds Chrome Stable and Beta to every fixture of
  the bench, on macOS, Linux and Windows**: the `behaviour` job of `drift.yml`
  installs each from Google on each platform a profile is shipped for and
  measures every fixture again with `measure --check --newer`
  (`--browser-arg=--no-sandbox` on Linux and Windows), a difference measured
  twice before it counts, and files an issue for each platform, channel and
  major, commented on only when what differs changes. A difference counts
  when both runs have it, a scenario with its protocol and request said
  alike up to its first colon; what one run alone has is the runner's (a
  navigation its start broke, which the error page reloaded), and a check
  with nothing in both is `unsteady` and files nothing. Run by hand, it files
  nothing unless asked (`-f file=true`), `-f profile=false` or
  `-f behaviour=false` leaves either half out, `-f os=` and `-f channels=`
  (JSON lists) measure only those runners and channels, and `-f fixtures=`
  (measure's flags, by name: `connections`, `alps`) and `-f only=` (its
  `--only`) only those fixtures and scenarios. Each run's differences and
  log go into the artifact, whatever the check came to. Before, only the
  shipped profile was compared with Chrome; the behaviour tls-forge is held
  to was measured once. The bench's `measure` exits 3 when a browser differs
  from the fixtures, 1 when it could not measure; `--newer` (with `--check`)
  holds what a build's version decides, `sec-ch-ua` and its kind and the
  length they give an HTTP/1.1 head, to what the browser sends itself.

- **`capture` keeps every client hint the browser sends a server that asks**:
  its page asks for each with a `<meta http-equiv="Accept-CH">`, which applies
  to the page's own requests alone and which no later visit carries, and the
  profile says what the browser's report came with: the device's (memory,
  pixel ratio, the window's size), the network's (`rtt`, `downlink`, `ect`),
  its person's preferences and the user agent's, as sent. Before, only the
  user agent's were kept, as the browser told the page's script, which a
  capture whose report came with none still keeps. `capture` says how many it
  sent. Chrome 155 sent its page all 21 and the next navigation none.

- **Every replay of what Chrome was measured to do runs wearing the Linux and
  Windows profiles too**, not the macOS one alone: requests and their
  connections, HPACK, HTTP/1.1 records, ALPS, WINDOW_UPDATEs, URLs, False
  Start, the first request's frames and the ClientHello, cold and resumed.
  What the platform decides, `sec-ch-ua-platform` and the client hints, is
  held to each profile's own values, written as Chrome writes them; a 401
  offering Negotiate is left out on Windows, where Chrome answers it through
  SSPI ([docs/support.md](docs/support.md#platforms)).

- **The Linux and Windows profiles of Chrome 155 have every client hint**, as
  Chrome sent them a page that asked for each, captured on GitHub's runners
  (Chrome 155.0.8059.84 on Ubuntu 24.04, 155.0.8059.85 on Windows Server
  2025): the user agent's (`sec-ch-ua-platform-version` is `""` on Linux and
  `"19.0.0"` on Windows), the device's, the network's and the preferences'. A
  server that asks for them is sent them, as by the macOS profile; before, only
  the macOS profile had any. The rest of both profiles is as it was: the
  captures matched them field for field.

- **`compare` checks that every key is a key**: a field `keys` says of each
  key of `key_share` and of the GREASE ECH key whether it is a public key of
  its kind, as the browser's always is (X25519: below 2^255−19, top bit clear,
  a point of the curve in the group of prime order; P-256, P-384, P-521: a
  point of the curve; ML-KEM-768 and -1024: FIPS 203's check), and whether
  keys of one kind are each their own. Before, keys were compared by their
  lengths alone, so random bytes in a key's place matched: the hello tls-forge
  sent before the GREASE ECH fix below now differs from Chrome's in `keys`,
  and nowhere else. `SecP384r1MLKEM1024` is named.

- **`profile.Profile.ClientProfileShuffled(shuffle)`** is the transport's
  profile with the order of the TLS extensions drawn for every connection, as
  Chrome draws it, or the capture's; `ClientProfile` draws when the browser
  does. **`profile.Profile.BareBase`** says a profile is a bare entry of the
  transport's catalogue.
- **`tlsforge.CanonicalURL`** is a URL as tls-forge sends a request for it,
  which is as Chrome does, or why it sends none.

- **A 401 that offers Digest is answered as Chrome 155 answers it**, with the
  credentials in the URL, as RFC 7616 has it: MD5 and SHA-256, each with its
  `-sess`, `qop=auth` or none, the opaque said back and a hashed username,
  the parameters in Chrome's order and a client nonce drawn for each answer;
  Digest before Basic, the first of two alike. What was answered with is kept
  by origin, realm and scheme, and sent unasked to its directory with the
  nonce count going on; a nonce the page says is out of date is answered
  again, and a request that would be sent its 32nd answer fails, as Chrome
  stops there. A challenge Chrome cannot read is passed over, and every
  challenge's parameters, Basic's too, are read as Chromium reads them: a
  quote that does not end a value is read past rather than turned down, and a
  parameter with nothing after its `=` makes the challenge one it cannot
  read. Measured on Chrome 155 (the `auth-digest-*` scenarios of
  `testdata/chrome155-requests.json`) and held to it request for request,
  each answer worked out again with the client nonce Chrome drew.
- **The daemon applies a request's browser context**, and says so: `hello`
  answers `capabilities: ["browser_context"]`, and the Node.js package's
  `browserContext` and the Python package's `browser_context` now go out as
  Chrome sends the kind they name, CORS and all. The `browser` object is read
  strictly: a key the protocol does not have is a bad request, and nothing is
  sent. Each package names the keys in its own language's style, the Python
  package's `referrer_policy` being the protocol's `referrerPolicy`, types
  them (`BrowserContext` in both), and refuses a context that is no object or
  has a key there is none of with a `TypeError`, before anything is asked.
- **`fetch --request-kind` and `--initiator-url` send a run's requests as
  Chrome sends that kind**: `navigation`, `form`, `fetch` or `xhr`, from the
  page `--initiator-url` names, CORS and all. What a page could not send, and
  a profile that is not of a Chromium browser, is refused with exit code 2
  before anything is sent or written; the run's header says what its
  requests are sent as (`sent as`), and its log (`request_kind`,
  `initiator_url`). A request CORS refuses is not tried again under
  `--retry`.
- **`Client.Validate` says why a request could not be sent**, without
  sending it: what `Do` would refuse before anything goes out.
- **`fetch()` and an XHR in a browser context do CORS as Chrome does.** One
  in cors mode to another origin whose method or headers CORS asks about
  goes after a preflight with Chrome's headers and no cookies, and not at all
  when the preflight does not allow it; what a preflight allowed is kept for
  the session as long as `Access-Control-Max-Age` says, five seconds by
  default and two hours at most; and an answer that does not name the page's
  origin, or does not allow the credentials that went, is an error. Every
  such error wraps the new `tlsforge.ErrCORS`. Methods go out as `fetch()`
  normalizes them.
- **A request can say what in a browser it stands for**, with
  `Request.Browser`: a navigation, typed or from a page, a form's GET or POST,
  `fetch()` or an XHR, from the page `Initiator` names, under its referrer
  policy, mode and credentials. It goes out as Chrome 155 was measured sending
  that request over HTTP/2 and HTTP/1.1 (`testdata/chrome155-requests.json`):
  its kind's headers in Chrome's order and values, `Sec-Fetch-Site`,
  `Sec-Fetch-Mode`, `Sec-Fetch-Dest` and `Sec-Fetch-User`, `Origin` and
  `Referer` as the Fetch and Referrer Policy standards have them (but that a
  downgrade is from https to anything else, `http://localhost` included, as
  in Chrome), the HTTP/2 `HEADERS` weight Chrome gives `fetch()` (220) on
  the connections a page's requests use, no client hints, `Sec-Fetch-*`,
  Brotli or zstd
  to a page that is not potentially trustworthy, and only the cookies
  SameSite and the credentials mode let
  through, a form's POST carrying for two minutes those that named none. One
  that carries no credentials, every CORS preflight among them, goes out on
  connections of its own, which resume only TLS sessions of their own, as
  Chrome keeps them apart (`testdata/chrome155-connections.json`), on those
  of the page's top-level site, and each hop of a redirect on those of its
  own site and credentials. What
  a page cannot send is refused before anything is sent. A request without
  one goes out as before.
- **Redirects are followed as Chrome 155 follows them**, measured
  (`testdata/chrome155-requests.json`): 301 and 302 make a `GET` of a `POST`
  alone and 303 of all but `HEAD`, each dropping the body and what describes
  it for good, where 307 and 308 keep both (Go's transport made a `GET` of
  every method, and sent a dropped body again after a 307); no `Referer` a
  request was not given; from a hop to another origin on, no `Authorization`
  and an `Origin` of `null`; no credentials a `Location` names; a Chromium
  profile's client hints after `Sec-Fetch-Dest`. A request in a browser
  context works each hop out again: `Sec-Fetch-Site` over every URL of the
  chain, the `Referer` narrowed from the one before under the page's policy
  or one a redirect's `Referrer-Policy` sets, `Origin` tainted as Chrome
  taints it and, given by a redirect, sent after `Sec-Fetch-*`, CORS on every
  redirect and a preflight again where a hop needs one, and an error wrapping
  `ErrCORS` for a redirect Chrome would not follow: `fetch()` in `same-origin`
  mode to another origin, and to a URL with credentials in it. `fetch()` of
  such a URL is refused before anything is sent.
- **A request in a browser context sends the client hints a server asked
  for**, as Chrome 155 was measured sending them: what an origin asks for
  with `Accept-CH` on the answer to a navigation, a form's or a redirect's,
  is kept for the session, which clients made `Fresh` share, and replaced,
  emptied or left as Chrome does; it goes with every navigation and form to
  that origin, in Chrome's order and where Chrome puts it, and with its
  pages' `fetch()` and XHR to it, and with nothing to another origin. A hint
  the profile has no value for is not sent. A navigation whose answer, or a
  redirect's, names in `Critical-CH` a hint its origin asks for that it did
  not carry starts again where it began, once, as Chrome's does, its first
  request with the hints after `Accept`; a form's POST and a script's
  request do not. The log says what each origin asked for, as `client hints
  asked`, and each navigation started again, as `restarted for client
  hints`.
  `Profile.Chromium` says which profiles take one.
- **`fetch --html-decoding browser` reads a page as Chrome 155 decodes it**
  for `--wait-for` and `--wait-for-element`: by its byte order mark, its
  `Content-Type`, then what a document of its type names in itself (in HTML
  an XML declaration and, over it, the first `<meta>` naming an encoding
  before the page leaves its head and is a kilobyte in; in XML its
  declaration; in CSS an `@charset`), else UTF-8 for XML and JSON and
  windows-1252 for the rest, and XML only up to the first byte its encoding
  has nothing for. So UTF-8 that names windows-1251 is read as windows-1251,
  as Chrome shows it. It is held to 174 bodies Chrome 155 was measured
  decoding, `testdata/chrome155-decoding.json`; the encoding Chrome guesses
  for a page that names none is not modelled. `legacy`, the default, reads as
  page checks always have, and `--html-decoding` without either check is
  refused. The report and the run log say which way a body was read
  (`html_decoding`).
- **`fetch --no-exit-lookup` makes no request to learn where requests come
  out**: no address service before the run, no probe of a site behind
  Cloudflare, no name a proxy gave for its exit resolved through its
  service. What a proxy says in its answer to `CONNECT`, or in the response,
  is still read; a request it said nothing of has no known exit, and the run
  says why. Without the flag a run makes these requests as before.
- **A release carries `SHA256SUMS` and `manifest.json`, and signed
  provenance for every file.** `sha256sum --check --ignore-missing
  SHA256SUMS` checks a download, and `gh attestation verify FILE --repo
  Sec-CH-Lemon/tls-forge` its provenance. The manifest binds every file, by
  name, size and SHA-256, to the version and the commit it was built from.
- **The bench the Chrome fixtures were measured on is in the repository**,
  `internal/harness`: a server that keeps every request as the bytes said it,
  over HTTP/2, over HTTP/1.1 alone and over plain HTTP, every scenario of
  `testdata/chrome155-requests.json` and the pages of
  `testdata/chrome155-decoding.json`. `go run ./internal/harness/measure
  --browser PATH` measures a browser again and writes the fixtures, or with
  `--check` holds the browser to them. Google Chrome 155.0.8059.80 on macOS,
  measured again, is what both fixtures say. The bench was in a scratch
  directory, and nothing could measure the fixtures again.
- **Which connection Chrome sends each request on is measured**, in
  `testdata/chrome155-connections.json`: 47 scenarios of a page and its
  `fetch()` and XHR of each credentials mode, to its own origin, another of
  its site and another site, to two names in turn, with preflights,
  navigations to its origin, another of its site and another site,
  redirects of a navigation, a form, `fetch()` in cors and no-cors mode and
  an XHR, to another origin of its site, to another site and back, a 307
  `POST` with a preflight and without one, connections the server
  ends, and requests it answers 421 (Misdirected Request): over a
  connection to another name, and the first time or every time over one of
  their own, a POST, a navigation, a redirect's hop and a preflight among
  them, over HTTP/2 and HTTP/1.1, each request with
  the connection it came on and whether that one resumed a TLS session.
  `measure --connections` names the fixture. Chrome takes the bench's
  certificate as a site's for them, by its key, since it pools HTTP/2
  connections across names only on a certificate without errors, and opens
  each page from another, two seconds after that one has loaded, since it
  closes its idle connections whenever its certificate verifier is told
  something new, which it is as it starts.
  Google Chrome 155.0.8059.80 on macOS, measured twice, did the same both
  times.
- **How Chrome writes the requests after a connection's first into HPACK is
  measured**, in `testdata/chrome155-hpack.json`: 9 scenarios of a page and
  what its script asked for on the page's connection, `fetch()` once and the
  same URL again, a navigation, cookies set and carried, PUT, DELETE, PATCH
  and POST, a CORS preflight on another origin's connection, a cookie larger
  than the dynamic table, and servers whose SETTINGS allow a table of 65536
  and of 1024 bytes: every header block of every connection, each field as it
  was written against the table the blocks before it left. The bench keeps
  each request's header block as the client wrote it. `measure --hpack` names
  the fixture. A scenario whose requests to one origin went on more than one
  connection is run again, at most five times: Chrome opens a spare
  connection beside a navigation's, and now and then sends the page's later
  requests on it. Google Chrome 155.0.8059.80 on macOS, measured twice, did
  the same both times.
- **The check a release is held to against a pinned Google Chrome**,
  `go run ./internal/pinned` ([docs/pinned.md](docs/pinned.md)). It reads a
  manifest of the reference build, holds the archived installer and the
  installed browser to their SHA-256, the executable to its platform and
  machine, and `--version` to Google Chrome of exactly that version, refusing
  Chrome for Testing and Chromium by name, and then compares the profile with
  it, launched as the manifest says. Its result names the commit and the
  release set it is for (`--commit`, else `GITHUB_SHA`, and `--set`), so that
  a release takes it only for what was measured. Every release waits for it:
  nothing is published until it has passed on each build the reference
  names, and a release with no reference stops there. It measures the
  reference on the bench too, every scenario of a page and every page whose
  decoding is asked about, and holds it to the fixtures tls-forge is tested
  against (`--requests`, `--decoding`), the values the build decides to the
  profile's.
- **A client can ask the daemon what it is before relying on it.** A line
  with `"control": "hello"` is answered with the protocol the daemon speaks,
  2, and its `capabilities`, without a connection; a daemon older than that
  answers it as a request with no url, which reads as protocol 1. The
  Node.js and Python packages ask it with `hello()`, and send a request with
  a browser context (`browserContext`, `browser_context`) only to a daemon
  that says `browser_context`, refusing it with the new `Unsupported` error,
  unsent, otherwise. A daemon older than the field sends `browser` as though
  it were not there, which is why a client asks.
- **A profile says what its browser draws for every connection**, as
  `per_connection`: whether it shuffles its extensions, and the lengths of
  its GREASE ECH payload. `capture` says it of the browser it measures, the
  shipped profiles say Chrome's, and a profile written by hand can say it of
  the browser it describes, where it was guessed from the profile's name and
  user agent, as it still is for a profile that says nothing.
- **A profile says the version of its format.** Profiles are written with
  `"schema": 2` (`profile.Schema`), the shipped ones too, and one that says
  it is read strictly: a field the format does not have, at any depth, is an
  error that names it, where it was passed over without a word, and a newer
  schema is refused. Schema 1 is read as strictly, without `client_hints`. A
  profile with no `schema` is read as before.
- **A profile has the values of the client hints its browser sends when
  asked**, as `client_hints`: the user agent's beyond the three it sends
  unasked, and the device's, the network's and the user's preferences, by
  name, as the browser writes them (`profile.ClientHintOrder`, Chrome 155's
  order). `capture` writes the user agent's from what the browser gives
  JavaScript, and `chrome_155_macos` ships every one Chrome 155 sent on macOS
  when a server asked for all of them. A hint a profile has no value for is
  never sent.
- **A comparison says what it was made of.** `Comparison.Measured` holds the
  browser's build and platform as it says them, how it was run, and the
  requests compared, protocol by protocol; `Comparison.Manifest` the rule
  each field was compared by (`fingerprint.Manifest`). `compare` prints the
  first above the diff, and `--json` carries both as `measured` and
  `manifest`.
- `fingerprint.ClientHello` keeps the record layer, as `RecordVersion` and
  `Records`, and reads `KeyShares` with the length of each key,
  `TrustAnchors` as dotted IDs and `PreSharedKey` without its tickets.
  `fingerprint.Field.Varies` says why a value is shown and never compared,
  `fingerprint.Field.Missing` marks one a side did not record, and
  `fingerprint.Report.Unchecked` what could not be compared; `OK()` is false
  while there is any. `fingerprint.ParsePreamble` reads HTTP/2 frames up to a
  first request's header block, `fingerprint.Representations` how each field
  of a header block was written, and `fingerprint.HTTP2.Raw` and
  `capture.HTTP2.RawFrames` keep the frames.
- `fingerprint.ClientHello.EncryptedClientHello` reads the outer
  `encrypted_client_hello` of a hello as a `fingerprint.ECH`: its cipher
  suite, its config id and the lengths of its key and payload. The log's
  `client hello` record says the payload's length as `ech_payload_bytes`.
- **Every output of a run names the run.** Its id is the moment it began,
  `2026-08-16-091850-563`, which its log and report were already named
  after: the log's `run` record says `run_id`, the trace's run says it and
  begins when the run did rather than when the trace was opened, the report
  says it with the profile worn, in its heading and as `run_id`, `started`
  and `profile` in the JSON, each request kept says it, and a session saved
  says it in its set's `note`, as `direct, run …` or `via …, run …`.
- `daemon.ServeContext` is `daemon.Serve` until a context is done: it takes no
  more requests, cancels the one in flight and answers it with why, and
  returns the context's error. `Serve` is unchanged.
- `SessionReset`, in the Node.js and Python packages, for a request that was
  not sent because the session it was made in has gone, and
  `MAX_REQUEST_BYTES`, the most a request can be as the daemon reads it.
- **The Python package's types are checked**, by mypy in strict mode, in CI
  and with `make python-typecheck`: the package's annotations, which
  `py.typed` hands to every caller's type checker, and
  `python/tests/typing_contract.py`, whose refusals have to stay refusals.
- **The Node.js package ships TypeScript types**, `index.d.ts`, for what it
  does at run time and no more: the client, its options, the request, the
  browser context, the response, `hello`, `resolveBinary`,
  `MAX_REQUEST_BYTES` and the error classes. A browser context's `kind`,
  `referrerPolicy`, `mode` and `credentials` are the values the daemon takes.
  `example/typescript/` is type-checked against them and run in CI.
- **The Node.js package's errors are classes a caller can tell apart**, the
  Python package's by the same names: `TLSForgeError`, `BinaryNotFound`,
  `TransportError`, `SessionReset` (a `TransportError` now), `RequestFailed`,
  `Unsupported` and `Timeout`, each exported. Their messages are unchanged,
  and one that wraps another error keeps it as `cause`. An error's `name` is
  its class, so `String(err)` begins with it rather than with `Error`. A
  mistake in the call is a `TypeError` or a `RangeError` and none of these: a
  request without a url and a `cookieSet` without a `cookieFile` are now
  `TypeError`s.
- `--proxy-env NAME` takes the proxy from the environment variable `NAME`, for
  `fetch`, `proxy` and `daemon`, so that its password is not on the command
  line. The variable is read only when it is named, and `--help` shows one
  named, `--proxy-env TLSFORGE_PROXY`. A name that is empty, a
  variable that is not set or is empty, and `--proxy` given as well are usage
  errors, before anything is asked or written.
- `daemon --proxy-stdin` takes the proxy from the first line of the daemon's
  input, its init line, `{"id":1,"control":"init","proxy":"…"}`. It is read
  once, before the client that goes through the proxy is made, and answered
  before any request is read: without an `error` when the daemon takes
  requests, or with one, after which the daemon ends with exit code 1 having
  sent nothing. An `init` line anywhere else is a bad request, and
  `--proxy-stdin` with `--proxy` or `--proxy-env` is a usage error.
  `daemon.ReadInit` and `daemon.AnswerInit` read and answer the init line for
  a Go program that serves the protocol itself. See
  [the init line](docs/protocol.md#the-init-line).
- `Response.Encoding` says which codings a body was decoded from, and the
  `response` record of the log says it as `decoded_from`.
- `Client.AllCookies` lists every cookie a client holds, for every host, and
  `Cookie` has `HostOnly` and `SameSite`. The cookie file is version 2, with
  `host_only` and `same_site`; a browser export's `hostOnly`, `session` and
  `sameSite` are read too. A version 1 file is read as it was, and
  `File.Unscoped` says it did not keep which cookies were their host's alone.
- **What tls-forge reproduces of Chrome, and how each part is checked**, is
  one table: [docs/support.md](docs/support.md). It names what is checked
  against a capture or by `compare`, what is known to differ, and what is not
  modelled at all, such as TCP/IP, HTTP/3 and JavaScript.
- The block a run begins with says `tcp/ip` when the profile's platform is not
  this machine's: the TCP/IP under the connection is still this machine's, and
  a server that reads it can tell. It says so too when a version named without
  a platform was answered with another platform's capture, for want of one of
  this machine's.
- **`fetch` writes down everything it does, as it does it**, for whoever has
  to work out afterwards what went wrong: every lookup of a name and the
  addresses it found, every dial, the handshake with an HTTPS proxy, the
  `CONNECT` and the proxy's answer, or its refusal with up to 1 KiB of what it
  said, every TLS handshake with the ClientHello that went out (JA4, JA4_r,
  JA3 and every list in it) and each certificate that came back, the header
  fields of each request in the order they were written, the HTTP/2 frames
  that came back, each redirect, retry and page check, and how each try and
  request ended, with the step a failed one gave up in. With `--output` it is
  kept there as `run-<time>.log`; `--log FILE` puts it anywhere else and
  `--log -` on standard error, around the count. A name ending in `.json`,
  `.jsonl` or `.ndjson` gets JSON lines, anything else `key=value` text with
  times to the microsecond; a file is added to, with mode `0600`.
  `--log-level` is `trace` (the default, everything), `debug`, `info`, `warn`
  or `error`. Every record of a request says which it is: `req`, `run`,
  `worker`, `try` and `client`. Proxy passwords, cookie values and
  credentials are `***`. `--log` naming a file the run reads or writes for
  another flag is a usage error, and a log that cannot be written makes the
  run exit 1.
- `WithLogger` has a Go client write down what it does, as it does it, to a
  `*slog.Logger`, and `Request.Logger` gives one request a logger of its own:
  each lookup and dial, the `CONNECT` and the proxy's answer, the connection
  and what its handshake settled on, the header fields as written, the answer,
  and the step a failed request gave up in, with the ClientHello of every
  connection and its server's certificates at `tlsforge.LevelTrace`. Every
  connection is dialed for a request, an HTTP/2 one that later requests go
  out on too, and its lookup and dial are that request's. Proxy passwords,
  cookie values and credentials are `***`.
- `capture` lists what a profile keeps of the machine it was captured on,
  which every request with it says: `accept-language`, and the client hints of
  the system's version, the processor, the model and the form; `--set
  NAME=VALUE` (with `--save` or `--install`, repeatable) changes one, given as
  its header carries it and checked before anything is measured. A hint the
  browser does not send is not given one, and nothing is kept.
- `capture --manual` measures a browser tls-forge cannot launch — Firefox,
  Safari, a phone's — which the person using it opens the page in:
  `--addr 0.0.0.0:8443 --host <name>` lets in a phone on the network, by a
  name it reaches this machine by (the command suggests `NAME.local`, which an
  iPhone finds by Bonjour): a browser names no server (SNI) to an address, so
  an address is refused where a profile is kept, and no profile is made of a
  ClientHello that names none. The
  first visit only gets the browser past the certificate made for the run; the
  visit measured is the next, typed into a new tab, on a connection of its
  own. A reload, a link, or a visit on a used connection is turned away with
  the reason. The profile is named after the browser, a Chromium browser by
  the brand it names (Brave is `brave_155`, though its user agent is
  Chrome's), and filed under the platform its user agent says
  (`safari_18/ios.json`); `--install` keeps it under that name, but not under
  the name of a profile tls-forge ships, which it would then answer for,
  unless `--name` says so. Its page then gives a second address, at a
  listener that offers HTTP/1.1 alone, opened the same way, which measures the
  browser over HTTP/1.1 and gives the profile its `http1` section, or a way to
  finish without it; `compare --manual` holds a profile to the browser over
  HTTP/1.1 too when it was measured so. The page then
  opens 26 connections more, each ended after its answer, and one given a
  ticket and one that resumes it: the profile draws for every connection what
  those hellos show the browser drew (the order of its extensions, the length
  of its GREASE ECH payload) rather than what its name suggests, and the
  summary says how the browser resumes against tls-forge; what a profile
  cannot say goes in its notes. The capture keeps them as `connections` and
  `resumed_client_hello`. The library has
  `MeasureVisitorAt`, `CompareVisitorAt` and `echo.WithManual`.
- `fetch --wait-for-element SELECTOR` counts an answer as the page when its
  HTML has an element matching the CSS selector, whatever its status, for a
  site that turns a client away with a 200 and a page of its own, or sends the
  page under a 403. An answer without it has a row of its own in the count
  (`✗ 200 OK, no #price`), is kept out of the success rate, is asked for again
  by `--retry`, and makes the run exit non-zero; one with it is the page, a
  403 too. Its JSON line has `missing_element`, its row in the report says
  `200, no …` with how the page began, and the JSON report counts them as
  `no_element` beside `wait_for_element`. The HTML is read in the encoding the
  response names, or as UTF-8 when it names none and is that throughout, and
  is not rendered: no script runs. A selector that will not parse, one of only
  spaces, and `-X HEAD`, which gets no body, are usage errors.
- `fetch --wait-for TEXT` counts an answer as the page when its body has the
  text in it, case and all, whatever its status, or, written as `/regexp/`
  with any of the flags `i`, `m`, `s` and `U`, text the regular expression
  (Go's syntax) matches. An answer without it is counted, asked for again and
  fails the run as one without the element does: `✗ 200 OK, no "In stock"`,
  `missing_text` in its JSON line, and `no_text` beside `wait_for` in the JSON
  report. Given both flags, a page has to have both. Another flag, an empty
  `//`, a pattern that does not compile, text that is not UTF-8 and `-X HEAD`
  are usage errors.
- `fetch --clear-output-dir` empties the `--output` directory before the run
  writes into it, of every file and directory in it, and leaves the directory
  itself. It refuses, before removing anything, the root of the file system,
  the home directory, the directory the command runs in, any directory that
  holds one of those, one with a git repository in it, one holding a file the
  run reads, and one holding the file its output is redirected to.
- **`fetch` takes a list.** Several URLs on the command line, `--urls a,b,c`,
  `--input FILE` in lines, JSON or CSV, or a list piped to standard input are
  fetched `--concurrency` at a time, four by default, and answered with JSON
  Lines, one object per request. An entry can name its own proxy, with one
  client and cookie jar for each. `--output` keeps every request in a
  directory, and `--save-cookies` writes one set per proxy. This is everything `batch` did;
  see Removed for what to change in a command that called it. What a list
  could not do before: `-X`, `-H` and `-d` are applied to every URL, `-i` adds
  the response headers to each line as `headers`, and `--json` answers one URL
  with a line instead of its page.
- `--retry N` asks again, up to `N` more times, when the answer is not a 2xx or
  when no answer comes. The waits between tries double from 250 ms and stop at
  two seconds, and `-v` reports every try that is made again with its reason
  while requests are made one at a time. The default is none, the last answer
  is the one that counts whatever its status, and the exit code still depends
  only on whether a response arrived.
- `--repeat N` makes every request `N` times, and exits non-zero if any run
  got no response; without `--output` the bodies follow one another on
  standard output. One URL is asked for one run at a time unless
  `--concurrency` says how many at once. A list is gone through once per pass,
  and each JSON line carries its pass as `run`. Lines of a single pass are
  unchanged.
- **`--output DIR` keeps every request in a directory**, made if it is not
  there, as three files whose names begin with the host, the moment the
  request was made and its number in the run, and go on with what each is, so
  that a request's files list together:
  `example.com-2026-08-16-091854-584-1-response.html`, the page, whatever its
  status, when anything came back, ending in what its `Content-Type` says it
  is (`.html`, `.json`, `.xml`, `.txt`, `.png` and so on, and the last type
  when it names more than one, as a browser reads it), or in what its bytes
  look like when the header says nothing more than octet-stream;
  `…-1-logs.log`, the request for a person to read, with every try, what each
  waited on, the header fields that went out and came back, and how an answer
  that was not a 2xx began; and `…-1-trace.json`, the request alone as a trace
  that ui.perfetto.dev opens. JSON lines name the three as `file`, `log` and
  `trace` instead of carrying the page, and so do both reports. The log and
  the trace are written with mode `0600`.
- `fetch` counts the answers by status code while it runs: a bar for how far
  the run has got, cut by how the answers went, a line for how long it has
  taken and has left, and a row for each status, by number and by name, with
  how many answers had it and their share. A last row, `no response`, counts
  requests that got none. Green and `✓` mark a 2xx, yellow and `→` a 3xx, red
  and `✗` everything else, each with a shade of its own in the bar. A run of
  one request is reported on one line. The count is redrawn in place and
  coloured when standard error is a terminal, and printed once, plainly,
  anywhere else. `--progress`, `--color auto|always|never` and `NO_COLOR`
  control it, and `-v` adds a line for every request.
- A run ends with what it came to. Under the count, a run of several requests
  prints how many were made, how many further tries `--retry` spent on them,
  the share that ended with a 2xx and the average time of one request,
  measured from when it is sent to its last answer; then the proxies it used,
  with each one nothing came back through, and where the pages, the JSON lines
  and the report went. A run that was interrupted says how far it got. A
  single request that was tried again ends its line with how many times.
- `--report` writes the run as a self-contained HTML page with a row for every
  request, for one URL as for a list. Given on its own it goes into the
  `--output` directory, or the current one, as `report-<date-time>.html`;
  `--report=PATH` says where instead. It is written however the run ended, a
  request that got no answer included, and its name is the last thing the run
  prints. A report that cannot be written fails the run with exit code
  1. The figures at its top include the average time of one request.
- Every row of the report opens to show what the request took: where it ended
  up after a redirect, the file it was saved to, its error in full, and every
  try that was made at it. A try gives how it ended, the connection it went
  out on with what the handshake settled on, how long was waited before the
  next one, and each thing it waited on with how long that took: the name
  lookup, the dial, the handshake, the request, the wait for the first byte
  and the answer. Each try is drawn as a bar on the length of the whole
  request. A report holds the tries of the rows it can show, so a long run
  does not keep them for every request.
- A try in the report opens further, to the request as it was written, every
  header field in the order it went out, and to what the answer came with: its
  header fields and, when it was not a 2xx, the first 512 bytes of its body.
  Cookie values, credentials and proxy passwords are written as `***`, as in a
  trace.
- `--report-format` writes the report as `html`, as `json`, or as both from
  the same run with `html,json`. Without it a `--report=PATH` ending in
  `.json` is written as the document and anything else as the page. The JSON
  document holds what the page shows under names of its own: the summary, each
  proxy with every address it came out of, and every request as the JSON line
  a list is answered with, with where it came out and its tries added, down to
  the steps and header fields of each. It holds every request, where the page
  stops at 2,000 rows. A directory gets one file for each format, named after
  the same moment, and a file path given two formats names them both, as
  `run.html` and `run.json`.
- **Every request says where it came out, when its proxy says.** `fetch` opens
  the tunnel through an HTTP or HTTPS proxy itself and keeps the header fields
  of the proxy's answer to `CONNECT` with the connection. A proxy that hands
  every connection an address of its own and names it there, in `X-Exit-IP`
  (with `X-Exit-Country`), in `X-ProxyMesh-IP` or in a field a file of your
  own names, gives every request the address it really came out of, and
  nothing is asked of anybody to find it. Which
  fields say it is a table built in, `exit-headers.json`, holding every field
  known when it was written: those of Massive, NodeMaven, shellroute,
  ProxyMesh, g3proxy, SOAX, Bright Data and Luminati, NetNut, Scrapoxy and Zyte
  Smart Proxy Manager. The file `--exit-headers` names, wherever it is, is
  laid over it as `mergeRight` lays one object over another: its fields and
  probes replace the table's of the same key, `"off": true` takes one out,
  and the rest are added and read first. A field can be a
  parameter of another, such as `brd_ip` in `Proxy-Status`, can come in the
  response a proxy decrypted, and can need the `CONNECT` to ask for it, as
  SOAX's `Respond-With` does. When a proxy says nothing, or only a name, the
  table says what to ask where only the same exit can answer: a probe of
  the site over the very connection the request went out on, as Cloudflare's
  `/cdn-cgi/trace`, believed only when its answer came back over the same
  tunnel, and a resolve of the name through the same proxy, as Bright Data's
  `-ip-<hash>` asking `brdtest.com/myip.json`, once for each name. Bright Data
  names a hash of the address in `x-brd-ip` instead, and that hash is shown
  where the address would be: the same hash is the same address. A request
  made without a proxy comes out where the run does, as asked before the
  first request. Where neither says, the exit is unknown, and the report and
  the log say why. When the addresses differ the report's rows get a column of
  them and the line above them says how many there were; the table of proxies
  lists the addresses each came out of; every try shows the proxy's answer.
  The log and the traces have it too, and the JSON report has it as
  `proxy_answer` and `exit` on each connection and `exit` or `exit_error` on
  each request, an `exit` holding its `ip` or its `hash`.
- **A report opens the trace of every request.** When the run was traced, by
  `--trace` or by `--output`, which keeps a trace of each request, an opened
  row links to that trace and to the request's log, relative to where the
  report is, and has **Open in Perfetto**: it opens ui.perfetto.dev in a new
  tab and hands it the trace of that request, written into the page so that a
  report opened from a file needs nothing else. Perfetto asks before it opens a
  trace from a page opened from a file. A traced report holds this one inline
  script; any other is still without one. The JSON document names the trace of
  the run as `trace`.
- `--trace FILE` records every step of a run in the Trace Event JSON format
  that [ui.perfetto.dev](https://ui.perfetto.dev/) opens: the settings, the
  profile, the exit-address lookup, and for each try the name lookup, the
  dial, the TLS handshake, the request as written, the wait, the response,
  redirects and the reason for a retry. Several requests at once are drawn on
  a row per worker. The file is one event per line, written as the run goes so
  that an interrupted run still leaves a readable trace, created with mode
  `0600` and replaced on every run. Proxy passwords, cookie values and
  `Authorization` credentials are written as `***`.
- `Client.Fresh()` in the Go package: a client of the same session, with the
  same profile, header fields, cookie jar and warmed cookies, and connections
  and a TLS session cache of its own. What it sends shares no connection with
  the client or another fresh one, and resumes none of their TLS sessions, so
  through a proxy that hands every connection an address each comes out of
  its own.
- `Request.Trace` in the Go package: optional hooks for the name lookup, each
  dial, the connection and what its handshake negotiated, the header fields in
  wire order, the first response byte and every redirect followed.
  `ConnInfo.ProxyHeader` is the header fields of an HTTP or HTTPS proxy's
  answer to `CONNECT` for the tunnel a connection goes through,
  `ConnInfo.Tunnel` the number of that tunnel, and `WithProxyHeader` adds
  header fields to every `CONNECT`.

### Removed

- **`batch` is gone, and `fetch` does what it did.** `tls-forge batch` now
  prints what to type instead and exits with code 2. A command that called it
  becomes `tls-forge fetch` with the same arguments, apart from these:

  | In `batch` | In `fetch` |
  |---|---|
  | `-i FILE` | `--input FILE`; `-i` is `--include` |
  | `-o FILE`, the JSON lines | `> FILE`; `-o` is a directory every request is kept in |
  | `-d DIR` | `--output DIR`, whose files are named after the request rather than the URL; `-d` is `--data` |
  | `-R PATH`, `--report PATH` | `-R=PATH`, `--report=PATH`; the flag alone puts the report beside `--output` |
  | three further tries by default, set with `--repeat N` | none by default, set with `--retry N`; add `--retry 3` to keep them |
  | `--repeat 0` to turn retries off | nothing: that is the default, and `--repeat` now means how many times each request is made |
  | one URL as the only argument | add `--json`; without it the answer is the page |
  | waits for URLs to be typed when none is given | a usage error; a list piped to standard input is still read |
  | `--report-ip[=false]` | nothing: a report asks nobody where its requests came out, and takes it from what each proxy said |

  Other things a `batch` user will see change: a try is made again for an
  answer that is not a 2xx as well as for no answer, once `--retry` asks for
  any. What the run ends with is the count by status and the figures under it
  rather than the `Ran`, `Scraped`, `Not 2xx`, `No response` and `Data` table.
  The count is printed once at the end even when standard error is not a
  terminal. A list whose entries all go the same way asks where it comes out
  before its first request, as `fetch` does for one URL, and no longer needs
  `--report` for that. A proxy named with `--proxy` that cannot be used fails
  the command before anything is fetched, instead of failing every line.

### Security

- Builds use Go 1.26.10, whose `crypto/x509` distrusts compromised
  intermediate certificates (GO-2026-6809, which `govulncheck` reports as
  reachable through the TLS handshake with an HTTPS proxy). Go 1.26.10 is now
  the minimum toolchain, and the image is built with it.
- **The echo server's certificate is a leaf, not a certificate authority.**
  It was marked as one, with the right to sign certificates, and
  `capture --manual` asks a person to accept it in their browser: accepting
  it could vouch for whatever it signed. It is still signed by itself and
  trusted as itself by whoever trusts it.
- **A proxy's password is said nowhere.** A proxy URL that could not be read
  was quoted back whole, password and all, on standard error and in the run's
  log. The password of every URL is now taken out of everything that is
  written down or sent on: standard error, the log, the trace, the reports,
  the JSON lines, the daemon's answers, and the `proxy` command's error lines
  and 502 answers. A proxy's username is kept. The library's errors from
  `New`, `Fresh` and `Do`, and what `proxy.Options.OnError` is given, say
  nothing of a password, and wrap the error that did, for `errors.Is` and
  `errors.As`. The HTTP/2 transport's own lines in the log, which name every
  header field it decoded when `GODEBUG=http2debug=2` asks, keep a field's
  name and lose its secret, as a request's record does.
- **The Node.js and Python packages no longer put a proxy's URL on the
  daemon's command line**, where `ps` showed its password to every user of
  the machine. Nor do they put it in the daemon's environment, which its
  owner and root can read while it runs. It goes on the first line of the
  daemon's input, the init line `--proxy-stdin` asks for, and nowhere else:
  not in the calling process's environment, and not in another client's
  daemon. A `tls-forge` older than `--proxy-stdin` refuses the flag, and the
  packages say it is older than they are, before any request. A daemon that
  refuses its arguments fails every request waiting on it rather than being
  started again for each. Until the init line is answered without an error
  there is no session: a daemon that refuses it, does not answer it in time,
  answers it with a line that is not an answer, cannot be written to or ends
  first is stopped, the requests waiting fail with why and without the
  password, and the next request is not told a session went.
- A page `--output` keeps is written with mode `0600`, as the log, the trace
  and the report are. It was `0644`, readable by everyone on the machine, and
  a page can be one that only a session could open.
- **A report no longer sends session cookies to the address service.** A
  cookie given without a domain, such as `--cookie name=value`, is filed
  against every host a client talks to, so the exit-address lookup that
  `batch --report` made at `https://ipinfo.io/json` arrived with it attached.
  The lookup is now made by a separate client with the same profile and proxy
  and no cookie jar. Runs without `--report`, with `--report-ip=false`, or
  whose cookies all name a domain were not affected. Every release up to 0.2.2
  is.
- The address the service answers with must parse as an IP address before it
  is shown; anything else is reported as not looked up.

### Changed

- **The forks are required as pushed.** `go.mod` names utls, fhttp,
  websocket, quic-go-utls and tls-client at the commits their `tls-forge`
  branches were last pushed at (2026-10-26), so tls-forge builds and passes
  its tests without a `go.work` beside the forks' checkouts; the pins before
  were of 2026-10-19 and 2026-10-20, and only that workspace built. With
  them, an HTTP/2 connection just closed no longer counts as one the origin
  has, so a request meant to wait behind QUIC waits as Chrome's does (the
  fork of fhttp: `HasConn` counts a connection that can take a request).

- **A request's timeout is one deadline for all of it**: `WithTimeout`, and
  `--timeout` for each try of `fetch`, bound its connection, its preflight,
  every hop of its redirects, its answers to a 401 or a 421, its start again
  for client hints and its body together, where each of those but the hops
  had the whole timeout again: a request answered after a 401 could take
  twice as long. A request that runs out of time says
  `context deadline exceeded`, the error of its context, which
  `errors.Is(err, context.DeadlineExceeded)` finds, and which the transport
  told apart from its own timer before (`net/http: request canceled
  (Client.Timeout exceeded while awaiting headers)`), at random.
- **utls is a fork of tls-forge's too**: `github.com/igor-lemon/utls`, the
  `tls-forge` branch of a fork of bogdanfinn/utls v1.7.8-barnius, on which
  tls-forge's forks of fhttp, tls-client, quic-go-utls and websocket build.
  A type of utls that tls-forge hands out or takes, as the `ClientHelloSpec`
  of `profile.Profile.Spec`, comes from there: code that imported
  `github.com/bogdanfinn/utls` for one imports `github.com/igor-lemon/utls`.
- **A URL Chrome sends nothing for is refused before anything is sent**: one
  on a port Chrome keeps away from, Chromium's restricted ports such as 22, 25
  and 6000 (measured on 0 and 6000, and on 4190 and 6679, which Chrome sends
  to though the Fetch standard blocks them), and a redirect to one fails the
  request. So is a path with a percent sign that escapes nothing, such as
  `/50%off`, which Chrome sends as it is and a `url.URL` would escape once
  more. `fetch` says so of every entry of a list at once and exits 2. Tests
  that took `http://127.0.0.1:1` for an address nobody answers at need
  another: port 1 is one of those.
- **`fetch` writes each URL as it was asked for**, as Chrome writes it, in its
  lines, logs, traces and reports: `https://example.com` is
  `https://example.com/`, and `HTTP://Example.COM:80/a/../b` is
  `http://example.com/b`.
- **Each hop of a redirect goes out on the connections of its own top-level
  site and credentials**, as Chrome 155 sends it
  (`testdata/chrome155-connections.json`): a navigation's or a form's hop to
  another site, and a request's without a browser context, on that site's
  connections, though one of the first site's could carry it, and a hop
  back on the first's; a hop that leaves a request without credentials on
  the connections of requests that carry none, which it stays on, back at
  the page's origin too. A hop's preflight goes out on its page's site's,
  and its answer to a 401 or a 421 on the connections the hop went out on.
  Every hop went out on the connections of the first. Through tls-forge's
  fork of tls-client, whose `WithTransportWrapper` hands tls-forge the round
  tripper of each transport; one given with `WithTransportOption` replaces
  tls-forge's, and every hop then goes out on the connections of the
  request's first.
- **A request a server answers 421 (Misdirected Request) is sent again,
  once**, as Chrome 155 sends it (`testdata/chrome155-connections.json`, and
  three scenarios of `testdata/chrome155-requests.json`): its body and header
  fields as they went, on a connection of its host's own, never one shared
  with another name, which the host's later requests go out on too. Over
  HTTP/1.1 the connection the 421 came on is closed and the request goes out
  on another; over HTTP/2 a connection the host has of its own carries it.
  Each hop of a redirect and each CORS preflight is sent again for a 421 of
  its own, a 401 answered between or not, and a second 421 is the answer.
  The cookies a 421 sets are not kept when the request is sent again for it,
  as Chrome hands such a 421 to nothing. The log says `restarted for a 421`. The 421 was the answer, which
  a request to another name sharing a connection made possible where a
  connection for each name never had one. Through tls-forge's fork of fhttp
  (`http2.WithCoalescing`, `WithResponseCookies`).
- **Connections, and the TLS sessions they resume, are kept apart for each
  top-level site**, as Chrome 155 keeps them
  (`testdata/chrome155-connections.json`): a navigation or a form goes out on
  the connections of the site of the page it loads, and what a page's scripts
  send on the page's. A request without a browser context goes out on those
  of its URL's site, as a navigation typed in. A client keeps the connections
  of the last 64 sites it sent requests to; one more drops the site used
  longest ago, closing its idle connections and forgetting its TLS sessions.
  `fetch`'s exit probe asks a site over that site's connections, which a
  request redirected there from another site went out on too. For a
  script's request from a page of another site, whose connections are the
  page's site's and not the probed URL's, or from a page of another origin
  of the URL's site, which carries no credentials there, it goes through
  another tunnel than the request, and its answer is not believed.
- **A request to another name goes out on an HTTP/2 connection the client
  holds to the same address**, as Chrome 155 sends one
  (`testdata/chrome155-connections.json`): one of its kind, for requests with
  credentials or without, and of its top-level site, whose certificate was
  verified and is good for the name, at an address the name is found at and
  on its port. A page's `fetch()` of another site serving from that address
  goes out on the page's own connection, and so does a navigation to another
  name of the page's site. The name is looked up first, as Chrome does,
  and a request no connection fits dials as before. None is shared through a
  proxy, with `WithInsecureSkipVerify`, or when `WithTransportOption` may say
  how to dial; HTTP/1.1 connections never are. The forks of fhttp and
  tls-client give tls-client's `WithConnectionCoalescing`.
- **tls-forge builds on its own forks of fhttp and tls-client**, with those of
  quic-go-utls and websocket, which name the same fhttp, so that what the
  transport writes can be changed where Chrome writes otherwise:
  `github.com/igor-lemon/fhttp`, `github.com/igor-lemon/tls-client`,
  `github.com/igor-lemon/quic-go-utls` and `github.com/igor-lemon/websocket`,
  each the `tls-forge` branch of a fork of bogdanfinn's at the version used
  before (tls-client at the commit the checksum database holds as v1.16.0,
  whose tag was moved). For Go only, and only a path: an option given to
  `WithTransportOption` imports `tls_client` from
  `github.com/igor-lemon/tls-client`, a jar given to `WithCookieJar` is one of
  `github.com/igor-lemon/fhttp`, and `profile.Profile.ClientProfile` returns
  that tls-client's `profiles.ClientProfile`. Nothing on the wire changes.
- **The credentials in a URL are sent as Chrome sends them**: only once a 401
  asks with a Basic challenge, the request sent again with `Authorization`
  where Chrome's network stack adds it, its body too; then kept for the
  session by origin and realm, sent unasked to the directory they were
  answered in and given to a 401 of the realm elsewhere at the origin; and
  credentials turned down are tried once. Measured on Chrome 155 (the
  `auth-*` scenarios of `testdata/chrome155-requests.json`, which the bench
  in `internal/harness` measures). They went with the first request, as Go's
  transport sends them: over HTTP/1.1 in the HTTP/2 layout, with an empty
  `User-Agent: ` line for a profile with no headers; and `Response.URL`, the
  `final_url` of `fetch`'s lines, said the password. A 401 that offers NTLM,
  or Negotiate to a profile of Windows, is left unanswered: Chrome answers it
  in that scheme.
- **A Node.js response has exactly the fields it documents**: `status`,
  `url`, `body`, `content`, `headers` and `cookies`, in that order. It
  carried the rest of the daemon's answer as well, its `id` and
  `bodyEncoding` among them, and would have carried whatever a newer daemon
  added. The Python package's `Response` always had only its own.
- The three fake daemons the Node.js and Python suites run against answer
  one list of scenarios, `testdata/fake-daemon/scenarios.json`, each from a
  table it dispatches on and declares, and each suite holds its fake to the
  list; a scenario no fake knows is an error naming it, where it was a 404.
  CI runs both suites against the native fake on Linux as well as on
  Windows: it counted a body's length in bytes where the others count
  characters, which only Windows could have shown.
- **`compare` reads HTTP/2 as it went.** The echo server keeps the frames a
  client sends from the end of its preface to the end of its first request's
  header block, captures carry them as `raw_frames`, and `compare` holds the
  client to the browser on which frames came, in what order and with which
  flags, acknowledgements aside, and on how each field was written in HPACK:
  indexed or not, its name from which table, each string Huffman-coded or
  not. It finds one difference from Chrome 155: tls-forge's transport writes
  `:path` with indexing and names it from the static table's second `:path`
  entry, where Chrome writes it without indexing and names it from the
  first. `compare` reports it, and exits 3, until the transport writes it as
  Chrome does. A capture saved before has no frames, and they are shown as
  not checked.
- **`compare` holds the whole ClientHello to the browser's.** It compared the
  lists a JA4 is made of and little more: another trust anchor, record
  version, legacy version, session id length or compression method, a key of
  another length, GREASE somewhere else, or another `status_request` made no
  difference. It now compares the record layer and every field of the hello,
  the contents of each extension that is the same on every connection, and
  the shape of what is drawn for each: where GREASE goes, how long it is and
  which of its values are one, the length of each key, ECH's cipher suite and
  key, and the identities and binders of `pre_shared_key`. The length of the
  ECH payload, which Chrome draws for every connection, is shown on a `~`
  line and not compared. An extension no rule describes, sent by both sides
  with different contents, is shown as not checked, and the command exits 3.
- `echo.Server.Sessions` returns the latest 128 connections rather than
  every one the server has seen, and the server keeps the latest 128 pages
  served, captures nobody has awaited, manual visitors and recovered panics:
  `tls-forge serve` left running held all of them for as long as it ran.
- **`fetch` refuses what it cannot run with, as a usage error, before it
  touches anything.** A value a flag does not take (`--progress`, `--color`,
  `--format`, `--report-format`, as `--log-level` already was), an unknown
  profile, a `--proxy` or a list entry's proxy that is no `http`, `https`,
  `socks4`, `socks4a`, `socks5` or `socks5h` URL with a host, a `--timeout`
  of nothing, and a list that does not read as one or holds an entry that is
  not an HTTP or HTTPS URL now exit 2, before a directory is emptied or a
  file opened, the address is asked about or a request is made; they exited
  1, and an unusable proxy or profile only once the run had begun. `proxy`
  refuses an unknown profile and an unusable proxy the same way, before it
  makes its authority. Two of `--urls`, `--input` and URLs on the command
  line are refused too, rather than one quietly taken over the other.
- A request's deadline in the Node.js and Python packages counts from the
  call. The time it waits behind another request is inside it, so a call
  settles within its timeout rather than within that many times the number of
  requests in front of it. A Python request whose deadline passes while it
  waits raises `Timeout` without being sent.
- The Python `Client.close()` stops the daemon at once, as the Node.js one
  does, rather than waiting for a request in flight: that request, and any
  waiting for it, raises `TransportError("tlsforge: client closed")`.
- **The Node.js and Python packages say when a client's session has gone.** A
  timeout or a broken write stops the daemon, and a daemon can die; its
  cookies, TLS sessions and connections go with it. Every request waiting for
  it is now rejected with `SessionReset`, without being sent, and the next one
  made is when none was waiting, rather than going out as a new identity
  nobody asked for. Requests after that start a new session. The request the
  daemon was working on fails with the reason, as before.
- A report given a directory, or `--report` alone, is named after the moment
  the run began, as the run's log is, rather than the moment it was written,
  so that the files of one run share it. `--report` naming the `--output`
  directory puts the report in it even before the run has made it.
- `cookie.File.Encode` returns `([]byte, error)`: it fails rather than write
  less than it was given.
- `cookie.Set.EncodeNetscape` writes a cookie's include-subdomains column from
  `HostOnly` rather than from a leading dot in `Domain`: a cookie is its
  domain's unless it says it is its host's alone, and a domain's cookie is
  written with a leading dot. `Client.Cookies` is `CookiesFor` by an older name.
- A profile from tls-client's catalogue no longer sends the transport's own
  `accept-encoding: gzip, deflate, br`: like every other header field, it goes
  out only when given. A measured profile sends Chrome's, as before.
- A client without a proxy dials through a dialer of tls-forge's own, with the
  timeout and local address the transport's would have had, so that the
  connections HTTP/2 dials apart from any request can be logged. A client
  given `WithTransportOption` keeps the transport's, since one of those options
  may be a dialer or a proxy.
- What the HTTP/2 transport says without being asked, such as a server
  breaking the protocol or a cookie with a domain it will not keep, goes into
  the run's log as a warning when there is one, rather than onto standard
  error between the lines of the count.
- **A new connection to a site resumes its TLS session, as Chrome's does.** A
  measured profile's handshake is the browser's first contact, and every
  connection was one, however many times a run went to a site. Now a profile
  whose hello offers `psk_key_exchange_modes`, every measured one, ends its
  spec with the `pre_shared_key` the browser resumes with, sent only when there
  is a session to resume: a new connection to a site that issued a ticket
  resumes it, with that extension last, after the second GREASE one. Measured
  against Chrome 155, whose cold and resumed hellos are now in `testdata/`: the
  resumed connection's JA4 is `t13d1518h2_8daaf6152771_e2d80978ab2e`, Chrome's
  own. `fetch` keeps one client for each worker and proxy, which lets go of its
  connection after every try and keeps its sessions, so every request still
  goes out on a connection of its own and the ones after the first resume.
  `WithoutSessionResumption()` keeps every connection cold, and
  `Client.CloseIdleConnections()` closes the connections a client holds open.
- **`fetch --help` shows its flags under what each is for**: what to fetch,
  the request, fingerprint and transport, proxy, session, running, output,
  and report and trace, rather than in one list of 28. The table of flags in
  README.md is under the same headings.
- **Every request goes out on a connection of its own.** Every URL, every
  `--repeat` of it and every `--retry` try opens a connection of its own, with
  a TLS handshake of its own, where it used to go out on the one a request
  before it had left open, and over HTTP/2 to share it with the requests made
  at the same time: a list or a repeat through a proxy that hands every
  connection an address came out of one of them. Now each request gets its
  own, and a try turned away from one exit is made again from another.
  `--reuse-connection` keeps a URL's connection for its repeats and its tries
  instead. A request's redirects, and what its site is asked over the same
  connection, still go through its connection, and the cookies are the
  session's as before.
- **A terminal no longer gets the page.** `fetch` printed the body on standard
  output wherever that led, and a list its JSON lines, each holding a whole
  page. On a terminal both now show the count of answers instead, and print
  the body or the lines there only with `--print-body`; a run that printed no lines
  says so at the end. A pipe, a redirect and `--output` receive exactly what
  they did before, so `tls-forge fetch URL > page.html` is unchanged.
- **`fetch --output` names a directory, not a file.** `fetch -o page.html URL`
  wrote the page to `page.html` and printed `wrote N bytes to FILE`; it now
  makes a directory called `page.html` and keeps the request in it, with a log
  and a trace beside the page. `tls-forge fetch URL > page.html` is what writes
  one page to one file. Where the requests were kept is the last thing on
  standard error, and `-v` names the page of every run.
- The report is titled `tls-forge fetch` rather than `tls-forge run`. When a
  request is made more than once it counts requests rather than URLs, and
  every row says which run it was.
- The rows of the report give `Started` without the year and no longer have an
  `Ended` column: an opened row gives both moments to the millisecond. The
  proxy and the exit address are each said once above the rows when every
  request had the same, and stay on each row when they did not.
- `fetch` reports the address its requests come out of, as the last line of
  the profile block on standard error. The address is asked of a public
  service before the first request, with the same profile and proxy and
  without the session's cookies, so **every run that goes one way now makes at
  least one additional request to a third party**. A failure is reported on
  that line without failing the fetch. A list whose entries name different
  proxies asks nobody, before it starts or after. `proxy` and `daemon` ask
  nobody.
- The exit address is asked of four services instead of one, for that line and
  for a report alike: `www.cloudflare.com/cdn-cgi/trace`, then
  `checkip.amazonaws.com`, `api.ipify.org` and `ipinfo.io`. The next is asked as
  soon as the one before it fails or has said nothing for its share of the
  wait, and the first to answer is believed. A lookup waits at most five
  seconds in all; for a report it used to wait the full request timeout for
  each proxy. Amazon and ipify report the address without a country.
- HTTP and HTTPS proxies are tunnelled by tls-forge rather than by the
  transport, so that the proxy's answer to `CONNECT` is kept. The proxy is
  spoken to over HTTP/1.1, one connection to it for each tunnel, and HTTP/3 is
  turned off for a client that has one, which the transport refused through
  such a proxy anyway. SOCKS proxies are unchanged.

- Every action the workflows use is pinned to the commit of a release, with
  the release named beside it, and Dependabot proposes their updates weekly,
  as it does the Docker bases. They were named by tags and a branch, which
  move.
- **A release is built once, and every attempt publishes what was built.**
  The release workflow builds the set, checks it on every platform, and
  stores it in the tag's draft GitHub release before anything is published;
  a release run again on its tag takes the set from the draft, however long
  ago it was built, and never builds another. What npm, PyPI or the draft
  already has is held to the set by digest: the same is passed over, and a
  file that differs stops the release. It used to keep the build for two
  days, as a workflow artifact, and to fail on a GitHub release that was
  there already. A dry run, `gh workflow run release.yml`, builds and checks
  the set and asks each registry what it has, and publishes nothing.
  RELEASING.md says how.
- **The Python package builds with hatchling 1.27 or later**, the first to
  write its licence as the metadata PyPI and pip read: `License-Expression:
  Apache-2.0` and a `License-File` for each notice. Hatchling 1.26 built it
  and left both out, and 1.25 refused it. A wheel whose metadata does not
  say both is not published, and CI builds with 1.27 itself.
- The packaging is tested where it was only run: what each npm package and
  wheel carries and how it is stamped, the licence files in each, the
  binary's mode, every refusal, and the Homebrew formula's checksum for each
  archive, each script at 100% of its lines and branches in `make
  release-test`.
- **`make dist` builds a release's set into `dist/set`**, with
  `scripts/release-build.mjs`: every file a release publishes (the five
  archives, the six npm packages packed, the Python source distribution and
  five wheels, the Homebrew formula and the licence files), with
  `SHA256SUMS` and a `manifest.json` that binds them, by digest, to the
  version and the commit. The set is verified once built. It wrote
  `dist/npm` and `dist/pypi`, unpacked and with no checksums.

### Fixed

- **A report, a trace and a kept request say what went out, whenever the
  answer began.** The transport says a request was written right after its
  write, which can come after the answer's first byte; the sending was then
  over, and its header fields went unsaid (a JSON report's first try
  without its request, on a loaded runner). What the transport says of a
  sending its answer ended is now that sending's, the end of the try waiting
  for it a moment (100 ms at most); a server that answers before it has read
  the whole request has the sending end at its first byte, as before.

- **The `proxy` command's 431 reaches a client on Windows.** A request whose
  header ran past its budget was answered 431 and its connection closed with
  the rest of the header unread, which resets it: a Windows client throws
  away what it had not read yet when that happens, and saw the answer
  without its body. After such an answer the proxy now ends what it sends (a
  FIN, or a TLS close_notify in a tunnel), then reads and drops what still
  comes, for a second or 1 MiB at most, before it closes.

- **A redirect's next request depends on no stream Chrome has closed.** The
  answer to a request with a body, a form's POST, whose HEADERS ended its
  stream was handed on before the stream left its connection's priority
  lists, so a hop sent at once could depend on it (`h2.priority_dependency`):
  on a Linux runner a form's 302 hop said `1 1 255` where Chrome says
  `1 0 255`. The stream leaves them first now, and an answer let go of
  unread (a redirect's, a 401's, a Critical-CH restart's) leaves them as it
  is let go of, as Chrome closes its stream at once, however long its body
  is then waited for. A preflight's, waited on for its first bytes, stays
  until they come, as Chrome kept one open 7 s.

- **`fetch --pcap` on Windows keeps what a QUIC connection received.** The
  capture held the datagrams it sent and none it was sent: quic-go reads a
  socket there one datagram at a time, which the capture did not see. Those
  reads are kept too now.

- **A key log that fails once no longer holds up every later handshake.** A
  `WithKeyLogWriter` writer whose write failed failed its handshake, as
  crypto/tls's does, but the fork of utls returned from that write with the
  lock every key log of the process is written under still held (bogdanfinn's
  `SSLKEYLOGFILE` support, 2024): each later handshake that wrote its
  secrets, of any client of the process, waited for it for good, the
  request's own deadline included, and so did each after a file
  `SSLKEYLOGFILE` names that could not be opened, written or closed. The
  lock is let go of on every return now; the handshake whose key log failed
  still fails. `fetch --keylog` and `--pcap` were never affected: their
  writers never fail a write.

- **The measuring server answers localhost at [::1] too.** It listened at
  127.0.0.1 alone, on a port the system picked, and gave its URL as
  `https://localhost:PORT`; a client of localhost tries [::1] first (Chrome
  does, and so does tls-forge's own client on macOS), so whatever another
  program held at [::1] on that port answered instead. Here another program's
  node workers did: `capture`'s stand-in browser in the tests reached one, and
  the capture waited out its 30 seconds (`no capture from …: context deadline
  exceeded`). By default (`127.0.0.1:0`, as `capture`, `compare` and `serve`
  start it) it listens at both addresses now, its HTTP/1.1 listener too, each
  on a port free at both; an address given with `--addr` is listened at alone,
  and a machine with no IPv6 loopback address has 127.0.0.1 alone, as before.

- **The bench takes a port free at both loopback addresses** for plain HTTP.
  It listened at 127.0.0.1 on the port the system gave and at [::1] on the
  same number, which another socket may hold there: macOS gives a port at
  127.0.0.1 that a socket of IPv6 alone holds at [::1] (another program's
  node workers on the machine measured), and the other way round. A whole
  `go test ./...` failed so once: `harness: listen tcp [::1]:53165: bind:
  address already in use`. Such a port is let go of now and another taken,
  each try asking the other address first, sixteen at most.

- **A fresh redirect is cached without its body.** A browser context's cache
  kept an explicitly fresh 301, 302, 307 or 308 only once its body had been
  read to the end, which nothing waits for when a redirect is followed: an
  HTTP/2 redirect whose body came after the 500 µs the client gives it, an
  HTTP/1.1 one larger than the 16 KiB drained, or one still being drained
  when its request ended, was not kept, and the next request for it went to
  the origin again. It is kept as the client goes on from it now, without
  its body, as Chrome keeps it (Chrome reads no redirect's body), and its
  HTTP/1.1 connection is drained as the transport's own, so that the end of
  its request no longer cuts the drain and closes the connection.

- **QUIC and TCP keep their TLS sessions apart.** HTTP/3 (`WithProtocolRacing`,
  and from DNS) shared one session cache with TCP, by name, so a QUIC
  connection offered the ticket a server had given over TCP, which a QUIC
  server cannot resume, and the other way round. QUIC's sessions are kept in
  a cache of their own now, as Chrome keeps them.

- **A CONNECT an HTTP/2 proxy refuses fails at once.** Through an HTTPS proxy
  that speaks HTTP/2, a CONNECT the proxy answered 403 or 407, or took back
  with a GOAWAY, held the dial for good, the request's own deadline included:
  the transport waited for the tunnel's body to be written, which a refused
  tunnel never is. The fork of fhttp now closes a stream's request body when
  its write is stopped, as x/net does, so the dial ends with the proxy's
  answer (`proxy responded with non 200 code: 407 ...`).

- Chrome browser-context Range requests now use the measured network slot and
  identity encoding and HTTP/1 spelling; If-Range retains renderer order and adds max-age=0.
  Complete fresh entries can answer a single range. Strong-validator prefix
  entries are validated and completed with If-Range before answering a full
  GET, with exact interval, validator and body-length checks before joining.

- **Chrome connection recheck:** enforce the 256-KiB HTTP/1 response-head
  boundary and six active connections per host pool; preserve HTTP/2 after a
  decoded over-budget Huffman field; send `illegal_parameter` for an unoffered
  TLS1.2 ALPN selection. The ordinary TLS/parser modes retain their policies.
- **Chrome cookies and browser response metadata:** retain received cookie
  pair bytes, accept an exact IP Domain as host-only, and reset equal-path
  ordering only when a replacement changes its value. Preserve original H1
  transfer/trailer declarations in browser-context responses. Chrome-mode H1
  parsing uses the measured 200 fallback for a missing numeric status.
- **Browser state:** a new narrow preflight grant replaces old permissions
  for that origin/URL/credentials scope. Revalidate cached GETs through HEAD,
  retain explicitly fresh GET redirects, and coalesce identical buffered GETs
  with caller cancellation and bounded pending work. Cache modes, document
  state and other missing APIs remain open. Exact paired observations and
  remaining limits are maintained in the sibling browser knowledge base.

- Share an HTTPS proxy's outer H2 connection and HPACK state between CONNECT
  and ordinary HTTP requests within a client/top-level site. Keep CONNECT
  deadlines and closure local to the stream, preserve active peers on idle
  cleanup, and isolate Fresh clients and different sites.
- Suppress further TLS alerts after a failed Chrome-mode encrypted write;
  its record sequence has already advanced and must never be rolled back.
- Give H2 CONNECT its measured Chrome weight 147 independently of the
  navigation or Fetch request inside the tunnel.

- Forward plain HTTP through HTTPS proxies using their negotiated HTTP/1.1
  or HTTP/2 protocol, instead of CONNECT. Keep proxy authentication on that
  hop and close both forwarding pools when idle connections are cleared.

- Preserve scripted Priority over HTTP/1.1; match cookies against escaped URL
  paths and derive their default path without percent-decoding. Decode 206
  responses and follow measured Chrome gzip EOF/first-member behavior while
  retaining malformed-stream, HTTP-framing and decoded-size error checks.

- Avoid duplicate script-owned Accept-Language/Priority fields and replace
  the current Vary representation as fresh Chrome cache sequences do.

- Fetch/XHR contexts now follow twenty redirects and reject the twenty-first
  with `the 21st redirect was not followed`. Navigation/form and low-level
  requests retain the separately measured nineteen-redirect navigation bound.

- Chrome fidelity remediation: requested-hint construction order and caller
  header spelling; partitioned cookies; browser-context GET freshness and
  conditional revalidation; gzip trailer tolerance (the subsequent measured
  clean-EOF/first-member correction is listed above); browser-context encoded response metadata; browser CONNECT headers
  and outer proxy TLS. Local transport fork edits also address ticket
  consumption/age, terminal-dot SNI, unsolicited EncryptedExtensions, compressed
  certificate errors, KeyUpdate coalescing, ALPN replacement reuse and HTTP/2
  error frames. These edits use the local Go workspace until fork publication;
  live acceptance and remaining scopes are recorded separately in net-fp-server.

- Browser-context Fetch/XHR combines repeated script fields and follows Chrome's
  renderer-map order instead of fixed custom-header slots;HTTP/1 preserves their
  input spelling,including lower case. Raw requests retain
  repeated fields. Regression fixtures cover varied names,case,lengths and
  table growth from real Chrome.
- Measured ClientHello profiles serialize ALPS only for protocols in the final
  ALPN list,including after `WithForceHttp1` changes it. Ordinary H2 offers and
  negotiated-ALPS fixtures remain covered.

- **The bench's ALPS fixture counts no connection the browser never used**:
  a connection Chrome opened as it started, beside its navigation's, and
  sent nothing on but its SETTINGS, no request and no GOAWAY, was counted as
  one of the scenario's handshakes, so on GitHub's Linux runner a check now
  and then said 2 handshakes where Chrome had made 1 (`alps-accept-ch`).
  Only the connections a request came on and those the browser refused, with
  a GOAWAY, count; no handshake Chrome was measured to make is another.

- **The bench runs a scenario again whose first page came as a reload**:
  Chrome's start on a hosted runner now and then broke the navigation a
  scenario begins with (closing its connections as its certificate verifier
  is told of the system's store), and its error page asked for the page
  again, with `Cache-Control: max-age=0`, which no page a browser opens
  carries: Beta 157 on Linux in 7 scenarios each check, Stable once in four,
  each a difference of nothing Chrome does. Such a run, its start or its run
  page asked for with a Cache-Control, is run again in a fresh profile, three
  times at most, saying so; a scenario whose page came so every time did not
  finish. No request in the fixtures is one: a form's POST and the GET of its
  redirect carry a Cache-Control of their own.

- **The bench's scenarios of connections start from a page whose connection
  ends once it is answered**: Chrome on macOS and Linux closes every idle
  connection as its certificate verifier is told of the system's trust store,
  just after it starts, and sent each run page on a connection that resumed
  the first page's session; Chrome on Windows is told nothing then, and sent
  it on one that resumed none, so its check differed in the run page's
  connection of every scenario (151 requests), and in nothing Chrome decides.
  The connections fixture was measured again so, on Chrome 155.0.8059.85:
  what each run page sent, connections and sessions alike, is what it was,
  but for the first page's address in its Referer. And whether the run
  page's own connection resumed a session is no longer held to the fixture:
  on GitHub's runners Chrome now and then sent it on a connection it had
  opened as it started, before it had a session, though the first page's had
  ended (one to three scenarios a run on macOS and Linux); which connection
  each request goes on, and whether every later one resumed, is held as
  before.

- **The bench's check holds what Linux and Windows decide as Chrome's rules
  say**: a value the platform decides (the user agent, `sec-ch-ua-platform`,
  the client hints) is held to how it was written into HPACK, its coding aside,
  since Chrome codes a value with Huffman only when that is shorter and
  Linux's empty platform version goes plain; and a head and a body of an
  HTTP/1.1 request to one write or two as Chrome's 1,400-byte rule says for
  their lengths, a shorter head on Linux taking a body along that macOS's did
  not; and a stream's last WINDOW_UPDATE, after others of it, may be missing,
  as a reader slower than the server's pause before the stream's end never
  sends it. Chrome Stable 155 on Linux showed all three against the macOS
  fixtures: its eleven differences were none.

- **The bench's check goes on past a scenario the browser does not finish**,
  and passes over what Chrome does otherwise on the platform it runs on. On
  Windows Chrome answers a 401 that offers Negotiate through SSPI, so the
  scenario that offers it never reached its end page, and the weekly check
  stopped there, Stable 155 and Beta 157 alike, before it had measured the
  rest. A scenario the browser began and did not finish is now a difference,
  what it asked kept and said, and is never written into a fixture; one it
  asked nothing of, once it has loaded others, is tried once more in a fresh
  profile, and asking nothing again is a difference too; one never begun
  before any other stops the check, as a browser that loads nothing does. On
  Windows the check passes over the Negotiate scenario, and the NTLM one,
  whose first message Chrome there writes through SSPI with the system's
  flags and version, saying why, as the replays wearing the Windows profile
  do. A page whose dump fails, as Chrome's on a macOS runner once did, is
  asked once more, and a dump that fails says the last lines Chrome said on
  its standard error. A fixture that cannot be measured at all (Beta 157 on
  Linux sent `hpack-big-cookie`'s requests over two connections every time)
  is, checked, a difference of its own, and the other fixtures are measured;
  with none measured, the check could not run.

- **The bench keeps the GOAWAY a client sends as it hangs up**: a client that
  ends a connection right after its GOAWAY, as Chrome and tls-forge do when a
  server's ALPS does not read, resets it, and Go's HTTP/2 server, whose next
  write met the reset, closed the connection, now and then before the bench
  had read the GOAWAY: `measure --alps` and the ALPS replay then said none was
  sent (2 runs of 20 of the replay on three platforms). The bench's ALPS
  server now reads on until the client has ended the connection, or for a
  second after the server is done with it.

- **The bench's `measure` and the pinned gate run Chrome on Windows and on a
  hosted runner**: both asked the browser `--version`, which `chrome.exe`
  takes as a page to open, so they waited on a browser for good; on Windows
  they now read the product name and version the executable holds, with
  PowerShell. `measure --browser-arg` gives Chrome an argument after the
  bench's own, again for more, as `--no-sandbox` where its sandbox cannot
  start, and the fixture it writes says it; the pinned gate gives the bench
  the reference's `launch` arguments, which before reached `compare` alone.

- **A Chromium profile false starts on a TLS 1.2 server, as Chrome does**: on
  a connection's first, full TLS 1.2 handshake with an ECDHE key exchange, an
  AEAD cipher suite and a protocol negotiated by ALPN, the request goes right
  after the client's Finished, before the server's; without ALPN, with a CBC
  suite or an RSA key exchange the client waits, as Chrome 155 was measured
  to (`testdata/chrome155-falsestart.json`). Chromium sets
  `SSL_MODE_ENABLE_FALSE_START` for every connection; tls-forge waited for
  the server's Finished, a round trip more, which a TLS 1.2 server could
  tell on every connection. The first read of the connection then reads the
  server's Finished and checks it. Another browser's profile waits as before.
- **Captured profiles generate a valid X25519 public key for GREASE ECH**:
  uTLS's fingerprinter filled `enc` with random bytes, bypassing its normal
  HPKE sender key generation. `Profile.Spec` now leaves that key unset so
  uTLS generates it. Payload bytes and length selection keep their existing
  behavior. Wire-level regressions check encoding, curve membership and the
  prime-order subgroup on cold and resumed connections, including both
  X25519 components of `key_share`.
- **`--clear-output-dir` knows a directory by what it is, not by how it is
  named**: the home directory, the directory the command runs in, one that
  holds either, and one holding a file the run reads are refused whatever
  they are called, in other capitals where names ignore case and by another
  name the system gives a directory (macOS's `/System/Volumes/Data`), as
  through a link already. On a Mac `-o /Users/ME --clear-output-dir` emptied
  the home directory /Users/me, and `-o OUT` a directory `out` holding the
  `--input` list. Where names keep case, `OUT` is another directory, and is
  made.
- **A request to a server that changes its protocol between connections is
  answered**: a connection dialed for a request that spoke another protocol
  than its transport (HTTP/1.1 where the address had spoken HTTP/2, or the
  other way round), as a load balancer over servers that differ can make it,
  failed the request with `the server negotiated a protocol the cached
  transport does not speak`, and one whose transport was dropped as it
  dialed built another transport and failed its request with `protocol
  negotiated`. Now such a connection is let go of, and the request goes
  again, nothing of it having been sent, on a transport set up for what the
  server speaks now, three times at most: a handshake more than Chrome, which
  takes the connection. The transports an address has and the protocols
  they speak stay in step. Through tls-forge's fork of tls-client.
- **A connection whose handshake the server never answers holds up only the
  request it is dialed for, and no longer than that request's deadline**: an
  HTTP/2 connection after a client's first to a host was dialed with no
  context, and the requests waiting for it waited for good, past their
  deadlines and Ctrl-C, through a server that took the TCP connection and
  never answered its handshake; and every connection a client dialed, to any
  host, waited for the one before it, while the first to a host held up even
  the requests to hosts whose connections were open, and `Close`. Now a
  connection is dialed within the context of the request it is for, a
  request waiting for a connection another request is opening waits no
  longer than its own context, and the connections to one address are
  dialed one after another apart from every other address's; `fetch` stops
  at Ctrl-C and SIGTERM, and ends a try at `--timeout`, whatever its
  handshake does. A SOCKS5 or SOCKS4 proxy that takes the connection and never
  answers held a request for good the same way, and lets go of it at its
  deadline now too. Through tls-forge's forks of fhttp
  (`http2.Transport.DialTLSContext`) and tls-client.
- **The client's second TLS 1.3 flight goes in one record, as Chrome's**:
  its EncryptedExtensions (ALPS) and Finished, and a client certificate's
  Certificate and CertificateVerify with them, packed into records of as
  much as one carries, as BoringSSL writes a flight, where utls wrote a
  record for each. Measured on Chrome 155 (every `alps-*` scenario of
  `testdata/chrome155-alps.json` that negotiated ALPS) and held to it,
  through tls-forge's fork of utls.
- **What a server gives in ALPS is taken as Chrome takes it**: its HTTP/2
  frames are read before the connection's first request as Chrome 155 reads
  them, a SETTINGS frame's settings taken (a header table opens the first
  request's block with a size update), and a window past 2^31-1,
  `ENABLE_PUSH`, `MAX_FRAME_SIZE` and `MAX_HEADER_LIST_SIZE` passed over;
  ALPS Chrome refuses (a frame that does not read as its type may, a frame
  ALPS may not carry, a SETTINGS acknowledgement, a frame cut short, an
  `ACCEPT_CH` frame on a stream or with flags, `ENABLE_CONNECT_PROTOCOL` or
  `NO_RFC7540_PRIORITIES` past 1) ends the connection with Chrome's GOAWAY,
  `Error parsing ALPS: N` or Chrome's own words, and the request fails, tried
  on no other connection. Measured on Chrome 155 (the 73 scenarios of
  `testdata/chrome155-alps.json`) and held to it, through tls-forge's fork
  of fhttp. Until now the transport passed over whatever ALPS held.
- **A Chromium profile's request waits for a stream**, as Chrome's does,
  when the server's are all in use, on the connection it would have gone out
  on, where the transport opened another connection; through tls-forge's
  fork of tls-client (`ClientProfile.WithStrictMaxConcurrentStreams`).
- **A page's request carries the client hints its connection's ALPS asks
  for, as Chrome's does**: a navigation, a form and each hop of a redirect in
  a browser context, over a connection whose server gave an `ACCEPT_CH` frame
  for its origin in ALPS, go with the hints it names that they do not carry,
  after `Accept`, those they carry in their place, as Chrome 155 starts such
  a request again; `fetch()` and XHR carry none, and nothing is kept for the
  origin. Measured on Chrome 155 (the 13 `alps-accept-ch*` scenarios of
  `testdata/chrome155-alps.json` it did not refuse) and held to it. The log
  says them (`client hints asked over ALPS`). Until now no request carried
  them.
- **An HTTP/1.1 request goes out in TLS records as Chrome's**, with a
  Chromium profile: its head at once, whatever its size, so that only TLS's
  16,384 bytes cut it, and a body held in memory in the same write when the
  two are no more than 1,400 bytes together, Chrome's limit; any other body
  after the head, as before. The transport cut a head larger than its 4 KiB
  buffer into pieces of 4,096 bytes, a record each, where Chrome's large
  headers, URLs and cookies fill records of 16,384, and wrote every body
  after its head, where Chrome's small bodies share the head's record.
  Measured on Chrome 155 (the 14 scenarios of
  `testdata/chrome155-records.json`) and held to it, through tls-forge's
  forks of fhttp (`http.Transport.MaxMergedHeadAndBody`) and tls-client
  (`ClientProfile.WithMaxMergedHeadAndBody`).
- **A header block of more than one frame goes out in one write, as
  Chrome's**: its HEADERS and CONTINUATION frames reach TLS together, so
  that a record of 16,384 bytes carries the HEADERS frame and the start of
  the next, whatever the profile. The transport wrote the HEADERS frame,
  larger than its buffer of 4 KiB, on its own and the CONTINUATION after it,
  a record each, where Chrome's large request headers fill their records.
  Measured on Chrome 155 (`hpack-records-big-header` in
  `testdata/chrome155-hpack.json`) and held to it, through tls-forge's fork
  of fhttp.
- **A request's body goes out in DATA frames and TLS records as Chrome's**,
  with a Chromium profile: DATA frames of at most 16,375 bytes, each filling
  a TLS record of 16,384 with its frame header, and TLS records as large as
  what is written from a connection's first byte. The transport wrote DATA
  frames as large as the server allowed, a 64 KiB body in one against a
  server allowing 1 MiB, and Go's TLS cut the first writes of a connection
  into records of 1,186 bytes that grew until 128 KB were sent, so a header
  block of 5 KB went in two records where Chrome's went in one. Measured on
  Chrome 155 (the `hpack-records-*` scenarios of
  `testdata/chrome155-hpack.json`) and held to it, through tls-forge's forks
  of fhttp (`http2.Transport.MaxDataFramePayload`) and tls-client
  (`ClientProfile.WithMaxDataFramePayload`,
  `ClientProfile.WithDynamicRecordSizingDisabled`).
- **A header block too large for one frame goes out as Chrome cuts it**, and
  no longer past what the server allows: in HEADERS and CONTINUATION frames
  of at most 16,374 bytes of payload each, the HEADERS frame's five of
  priority included, whatever the server's `SETTINGS_MAX_FRAME_SIZE`, with a
  Chromium profile. The transport cut a block into frames as large as the
  server allowed, and gave the first the block's 16,384 bytes and its
  priority's five, a frame of 16,389 that a server allowing the default
  16,384 refuses with a connection error, after which the request was sent
  again on new connections until the client gave up: a request with more
  than about 16 KB of headers, such as a large cookie, failed. Every HEADERS
  frame now leaves room for its priority, whatever the profile. Measured on
  Chrome 155 (the `hpack-big-header*` scenarios of
  `testdata/chrome155-hpack.json`) and held to it, through tls-forge's forks
  of fhttp (`http2.Transport.MaxHeaderFramePayload`) and tls-client
  (`ClientProfile.WithMaxHeaderFramePayload`).
- **The TLS extension order is drawn as Chrome draws it**: every order of
  the extensions that move as likely as any other, GREASE, padding and
  `pre_shared_key` where the capture has them. The transport's shuffle,
  which tls-forge used, passes over a swap with GREASE, and kept every
  extension in the place the profile's capture has it about twice as often
  as Chrome does: a site that knows the shipped profiles could tell it in a
  few dozen connections. A profile now draws the order itself
  (`profile.Profile.ClientProfileShuffled`); a bare entry of the transport's
  catalogue is still the transport's. Measured on Chrome 155 (two launches
  of 200 ClientHellos, `testdata/chrome155-hellos.json`) and held to a rule
  decided before measuring.
- **A page over https sends nothing to plain http on another machine**, as
  Chrome blocks it as mixed content: `fetch()` and an XHR, in any mode, with
  any credentials and by any method, nor a redirect of one there; a form,
  which Chrome submits there only once the person using it says to go on past
  a warning, nor a redirect that posts it there again (307, 308). tls-forge
  sent them all. `localhost`, a name under `.localhost` and a loopback
  address are potentially trustworthy, and go; so does a navigation, and
  anything from a page not over https. The first request is refused before
  anything is sent, by `Client.Validate` too and by `fetch --request-kind`
  with exit code 2; a redirect stops there, and is not tried again under
  `--retry`. Each is an error wrapping the new `tlsforge.ErrMixedContent`.
  Measured on Chrome 155 (the 22 `mixed-*` scenarios of
  `testdata/chrome155-requests.json`) and held to it request for request.
- **A server's cookies are held to what Chrome takes of them**, with a
  browser context and without: a prefix's rules in any case (`__Secure-`,
  `__Host-`, `__Http-`, `__Host-Http-`), `SameSite=None` only with `Secure`,
  `Secure` only from https or plain http to the machine itself, a `Secure`
  cookie left alone by one of its name from plain http, at most 4096 bytes of
  name and value, and a `Path` or `Domain` past 1024 bytes passed over. A
  `Secure` cookie goes to plain http on the machine itself, as Chrome deems it
  secure. tls-forge kept every cookie the transport's jar took, and sent the
  invalid ones back. Measured on Chrome 155 (the six `set-cookie-*`
  validation scenarios of `testdata/chrome155-requests.json`) and held to it
  request for request. The cookies the caller gives are filed as they are.
- **A script's answer from another site keeps its `SameSite=None` cookies
  alone**, as Chrome's: the answer to `fetch()` or an XHR of another site
  than its page's set cookies of `SameSite=Strict`, `Lax` and of none
  named, which tls-forge kept and a later request carried. A navigation's, a
  form's and a request's to its page's site keep any, whatever site a
  redirect went through. Measured on Chrome 155 (the six
  `set-cookie-samesite-*` scenarios of `testdata/chrome155-requests.json`)
  and held to it request for request.
- **`Sec-Fetch-Storage-Access` goes as Chrome sends it**: on a script's
  request with credentials to another site than its page's. A redirect that
  takes one through another site back to its page's site sends none, though
  `Sec-Fetch-Site` says cross-site; tls-forge sent it there. Measured on
  Chrome 155 (`set-cookie-samesite-fetch-redirect-back`).
- **The cookies an answer sets are kept as Chrome keeps them**, with a browser
  context: none of those of the answer to a request that carries none
  (credentials `omit`, or `same-origin` to another origin, each hop of a
  redirect by its own), and none of a preflight's. tls-forge kept every
  cookie every answer set, so a later request carried what Chrome's would
  not. An answer CORS refuses keeps its cookies, as Chrome's does. Measured
  on Chrome 155 (the five `set-cookie-*` scenarios of
  `testdata/chrome155-requests.json`) and held to it request for request.
- **A request goes out for its URL as Chrome writes it**, with a browser
  context and without: the scheme and the host in lower case, a name in
  another script in Punycode, an IPv4 address in any of its forms dotted and
  decimal, an IPv6 one as the URL Standard writes it, no port the scheme
  means, a slash for a backslash, dot segments resolved, what a path or a
  query cannot hold percent-encoded and what is percent-encoded already left
  as it is, and the spaces around it, any tab or newline in it and its
  fragment dropped; each hop of a redirect is the URL Chrome makes of its
  `Location`. The server name, `Host` and `:authority`, the request target,
  the cookies, the origin, the connections, a Digest answer's `uri` and
  `Response.URL` are all of that URL. tls-forge sent a URL as `url.Parse`
  reads one: a host in capitals, a port the scheme means, dot segments and
  an IPv4 address in another form went out as given, and a `Location` naming
  another host and port without a scheme, after a plain http URL that named
  no port, went out with the `Host` of the hop before. Measured on Chrome 155
  over HTTP/2 and HTTP/1.1 (`testdata/chrome155-urls.json`, 58 URLs given to a
  page, by a `Location` and typed), and held to it through the transport, the server
  name and `:path` included. `CookiesFor` and a browser context's `Initiator`
  read a URL the same way.
- **WINDOW_UPDATEs go as Chrome sends them while a body is read**, with a
  Chromium profile: what is read of a window is told once more than half of it
  is untold, 3 MiB of a stream's 6 MiB and 7.5 MiB of the connection's 15 MiB,
  or at the first read more than five seconds after the last, however little; a
  stream the server ended is told nothing more; and the server's own window
  changes none of it. The transport told a stream of every 16 KiB read while
  the server's own window was under 1 MiB, as the RFC's 65535 is, eleven
  updates for a body of 300 KiB where Chrome sends none, and gave the
  connection back less than half its window at a time, which Chrome never does.
  Bodies are read 8 KiB at a time, as Chrome reads them, so that an update says
  at most that much past half. Measured on Chrome 155
  (`testdata/chrome155-flow.json`) and held to it, through tls-forge's forks of
  fhttp (`http2.Transport.WindowUpdateDelay`) and tls-client
  (`ClientProfile.WithWindowUpdateDelay`).
- **A request without a browser context goes to plain http as Chrome sends it
  there**, with a Chromium profile: without the client hints and `Sec-Fetch-*`,
  and offering neither Brotli nor zstd. tls-forge sent every header of the
  profile to any URL, seven Chrome sends only to a potentially trustworthy one,
  and an `Accept-Encoding` it does not offer another. Each hop of a redirect
  goes as its own URL is, from https to plain http without them and from plain
  http to https with them, where every hop went with the first request's
  headers. `localhost`, a name under `.localhost`, `127.0.0.1` and `[::1]` are
  potentially trustworthy, as https is, and get them all. Measured on Chrome
  155 (the `nav-direct-*` and `redir-nav-direct-*` scenarios of
  `testdata/chrome155-requests.json`), and held to it request for request. A
  header the client or the request was given goes as given, as before.
- **The trust anchors of Chrome 154 and later go out in Chrome's order**,
  sorted by their bytes, as Chromium sorts them, and `compare` holds them to
  it. Every capture of Chrome 154 and 155, on three platforms, holds them so;
  tls-forge drew an order for them once for each process, as an older Chrome
  did, so it sent Chrome's IDs in an order of its own, and `compare`, which
  held them to their set, saw nothing. A profile captured from a Chrome before
  154, whose order was drawn for each process (the captures of 152 and 153
  hold three orders each), is still drawn so and compared as a set.
- **A request whose credentials are kept to its page's origin carries none
  back there after a redirect took it elsewhere**, in no-cors mode as in
  cors mode, as Chrome 155 sends it (`redir-fetch-no-cors-back-cookies` in
  `testdata/chrome155-requests.json`, and `conn-redirect-no-cors-back` in
  `testdata/chrome155-connections.json`): a no-cors `fetch()` of another site
  redirected to the page's origin carried the page's cookies there. From
  the first hop that leaves the page's origin, what it gets is no longer the
  page's own, and it carries no credentials again.
- **The request that answers a 401 in a browser context carries the cookies
  the request did**, as Chrome 155 sends it (`auth-nav-cross-site-samesite`
  in `testdata/chrome155-requests.json`): a navigation to another site that
  asked for credentials answered with that site's `SameSite=Strict` cookies,
  which the navigation itself had rightly gone without. The jar was told
  which cookies the answer carries about a copy of its URL the transport
  never asked about.
- **A request's own `Cookie` goes with the jar's cookies over HTTP/1.1 too**,
  as `net/http` adds a jar's: every cookie it names first, then those the jar
  holds for the URL, the same over HTTP/1.1 and HTTP/2, on the answer to a 401
  and on a redirect to its host or one under it (a redirect to another host
  carries the jar's alone, as before). Over HTTP/1.1, where a request has a
  layout of its own (a profile that measured HTTP/1.1, as every shipped one
  but `chrome_151` on Linux and Windows did, or a bare catalogue name), its own
  replaced the jar's. Several `Cookie` fields now go as one, every cookie in
  them before the jar's, where the transport kept only the first once it added
  the jar's; a stray `;` leaves no empty cookie, and a `Cookie` with none in it
  is no `Cookie`. GO.md, both libraries' READMEs and `Request.Cookies` said a
  `Cookie` of one's own replaced the jar's.
- **A request without a browser context sends its cookies where Chrome 155
  does**, with a Chromium profile: right after `Accept-Language`, over
  HTTP/2 one field for each cookie, right before `priority`, and over
  HTTP/1.1 one line, on a redirect's hops too; a `Cookie` the request is
  given goes there as well. The transport wrote them after every header the
  profile names, which over HTTP/2 put them after `priority`. In a browser
  context they went there already, as every kind of request Chrome was
  measured sending cookies with shows (`testdata/chrome155-requests.json`).
- **A connection's later requests go into HPACK as Chrome writes them**, for
  a Chromium profile, measured on Chrome 155: a `:method` other than GET and
  POST without indexing, named by the static table's first `:method`, as
  `:path` already was; a field larger than the dynamic table, such as a
  cookie of 4 KiB, with incremental indexing, which empties the table, so that
  the requests after it are written whole; and the table as large as a
  server's SETTINGS let it be, said at the start of the next header block.
  The transport indexed such a `:method` and named it by the static table's
  second, which moved every dynamic index after it, wrote a large field
  without indexing, and kept the table at 4096 bytes. Through tls-forge's
  forks of fhttp (`hpack.Representation.IndexTooLarge`,
  `http2.Transport.MaxEncoderHeaderTableSize`) and tls-client
  (`ClientProfile.WithMaxEncoderHeaderTableSize`).
- **`:path` goes into HPACK as Chrome writes it**, for a Chromium profile:
  without indexing, named by the static table's first `:path`. The transport
  indexed it and named it by the second, which `compare` reported and the
  pinned check failed on; the fork of fhttp now says how each field is
  written (`hpack.Representation`), and the profile says it.
- `fetch` writes no URL's password. Its lines said the `url` asked for as it
  was given, password and all, and so did the line of each request with
  `-v`, the file kept of each request and both reports, against what the
  README says of every URL: each now says the username alone, as the log and
  the trace did. The request still goes out with the URL as given.
- A client profile given as a transport option
  (`WithTransportOption(tls_client.WithClientProfile(...))`) orders the
  HTTP/2 pseudo-headers too, as GO.md says an option that sets what tls-forge
  sets does. Every request carried the tls-forge profile's order, so its
  handshake was one browser's and its pseudo-headers another's.
- `THIRD-PARTY-NOTICES.txt` names `github.com/andybalholm/cascadia`, which
  `--wait-for-element` linked into the binary without its notice. A check in
  CI now makes the notices, the report's stylesheet, `gofmt`'s output and a
  tidy `go.mod` again and holds each to what is committed
  (`make generated-check`).
- `--profile`'s help said its default was `chrome`, also on a machine where a
  run wears the browser measured there. It says what the default is: that
  browser when there is one, else `chrome`.
- **A Docker image built from a developer's checkout carries none of what
  that checkout has lying around.** The build was given a profile measured
  from the machine's own browser, which is compiled into the binary, along
  with virtualenvs, `node_modules`, a binary built in the root, `tmp/`,
  reports and agent worktrees. Release images, built from clean checkouts,
  were not affected. The image's working directory is made writable by its
  user explicitly, and its two bases are pinned by digest.
- `capture` finds Chrome, Chromium and Brave installed for one user on
  Windows, under `%LOCALAPPDATA%`, and Edge and Brave under `Program Files`
  as well as `Program Files (x86)`. A folder an unset variable names is no
  place to look, rather than a path under the working directory.
- A plain-http request to a host the client had reached over HTTP/2 failed
  with "http2: unsupported scheme", and an HTTPS request a plain one was
  redirected to on its own host failed with "protocol negotiated": tls-client
  took a URL with no port for one on 443, whatever its scheme, and sent it on
  the connections HTTPS had there. A plain-http request is told port 80 now,
  and keeps the host it was asked for: `Host`, the answer's URL, logs, traces
  and errors say it as it was.
- A profile written by hand on a catalogue entry that is one of utls's own
  presets, such as `chrome_110` or `safari_16_0`, failed with "please
  implement this method": its spec is read now as utls reads it to connect.
- The two ALPS codepoints were named the wrong way round: 17613 (0x44cd),
  which Chrome 155 sends and BoringSSL calls `application_settings`, was
  shown as `application_settings_old`, and 17513 as `application_settings`.
  Captures, logs and `compare` name them as BoringSSL does now.
  `fingerprint.ExtALPS` (17613) and `fingerprint.ExtALPSOld` (17513) are the
  names to use; `ExtApplicationSettings` and `ExtApplicationSettingsOld` keep
  their values, and are deprecated.
- A capture whose `session_resumed` said false made a profile of a resumed
  connection's hello: `FromCapture` read resumption from what the capture
  said, not from the hello. It reads it from the hello's bytes now, where a
  `pre_shared_key` that does not parse counts too, and refuses a capture
  whose JA4 or `session_resumed` contradicts its hello.
- `compare` did not compare the priority on HEADERS: a client that sent none,
  or another, matched Chrome, which sends one. Nor did it compare PRIORITY
  frames but through the Akamai string, the values of `:method` and
  `:scheme`, or an HTTP/1.1 request's method and version. It compares all of
  them now, and says a priority's weight as RFC 9113 counts it, 1 to 256.
- A Chrome profile sent the payload of its GREASE `encrypted_client_hello`
  at one length on every connection, the one its capture happened to draw,
  where Chrome draws one of 144, 176, 208 and 240 bytes for each connection,
  each as likely: measured on Chrome 155 over 301 connections. A length that
  never changed told tls-forge's connections apart from Chrome's. A Chromium
  profile now draws it as Chrome does, cold or resumed; its config id, key
  and payload were fresh for each connection already. A profile of another
  browser keeps the length it was captured with.
- A browser `capture` launched was ended by killing its own process alone:
  the renderer, GPU and network processes Chrome starts were left to end by
  themselves, and anything that did not stayed running after the run. The
  browser now starts as a process group of its own, a process tree on
  Windows, and closing it, or the end of its context, ends all of it.
- Every command had the HTTP/2 transport make a line about each frame it
  read, whether or not anything kept it: `proxy` and `daemon` among them, and
  a `fetch` with no log. Measured on loopback, that was 4 to 9% of a
  request's time and some 50 to 75 allocations. The transport is told to say
  them only by the first log a run keeps at the trace level, before the run
  opens a connection, and is never told otherwise again, since every
  connection reads the setting without a lock.
- A list that goes several ways read its `--cookies` file again for each
  identity's client, as the list got to it, under the lock every worker
  waits on and from the file as it was by then: a file changed meanwhile, or
  one that no longer read, gave a later identity another session or stopped
  it. The file is read once, before the run, and each identity's set is
  chosen then; one drawn at random is drawn once for each identity, and the
  log and the trace say which, identity by identity. A cookie file that
  cannot be read stops the run before its output directory is cleared or its
  log, trace or report opened.
- A run resolved its profile once for what it said and again for each client
  it made. A list that goes several ways makes a client for each as it gets
  to it, so a client made after `capture --install`, or after the file of a
  `--profile PATH` changed, wore the new profile while the run, its log and
  its kept requests said it wore the old one. `fetch`, `proxy` and `daemon`
  resolve it once, before they start, and every client wears that one.
- **The echo server bounds what a connection can hold, and for how long.** A
  handshake, a request or an HTTP/2 frame sent a byte at a time held its
  connection for as long as each byte came within 30 seconds of the last, an
  HTTP/2 request that never ended was held for as long as its client kept the
  connection busy, and any number of connections were served. A handshake now
  has 10 seconds in all and a request 10 seconds from its first byte, an
  HTTP/2 stream whose request has not ended by then is reset, a connection
  with no stream open for 30 seconds is told `GOAWAY`, and 128 connections
  are served at once, the next waiting to be accepted. A connection ended
  for breaking HTTP/2 is read for a second more before it closes, so that
  the `GOAWAY` saying why is not lost to a reset. Running out of file
  descriptors for a moment stopped the server accepting connections for
  good; it is waited out.
- **The echo server's HTTP/2 keeps to the client's windows and settings, and
  to bounds of its own.** It sent answers without looking at the client's
  flow-control windows, so a client that kept them small, or did not widen
  the connection's past 65535 bytes, was sent more than it allowed, and it
  kept a header table larger than a client asking for none could follow. It
  read frames of up to 16 MiB, held a request reset before its end until the
  connection closed, and took streams past the 250 it announced. Now an
  answer goes as the windows open, `SETTINGS_INITIAL_WINDOW_SIZE` and
  `SETTINGS_HEADER_TABLE_SIZE` are kept to, a stream reset is let go at once,
  and a connection holds at most 100 streams and 512 KiB, past which a stream
  is refused. A header list over 64 KiB is answered 431 and a body over
  64 KiB 413, where the connection used to close; a stream that breaks the
  protocol is reset and the rest go on; a frame over 16 KiB, a header block
  that cannot be decoded and a setting out of range end the connection with
  a `GOAWAY` that says why. Request trailers are read and dropped.
- **The echo server reads HTTP/1.1 as RFC 9112 has it, and says why it
  refuses a request.** A space before a header's colon was taken out, so
  `Content-Length : 5` was a length another server would not read; a header
  continued on the next line, a carriage return inside a line, a length with
  a sign and a version that is not HTTP/1 were taken too. They are refused
  now, and every refusal is answered with its status and reason, 400, 413,
  414, 417, 431, 501 or 505, before the connection closes, where the
  connection used to close without a word. A client that sends `Expect:
  100-continue` is told to go on before its body is read, rather than left
  to wait; `Connection: close`, and HTTP/1.0 without `keep-alive`, end the
  connection after the answer; and a request's header lines are held to 64
  KiB in all, as an HTTP/2 header list is.
- **`proxy` bounds what one connection can hold.** A request's header had no
  limit of size, and a header, or the handshake in a tunnel, sent a byte at a
  time held its connection for as long as each byte came within 30 seconds of
  the last. A header longer than 1 MiB is now answered 431, a header has 10
  seconds from its first byte and the handshake 10 seconds in all, and 1024
  connections are served at once, the next waiting to be accepted until one
  ends. A body keeps only the 30 seconds of each read, so a large upload on a
  slow link still goes through. Running out of file descriptors for a moment
  stopped the proxy accepting connections for good; it is waited out. An
  answer outside a tunnel was cut off 30 seconds into it, however steadily the
  client read it.
- A `CONNECT` to a port other than 443 lost its port when the request inside
  named the host alone, and the request went to port 443; a request inside a
  tunnel that named another host went to that host. A request now goes to
  the host and port the `CONNECT` named, and one that names somewhere else is
  answered 421 Misdirected Request. Bytes a client sent behind its `CONNECT`
  without waiting for the answer, the start of its handshake, were left
  unread, and the handshake waited until the connection timed out.
- **`proxy` passes on no field of the connection it came on.** A field the
  caller's or the origin's `Connection` named, `Connection: X-Hop` with
  `X-Hop`, went on to the other side, and so did `TE` and `Trailer` from the
  caller and `Keep-Alive`, `Upgrade` and `Proxy-Connection` from the origin.
  An answer to `HEAD` said its length was 0, and a 204 or a 304 was sent
  with a length and the body the transport had; the next answer on the
  connection could then not be read. A request to upgrade to a WebSocket was
  sent on as an ordinary one, and its answer taken for the upgrade's; it is
  answered 501 now. An answer's fields are written in a fixed order.
- A list that began with a UTF-8 byte order mark, as one saved by some
  Windows editors does, had its first URL refused; the mark is taken off. A
  URL whose scheme was written in capitals, `HTTP://`, was refused as not an
  HTTP URL; it goes out as `http://`. A line of a list longer than 1 MiB is
  said to be, with which line it is.
- **SIGTERM stops a command in order, as Ctrl-C does.** It ended `fetch`
  where it stood, without its report, its session or the end of its trace,
  which `kill`, a service manager and `docker stop` all send; and `daemon`,
  which never looked at Ctrl-C, ended without answering the request it was
  making. Now `fetch` cancels the requests in flight and writes what it has,
  and `daemon` answers the request in flight with why and exits 0. A second
  signal ends either at once.
- A Python request's deadline did not cover writing it. A daemon that stopped
  reading held a request with a 0.05-second deadline for as long as the daemon
  lived, since a body larger than the pipe waited on it; `close()` waited too.
  The write now ends at the deadline, the daemon is stopped, and the request
  raises `Timeout`.
- A request longer than the daemon reads, 16 MiB with its JSON, a binary body
  in base64 and the newline (a 13 MiB file, say), ended the daemon and the
  session in it, and the next request went out without its cookies. The
  Node.js and Python packages now refuse it before it is sent, with a
  `RangeError` and a `ValueError`, and the daemon and its session are left as
  they were. The daemon says why it stops at a line that long, which it reads
  no further than its limit.
- **Two flags naming one file no longer lose it.** `--input urls.txt --trace
  urls.txt` read the list and wrote the trace over it, and a report, a log or
  a saved session could be written over the list, the session a run started
  from, the exit header fields, or one another, by one name, a link or a hard
  link. Every file a run reads and writes is now checked together before the
  list is read or anything is emptied, opened or asked. Two that are one file
  when the run writes it for either are a usage error, as are a file the
  run's standard output or error is redirected to, a file that is the
  `--output` directory or would have to hold it or another file, and a file
  that is a directory or whose directory a file is in the way of. `--cookies`
  and `--save-cookies` may still name one file. `--clear-output-dir` refuses
  a directory holding a `.json` `--save-cookies`, which a run reads to add its
  session to.
- A report is written beside its file and moved over it once whole. One that
  failed half way, or a disk that filled, left half a report where the last
  one had been. A symbolic link where a report goes is replaced rather than
  written through, and a device such as `/dev/null` is written to as it is.
- `--trace` and `--save-cookies` make the directory their file goes in, as
  `--report` and `--log` did: a trace into a directory not there yet stopped
  the run, and a session saved into one was lost once the run was over.
- A host of more than about 200 characters made the names of a request's
  files longer than a file system allows, and `--output` stopped the run at
  the first such request. A host longer than 100 characters now keeps its
  first 91 and a hash of the whole.
- A file of sessions could be replaced by a single newline. A cookie dated
  after the year 9999, which a Netscape file can say and a browser export
  can write as a number, made the encoder write an empty document without an
  error, and `--save-cookies` wrote it over the file. A date read from a file
  is now kept within what the format can write, the latest or the earliest
  it can say; `cookie.File.Encode` returns an error for a date it cannot hold,
  and nothing is written when it does. A negative expiry in a Netscape file is
  a date in the past and the cookie has expired, rather than a session cookie.
- `--save-cookies` with a `.txt` file and a list through more than one proxy
  kept only the last proxy's session, each replacing the one before, while
  the count said every cookie was saved. Such a run is now refused before
  anything is fetched, with exit code 2, and told to name a `.json` file,
  which keeps each session as a set of its own.
- **A saved session keeps where each cookie goes and how long it lasts.** A
  cookie its host's alone was written down without saying so and read back as
  its domain's, so it went to every subdomain; a session cookie came back
  expiring in the year 9999; and a Netscape line whose include-subdomains
  column said FALSE was filed as its domain's too. Each cookie now keeps its
  scope, its lifetime and its `SameSite` from the jar to the file and back,
  in all three formats, and `--save-cookies` writes the whole session,
  including what a redirect's host set. A cookie lives at most 400 days, as
  in Chrome, which also keeps a `Max-Age` of centuries from becoming a date
  that cannot be written down.
- **A compressed answer is decoded as Chrome decodes it, and its header
  fields describe what is left.** A `deflate` body in the zlib form the name
  means hung until the request's deadline, over HTTP/1.1 and HTTP/2; a raw
  deflate body lost its first two bytes; and over HTTP/2 a gzip, br or zstd
  body was decoded with its `content-encoding` and `content-length` left on,
  so `tls-forge proxy` handed a browser behind it a page it could not decode,
  and `daemon` gave the Node.js and Python clients fields that were not true
  of the body. Bodies are now decoded by tls-forge from gzip, x-gzip, deflate
  (zlib or raw), br and zstd, stacked in any order, with
  `content-encoding` and `content-length` taken off once they are; a coding
  Chrome does not know, a `206` range, an empty body and a `HEAD` are left as
  they came, their fields with them. `WithMaxResponseBody` counts the decoded
  bytes, so a small body that decodes to an enormous one stops at the limit,
  and a zstd body that asks for a window over 8 MiB is refused, as Chrome
  refuses it. An HTTP/1.1 answer that was not compressed keeps its
  `content-length`, which the transport used to take off every one.
- `daemon` answers a request whose session holds no cookies with
  `"cookies": []`, as the protocol document always showed, rather than `null`;
  `null` now only ever comes with `error`. The Node.js and Python clients read
  both as no cookies, so nothing changes for them.
- A request never says `Go-http-client`. A profile from the transport's
  catalogue (`firefox_148`, `safari_ios_18_5`) brings a handshake and no
  headers, and the transport gave such a request its own user agent; it now
  sends none unless the profile or the caller names one, over HTTP/1.1 and
  HTTP/2 and on a redirect. `fetch` says, in the header of the run, that such a
  profile comes from tls-client's catalogue with no headers of its own, rather
  than that it shipped with tls-forge.
- A capture page that reported back is answered before the measurement is
  handed over, so the browser's page says it went through rather than that the
  server went away.
- Profile names know the phones' platforms, `_android` and `_ios`, and a
  profile from an iPhone or an iPad does not shuffle its TLS extensions: every
  browser there connects through Apple's stack, Chrome included.
- **A chain of redirects ends at its twentieth request, for every profile, as
  Chrome's does.** With a profile that carries an HTTP/1.1 layout, which
  includes every shipped Chrome profile, redirects were followed without
  limit: the policy that prepares the next request's headers replaced the
  transport's own check instead of adding to it. Two pages redirecting to each
  other were requested until the timeout, and a local server measured 54,600
  requests in five seconds. Chrome 155, measured on a chain that does not
  end, makes twenty requests and does not follow the twentieth redirect; the
  request fails there now with `the 20th redirect was not followed`, in the
  library, `fetch` and both SDKs. A catalogue profile stopped after ten with
  `stopped after 10 redirects`, and follows nineteen now.
- A redirect sent the URL that redirected, query and all, as `Referer` to
  wherever it led, another site included, where Chrome sends none a request
  was not given; a `Referer` a request was given was replaced by it.
- Every line of an error is printed with `tlsforge: ` at its start, once. An
  error from the Go library, which already begins that way, was printed as
  `tlsforge: tlsforge: Get "http://127.0.0.1:1/": … connection refused`, and
  when a run failed for two reasons at once, such as a request that got no
  answer and a report that could not be written, the second line had no
  prefix at all. Errors the library returns to Go programs are unchanged.

### Documentation

- `RELEASING.md` says how a release is made, what it needs, and what to do
  when one fails part of the way. `make docs-check` holds every relative link
  of the documentation to the files git tracks, and every fragment to a
  heading, as a clean checkout has them.
- The README opens with a quick start, lists the exit codes and every
  variable tls-forge reads in one place, says it reads no `HTTP_PROXY` or
  `HTTPS_PROXY`, and ends with troubleshooting. The examples of `--repeat` and
  `--trace` say what a run's later requests do: each goes out on a connection
  of its own and resumes the first one's TLS session, and
  `--reuse-connection` keeps the connection instead. They said the
  connection was kept.
- The release history is restored from the tags: 0.2.0, 0.2.1 and 0.2.2 are
  listed with what each shipped, and 0.1.0 with what its tag held and the day
  it was tagged.
- The README is in the order it is read: a quick start, how to install, what
  a TLS fingerprint is, then recipes, one task each (a list of URLs, a proxy
  given as `--proxy-env TLSFORGE_PROXY`, cookies kept across runs, retrying,
  a page's requests, checking the page, and keeping, tracing, logging and
  reporting a run), then the reference of every command and library,
  troubleshooting, limitations and development. Every heading kept its name,
  so a link to one still leads there.

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
