# Profile-owned network behavior

## Engine/profile compatibility (1.0.0)

The compiled engine version is **1.0.0**, independently of the browser build and
profile format **schema 4**. Every executable profile must declare the exact,
non-negative integer `engine_major: 1`. Engines reject profiles from both older
and newer majors, including files with no declaration. Schema, filename, browser
name, User-Agent and catalogue fallback cannot supply compatibility implicitly.
The check runs before request-related DNS, proxy, TCP, TLS or QUIC I/O.

```json
{"schema": 4, "engine_major": 1, "name": "my-browser"}
```

This illustrates metadata only; a complete profile still needs captured TLS/HTTP
data and the explicit `behavior` object. Browser values and selections stay in
JSON. Major selection is anchored to the latest published stable release:
`latest_released_major + 1` for an engine change, once for the whole next release.
The current candidate is **unreleased1.0.0** after0.2.2. Further runtime changes
before1.0.0 is published stay in major1; after publication, the next engine change
targets2.0.0. Existing primitives can be configured by JSON without an engine bump. Versioned CLI, daemon and SDK identity
must agree; `engine/version.json` is the compiled authority. Release builds refuse
a different version stamp. Go v1 uses the unsuffixed module path; `/v2` starts with major2. The release anchor and pending status are recorded in `engine/version.json`.

`profile.Load` is the execution loader. `profile.Inspect` reads an archive offline
without declaring it compatible. `Save` and `Clone` preserve the original
`engine_major`, including absence; they never retag an old profile. Explicit
migration creates a candidate while preserving original capture provenance:

```go
old, err := profile.Inspect(originalJSON) // offline; handle err
candidate, err := old.Migrate("my-browser-engine-1") // handle err
migratedJSON, err := candidate.Save() // save to a separate destination
```

Preserve the original file. Migration is not browser equivalence acceptance;
repeat the relevant actual browser/wire checks before relying on its behavior.
The 15 shipped profiles and all backend catalogue policies have explicit unreleased engine-1
migration provenance; older captured browser builds are not new measurements.
A bare catalogue preset still supplies no browser headers.

For a new programmatically created Go profile, explicitly set
`EngineMajor: profile.Major(tlsforge.EngineMajor())`. Never use this assignment to
silently accept an imported file. `tlsforge.Version()` and `tlsforge.EngineMajor()`
report the compiled identity. Client constructors, transport adapters, the
registry and `Fresh` enforce it; client/profile clones own their major value.

Daemon protocol **3** reports `engine_major` and `version` on `hello`. Every
request and proxy `init` line must carry `engine_major: 1`; missing or mismatched
metadata is rejected before client execution. Offline `hello` can omit the field.
Node/Python validate the actual daemon identity before every first request,
including plain requests, and revalidate a replacement process. An old executable
from PATH is rejected rather than used silently. Update the SDK and binary
together; no compatibility flag disables the gate.



Schema 3 keeps browser-specific network choices in the same JSON file as the captured ClientHello, ordered HTTP/2 settings, headers and HTTP/1 layout. The engine implements primitives and enforces capability/cryptographic/resource constraints. Profile names, versions and descriptive User-Agent text do not select policy.

## Updating a browser

1. Copy the complete shipped profile to a local JSON file.
2. Change the measured values or select an already implemented primitive in `behavior`. Preserve capture provenance; a TCP capture alone does not establish QUIC or session behavior.
3. Load it through `--profile /absolute/path/browser.json` or `profile.Load` + `WithProfileValue`. New clients read the file; an existing client retains its owned snapshot.
4. Run the relevant paired browser/wire acceptance. Passing schema validation does not establish browser equivalence.

Editing a local file requires no binary rebuild. Embedding a different default in a distributed binary requires rebuilding that distribution. This is initialization-time loading, not live mutation of pooled connections.

## Generation rules, not frozen observations

A profile describes a browser's rules under a declared request, machine and
connection context. A captured value is not automatically a reusable constant.
Separate scoped invariants, request-derived values, generated values, evolving
connection/session state, environment-dependent observations and unknowns.

Keep supported rules and their parameters in JSON. For example,
`per_connection.shuffles_extensions` selects fresh ordering and
`per_connection.ech_payload_lengths` specifies candidate lengths, not one captured
payload. Cryptographic generation remains an engine mechanism. QPACK diagnostics
use `{stream_id}` in a JSON template; the engine substitutes the actual stream.
Stream IDs, compression tables, tickets and cookies follow their current context;
they must not be copied from an earlier request or reset to imitate its bytes.

Use several real Chrome connections, independent contexts and repeated requests
on the same connection. Measure cold/reused/resumed states separately. Check
dynamic fields for protocol validity, freshness where required, relationships and
evidenced browser generation rules rather than equality of unrelated random
bytes. Legal GREASE repetition is not a failure. A small unchanged cohort is not
proof that a field is constant, and RFC-valid output alone does not prove Chrome
fidelity. Preserve originals and list every normalization explicitly.

The shared method is kept in the separate collector project at
`../net-fp-server/docs/DYNAMIC_COMPARISON_POLICY.md`, relative to this repository
root. It defines the sampling protocol, per-layer classification and evidence
limits.

## Compatibility and boundaries

HTTP/3 gates request streams on the completion of its local control-stream
initialization. This is an engine ordering invariant, with no profile opt-out.
It queues local SETTINGS before request HEADERS, including 0-RTT and direct
request streams, without waiting for peer SETTINGS or an acknowledgement. The
SETTINGS values/order and priority/GREASE contents still come from the profile.

Schema 0-2 retains its historical family inference during migration. `Save` materializes `per_connection` and the complete effective policy into schema 4, without mutating the source object. The two JSON templates in `utls/behavior` preserve old default behavior; explicit schema 3 data takes precedence, even for a file called `chrome`. Bare transport-catalogue presets remain legacy backend presets and are not newly measured complete profiles.

Existing shipped TLS capture bytes, ordered settings, header values, machine data and original provenance are preserved. Added behavior sections materialize the pre-existing runtime policy, including the newer policy previously applied to older Chromium profiles; this is not fresh acceptance of Chrome 151-154.

Unknown keys, duplicate behavior keys, null or wrong types, invalid ranges and unsupported algorithm names are errors. H3 ALPS, ORIGIN/coalescing and cross-version profile negotiation remain unavailable; they must not be advertised through arbitrary data. Missing-API catalogue scenarios remain open.

Certificate verification, authenticated Finished processing, nonce safety, protocol wire encodings, fresh keys/randomness, parser/state-machine mechanisms and safe finite resource bounds remain engine responsibilities. New algorithms/protocol features require engine code; existing parameter/ordering/timer changes require only profile data. A profile cannot replace the host kernel TCP stack. Explicit caller transport options retain their documented override precedence.

The shared policy registry in `github.com/igor-lemon/utls/behavior` contains supported keys/types and engine bounds. Browser values live in profile JSON. Dependencies currently resolve to the four local forks through `go.work`; no publication of those APIs is implied.

## Field reference

Dotted keys are literal JSON object keys. Durations include their units in the key. Core resource, decoder, redirect and authentication fields are required in schema 3; use a complete profile rather than an empty object. Omitted optional fields disable their override; preserve the complete measured profile when editing. `@hints` and `@alps-hints` are ordered expansion slots, not literal HTTP fields. HTTP/2 settings/pseudo headers/navigation priority remain in `http2`; per-connection ECH length draws and TLS extension shuffling remain in `per_connection`.

The values below are the migrated macOS 155 profile policy, not a standards-wide requirement or proof of a full Chrome fingerprint match.

| Field | JSON value |
|---|---|
| `cache.entries` | `256` |
| `cache.entry_bytes` | `8388608` |
| `cache.total_bytes` | `67108864` |
| `cookie.ip_domain_host_only` | `true` |
| `cookie.lax_unsafe_age_seconds` | `120` |
| `cookie.max_age_seconds` | `34560000` |
| `cookie.max_attribute_bytes` | `1024` |
| `cookie.max_pair_bytes` | `4096` |
| `cookie.raw_fields` | `true` |
| `cookie.reset_order_on_value_change` | `true` |
| `h1.auth_body` | `"read-all"` |
| `h1.dropped_body` | `"drain"` |
| `h1.idle_connection_timeout_ms` | `300000` |
| `h1.idle_reap` | `"on-request"` |
| `h1.max_connections` | `6` |
| `h1.max_idle_connections` | `6` |
| `h1.merged_head_body_bytes` | `1400` |
| `h1.missing_status` | `200` |
| `h1.preflight_body` | `"first-bytes"` |
| `h1.preserve_framing_fields` | `true` |
| `h1.request_timeout_resend` | `true` |
| `h1.response_header_bytes` | `262144` |
| `h1.restart_body` | `"close"` |
| `h1.unread_grace_us` | `2000` |
| `h2.allow_huffman_expansion` | `true` |
| `h2.alps_settings` | `[1,3,4,8,9]` |
| `h2.auth_body` | `"close"` |
| `h2.close_on_goaway` | `true` |
| `h2.connection_window_overflow_error` | `1` |
| `h2.data_frame_payload` | `16375` |
| `h2.dropped_body` | `"close"` |
| `h2.encoder_table_bytes` | `4294967295` |
| `h2.enforce_advertised_frame_limit` | `true` |
| `h2.header_frame_payload` | `16374` |
| `h2.hpack_first_static_name` | `true` |
| `h2.hpack_index_oversized` | `true` |
| `h2.hpack_indexed_exceptions` | `[":authority"]` |
| `h2.hpack_unindexed_prefixes` | `[":"]` |
| `h2.idle_connection_timeout_ms` | `0` |
| `h2.preflight_body` | `"first-bytes"` |
| `h2.preface_ping_failed_goaway_code` | `1` |
| `h2.preface_ping_failed_goaway_debug` | `"Failed ping."` |
| `h2.preface_ping_first_id` | `1` |
| `h2.preface_ping_hung_ms` | `10000` |
| `h2.preface_ping_idle_ms` | `10000` |
| `h2.priority_dependency` | `"nearest-weight"` |
| `h2.reject_unsolicited_ping_ack` | `true` |
| `h2.reset_data_before_headers` | `true` |
| `h2.restart_body` | `"close"` |
| `h2.retries` | `2` |
| `h2.retry_delay_ms` | `0` |
| `h2.retry_errors` | `["refused-stream","goaway-no-error","ping-failed"]` |
| `h2.strict_max_streams` | `true` |
| `h2.tolerated_response_fields` | `["connection","keep-alive"]` |
| `h2.unread_grace_us` | `500` |
| `h2.urgency_weights` | `[255,219,182,146,109,73,36,0]` |
| `h2.window_update_delay_ms` | `5000` |
| `h2.window_update_denominator` | `2` |
| `h2.zero_window_stream_error` | `3` |
| `h3.body_copy_bytes` | `8192` |
| `h3.grease_frame_n_bits` | `32` |
| `h3.grease_frames` | `true` |
| `h3.grease_setting_n_max` | `9999999999` |
| `h3.grease_setting_n_min` | `1000000000` |
| `h3.grease_setting_nonzero` | `true` |
| `h3.grease_settings` | `true` |
| `h3.priority_frame_type` | `984832` |
| `h3.priority_value` | `"u=0, i"` |
| `h3.pseudo_header_order` | `[":method",":authority",":scheme",":path"]` |
| `h3.settings` | `[{"id":1,"value":0},{"id":6,"value":262144},{"id":7,"value":0},{"id":51,"value":1}]` |
| `headers.accept_fetch` | `"*/*"` |
| `headers.accept_preflight` | `"*/*"` |
| `headers.alps_after` | `"accept"` |
| `headers.authorization_leading` | `["host","connection","content-length","cache-control"]` |
| `headers.browser_base_fields` | `["sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform","user-agent","accept-language","accept-encoding"]` |
| `headers.browser_context` | `true` |
| `headers.client_hint_order` | `["device-memory","sec-ch-device-memory","dpr","sec-ch-dpr","viewport-width","sec-ch-viewport-width","sec-ch-viewport-height","rtt","downlink","ect","sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-full-version","sec-ch-ua-arch","sec-ch-ua-platform","sec-ch-ua-platform-version","sec-ch-ua-model","sec-ch-ua-bitness","sec-ch-ua-wow64","sec-ch-ua-full-version-list","sec-ch-ua-form-factors","sec-ch-prefers-color-scheme","sec-ch-prefers-reduced-motion","sec-ch-prefers-reduced-transparency"]` |
| `headers.cookie_after` | `"accept-language"` |
| `headers.cookie_slot` | `true` |
| `headers.default_client_hints` | `["sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform"]` |
| `headers.default_referrer_policy` | `"strict-origin-when-cross-origin"` |
| `headers.form_cache_control` | `"max-age=0"` |
| `headers.form_order` | `["content-length","pragma","cache-control","authorization","@hints","upgrade-insecure-requests","content-type","user-agent","origin","@given","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]` |
| `headers.form_reload_order` | `["content-length","pragma","cache-control","authorization","@hints","upgrade-insecure-requests","user-agent","origin","content-type","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]` |
| `headers.given_order` | `"bytes"` |
| `headers.given_redirect_drops` | `["cookie"]` |
| `headers.h1_connection_default` | `"keep-alive"` |
| `headers.h1_generated_priority` | `false` |
| `headers.h1_prefix` | `["host","connection"]` |
| `headers.navigation_fetch_user` | `"?1"` |
| `headers.navigation_order` | `["pragma","cache-control","authorization","@hints","upgrade-insecure-requests","user-agent","@given","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]` |
| `headers.preflight_order` | `["accept","access-control-request-method","access-control-request-headers","origin","user-agent","sec-fetch-mode","sec-fetch-site","sec-fetch-dest","referer","accept-encoding","accept-language","priority"]` |
| `headers.priority_fetch` | `"u=1, i"` |
| `headers.range_accept_encoding` | `"identity"` |
| `headers.range_cache_control` | `"max-age=0"` |
| `headers.redirected_hints_after` | `"sec-fetch-dest"` |
| `headers.redirected_order` | `["content-length","pragma","cache-control","authorization","upgrade-insecure-requests","content-type","user-agent","origin","@given","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","@hints","referer","accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]` |
| `headers.reload_cache_control` | `"max-age=0"` |
| `headers.renderer_default_hints` | `["sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform"]` |
| `headers.renderer_extra_fields` | `["user-agent"]` |
| `headers.renderer_hint_insertion_order` | `["device-memory","sec-ch-device-memory","rtt","downlink","ect","sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-arch","sec-ch-ua-platform","sec-ch-ua-platform-version","sec-ch-ua-model","sec-ch-ua-full-version","sec-ch-ua-full-version-list","sec-ch-ua-bitness","sec-ch-ua-wow64","sec-ch-ua-form-factors","save-data","sec-ch-prefers-reduced-transparency","sec-ch-prefers-reduced-motion","sec-ch-prefers-color-scheme","dpr","sec-ch-dpr","viewport-width","sec-ch-viewport-width","viewport-height","sec-ch-viewport-height","width","sec-ch-width"]` |
| `headers.renderer_initial_buckets` | `8` |
| `headers.renderer_load_denominator` | `2` |
| `headers.renderer_order` | `"utf16-rapidhash-quadratic-v1"` |
| `headers.renderer_origin_dests` | `["font"]` |
| `headers.restarted_order` | `["pragma","cache-control","authorization","upgrade-insecure-requests","user-agent","@given","accept","@hints","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","if-none-match","if-modified-since","priority"]` |
| `headers.script_leading` | `["content-length"]` |
| `headers.script_metadata` | `["sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-storage-access"]` |
| `headers.script_priority_exclusive` | `true` |
| `headers.script_priority_weight` | `219` |
| `headers.script_trailing` | `["referer","accept-encoding","accept-language","cookie","if-none-match","if-modified-since","range","priority"]` |
| `headers.sent_priority` | `["document=u=0, i","iframe=u=0, i","style=u=0","font=u=0","image=i","script=","empty=u=1, i"]` |
| `headers.storage_access` | `"active"` |
| `headers.untrusted_drop_codings` | `["br","zstd"]` |
| `headers.untrusted_prefixes` | `["sec-ch-","sec-fetch-"]` |
| `headers.withhold_untrusted` | `true` |
| `headers.without_context` | `"typed-navigation"` |
| `http.auth_cache_entries` | `20` |
| `http.auth_cache_paths` | `10` |
| `http.auth_scheme_order` | `["basic","digest","ntlm","negotiate"]` |
| `http.body_read_bytes` | `8192` |
| `http.connection_error_methods` | `"any"` |
| `http.connection_error_retries` | `50` |
| `http.content_codings` | `["gzip","x-gzip","deflate","br","zstd"]` |
| `http.digest_algorithms` | `["MD5","MD5-sess","SHA-256","SHA-256-sess"]` |
| `http.digest_cnonce_bytes` | `8` |
| `http.drain_bytes` | `16384` |
| `http.drain_ms` | `5000` |
| `http.first_bytes_ms` | `0` |
| `http.gzip_decoder` | `"prefix-first-member"` |
| `http.max_auth_restarts` | `32` |
| `http.max_site_pools` | `64` |
| `http.negotiate_auth` | `false` |
| `http.preflight_default_age_seconds` | `5` |
| `http.preflight_max_age_seconds` | `7200` |
| `http.redirects_fetch` | `20` |
| `http.redirects_navigation` | `19` |
| `http.zstd_window_bytes` | `8388608` |
| `proxy.connect_header_order` | `["user-agent","proxy-connection"]` |
| `proxy.connect_priority_exclusive` | `true` |
| `proxy.connect_priority_weight` | `146` |
| `proxy.connect_pseudo_order` | `[":method",":authority"]` |
| `proxy.connection_value` | `"keep-alive"` |
| `proxy.forward_http` | `true` |
| `proxy.idle_timeout_ms` | `90000` |
| `proxy.profile_tls` | `true` |
| `proxy.tls_cache_entries` | `32` |
| `quic.accept_zero_available_version` | `true` |
| `quic.ack_timer_ms` | `24` |
| `quic.active_cid_limit` | `2` |
| `quic.alpn` | `["h3"]` |
| `quic.connection_receive_window` | `15728640` |
| `quic.datagrams` | `true` |
| `quic.dedicated_socket` | `true` |
| `quic.enabled` | `true` |
| `quic.grease_parameter_id_bits` | `62` |
| `quic.grease_version` | `true` |
| `quic.idle_timeout_ms` | `30000` |
| `quic.ignore_vn_after_retry` | `true` |
| `quic.ignore_vn_wrong_cids` | `true` |
| `quic.incoming_bidi_streams` | `100` |
| `quic.incoming_uni_streams` | `103` |
| `quic.initial_dcid_bytes` | `8` |
| `quic.initial_packet_bytes` | `1250` |
| `quic.max_ack_delay_ms` | `25` |
| `quic.max_datagram_frame` | `65536` |
| `quic.max_udp_payload` | `1472` |
| `quic.preserve_extensions` | `[0,65037,27,45,51764,10,13,51,16,43,41]` |
| `quic.remove_grease_groups` | `true` |
| `quic.shuffle_extensions` | `true` |
| `quic.shuffle_parameters` | `true` |
| `quic.source_cid_bytes` | `0` |
| `quic.stream_receive_window` | `6291456` |
| `quic.tls_cipher_suites` | `[4865,4866,4867]` |
| `quic.tls_signature_algorithms` | `[1027,2052,1025,1283,2053,1281,2054,1537,513]` |
| `quic.tls_versions` | `[772]` |
| `quic.version_information` | `true` |
| `quic.version_mismatch_error` | `10` |
| `quic.version_parse_error` | `10` |
| `quic.versions` | `[1]` |
| `tcp.keepalive` | `true` |
| `tcp.keepalive_count` | `0` |
| `tcp.keepalive_idle_seconds` | `45` |
| `tcp.keepalive_interval_seconds` | `0` |
| `tls.alpn_mismatch_alert` | `47` |
| `tls.certificate_decode_alert` | `50` |
| `tls.close_notify` | `false` |
| `tls.defer_key_update` | `true` |
| `tls.duplicate_extension_alert` | `47` |
| `tls.false_start` | `true` |
| `tls.full_size_records` | `true` |
| `tls.handshake_retries` | `1` |
| `tls.malformed_extension_alert` | `50` |
| `tls.preserve_sni_trailing_dot` | `true` |
| `tls.resumption` | `true` |
| `tls.retry_local_alerts` | `[10,50,51,110]` |
| `tls.single_use_tickets` | `true` |
| `tls.ticket_age_quantum_ms` | `1000` |
| `tls.trust_anchor_order` | `"captured"` |
| `tls.unsolicited_extension_alert` | `110` |
| `tls.validate_encrypted_extensions` | `true` |
| `url.blocked_ports` | `[0,1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,137,139,143,161,179,389,427,465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,989,990,993,995,1719,1720,1723,2049,3659,4045,5060,5061,6000,6566,6665,6666,6667,6668,6669,6697,10080]` |

## Acceptance checks

`profile/behavior_test.go` checks strict parsing, migration, cloning, name independence and adapter propagation. `profile_policy_test.go` changes only JSON files and observes actual TLS retry attempts, ordered H1/H2 request fields, H2 frame cuts, response-head boundaries, redirects, cookies/cache and first QUIC CID lengths. Existing wire/browser-fixture regression suites remain enabled. Fresh paired Chrome comparisons and their exact source/evidence hashes belong in the separate net-fp-server knowledge ledger.

Capture helper hint lists snapshot the process default once; request generation uses each client's explicit profile. This avoids rescanning the registry on every header. Restart a long-lived capture-helper process after changing its default profile.

Raw `WithTransportOption(WithClientProfile(...))` overrides are refused before transport creation; use `WithProfile` or `WithProfileValue` with explicit `engine_major`.

> Release-number correction (2026-10-23): current engine is unreleased1.0.0.
> The engine2..engine7 labels in historical mechanism notes below identify
> internal experiments, never published releases. All those mechanisms belong
> to the same pending v1. Future development before publication retains major1.
> Original measurement archives and their labels are preserved.

## HTTP/3 QPACK (unreleased engine 1)

Engine6 implements RFC9204 dynamic tables in both directions, all field-line
representations, encoder instructions, Required Insert Count reconstruction,
blocked sections, section acknowledgments, cancellation and decoder feedback.
Critical-stream errors close the connection. Table allocation, integer overflow,
queue bounds and reference lifetimes are engine invariants.

All selectable behavior belongs in profile JSON:

| Key | Values / meaning |
| --- | --- |
| `h3.settings` | Ordered settings, including decoder capacity1 and blocked streams7. Hard safety bounds are1MiB and1024; Chrome155/macOS declares65536/100. |
| `h3.qpack.huffman_names`, `h3.qpack.huffman_values` | `always`, `shorter`, `never`; `shorter` is strict, ties literal. |
| `h3.qpack.encoder_strategy` | `disabled` (static), `reuse` (insert literals for later reuse), `insert` (also reference new insertions when peer blocked credit allows). |
| `h3.qpack.encoder_table_bytes` | Local encoder budget, capped by peer decoder capacity and the hard1MiB bound; Chrome155/macOS65536. RIC wrapping still uses the full peer maximum. |
| `h3.qpack.encoder_warmup_sections` | Initial field sections encoded without table inserts/references. Chrome155/macOS1, explicit compatibility candidates0. |
| `h3.qpack.reference_base` | `required` or `insert-count` selects the field-section Base. |
| `h3.qpack.never_index` | Exact lower-case field names excluded from dynamic insertion/reference. |
| `h3.qpack.decoder_feedback` | `on-insert` increments plus section ACKs, or `on-section` ACKs. |
| `h3.qpack.streams` | `lazy`, `eager` or `deferred` local critical-stream lifecycle. Chrome155/macOS selects `deferred`. |
| `h3.qpack.stream_order` | Exactly `[2,3]` or `[3,2]`. Chrome155/macOS uses decoder-first `[3,2]`. |

A peer's decoder capacity and blocked budget are respected independently of our
advertised response-decoder limits. Before peer SETTINGS, the request encoder
uses capacity0; requests do not wait for peer SETTINGS. References pin entries
until section ACK/cancellation; new blocked references cannot exceed peer credit.
Instruction writes use bounded queues so HTTP/table locks never wait for QUIC
flow control. Queue exhaustion closes the connection rather than losing feedback.

The Chrome155/macOS profile selects `insert`, warmup1, `required`, `shorter`,
`on-section` and eager decoder-first streams. These are finite observed choices,
not universal RFC requirements or a claim about all Chrome workloads. Other14
profile candidates retain disabled request indexing and their old string coding
until measured; all15 have a real TLS/H2 smoke, not fresh old-browser acceptance.
Original engine2 profiles remain in the immutable r17 source archive.

Unreleased engine1.0.0 uses Go module `github.com/Sec-CH-Lemon/tls-forge` and Node/Python1.0.0.
Both cross-major execution directions are rejected. Schema4 and daemon protocol3
are unchanged. Offline Inspect/Save preserve old identity; explicit Migrate
creates a separately named candidate using JSON migration additions.

## QPACK small tables and error replay (unreleased engine 1)

| Key | Meaning / Chrome155 macOS measured value |
| --- | --- |
| `h3.qpack.draining_percent` | Capacity percentage reserved for draining old entries, 0..100; Chrome25. The index is computed once per section. Old exact matches may be duplicated without evicting their source; acknowledgments and live references still pin entries. |
| `h3.qpack.critical_close_space` | `application` or `transport`; Chrome transport for peer QPACK FIN/reset. |
| `h3.qpack.critical_close_code` | Exact close code; Chrome10 (QUIC PROTOCOL_VIOLATION). Application260 is a different error. |
| `h3.qpack.critical_close_frame_type` | Transport triggering frame field; Chrome15 in the measured FIN case. |
| `h3.qpack.critical_close_reason` | UTF-8 wire diagnostic, bounded1024 bytes; Chrome `17:Attempt to close a static stream`. |
| `h3.retry_unprocessed_attempts` | Total attempts for provably unprocessed H3_REQUEST_REJECTED/unopened streams, 1..16; retained compatibility value2. Separate from protocol-error replay. |
| `h3.retry_attempts` | Maximum total protocol-error attempts, 1..16; Chrome3. |
| `h3.retry_methods` | Explicit method allowlist; Chrome candidate `["GET","HEAD"]`. Independently, the engine rejects non-idempotent protocol replay. |
| `h3.retry_application_errors` | Exact application-space codes; Chrome candidate512/513/514. |
| `h3.retry_transport_errors` | Exact transport-space codes; Chrome candidate10. Application10 cannot match this selector. |

Retries apply only while waiting for response headers, require a live request
context and a nil/NoBody or successful GetBody replay. Body-read errors after
response delivery are never replayed. The retained JSON-selected retry budget for provably
unprocessed H3_REQUEST_REJECTED/unopened streams remains separate from this
profile-selected protocol-error policy. No fallback to another protocol is
introduced. Every new key is mandatory in current explicit profiles; migration
defaults are data in engine-migration.json. Other14 profiles keep draining0 and
protocol retries1 with no selected errors, pending their own measurements.

The small-table/critical-close mechanisms were introduced before engine6 and remain supported. Original engine3 profiles
are retained in the immutable dynamic-qpack-20261022-r18 archive. Schema4 and
daemon protocol3 remain unchanged; exact SDK/profile engine major1 is required.

## QPACK diagnostic policy (unreleased engine 1)

Nine current-profile keys select wire CONNECTION_CLOSE reason text. Every key
is required;all are UTF-8 strings limited to1024 bytes. Missing/null/unknown or
malformed fields are rejected before request DNS/socket activity.

| Key under `h3.qpack.` | Scope | Chrome155/macOS value |
| --- | --- | --- |
| `error_invalid_relative_index_reason` | Relative dynamic index underflow;not a static/post-base/RIC error | `126:Error decoding headers on stream {stream_id}: Invalid relative index.` |
| `error_capacity_exceeded_reason` | Encoder capacity above advertised maximum | `185:Encoder stream error: Error updating dynamic table capacity.` |
| `error_zero_increment_reason` | Decoder Insert Count Increment exactly0;not nonzero overflow | `187:Decoder stream error: Invalid increment value 0.` |
| `error_decompression_reason` | Other field-section decompression failures | `{detail}` |
| `error_encoder_reason` | Other encoder-stream syntax failures | `invalid or closed QPACK critical stream` |
| `error_decoder_reason` | Other decoder-stream failures | `invalid or closed QPACK critical stream` |
| `error_stream_unavailable_reason` | Local instruction stream cannot open | `QPACK stream unavailable` |
| `error_stream_write_reason` | Local instruction stream write failure | `QPACK stream write failed` |
| `error_queue_exhausted_reason` | Bounded local instruction queue exhausted | `QPACK instruction queue exhausted` |

`{stream_id}` is the actual failing request stream ID and is allowed only in
relative-index/decompression templates. `{detail}` is the preserved local error
text. All other placeholders/braces are rejected;there is no executable code,
format-string evaluation or arbitrary data access. Expanded diagnostics retain
a hard1024-byte UTF-8 bound. Empty reasons are allowed as an explicit choice.

Parser classification, RFC error space/code, reference validation and local error
causes remain engine mechanisms. Changing the wire message never turns invalid
data into success or changes retry/replay permissions. Current Chrome acceptance
for the first three classes is measured separately. Generic fallback/local-write
messages preserve the earlier policy;they are not a claim about every Chrome
error. Other14 profiles retain earlier diagnostic text pending browser witnesses.

The diagnostic mechanism was introduced in internal snapshot5. Unreleased engine1 retains
the diagnostic templates and uses the unsuffixed Go module,Node/Python1.0.0. Schema4 and daemon
protocol3 remain unchanged. Original engine5 profiles are preserved in the
dynamic-series-20261023-r21 pre-fix source archive.


## QPACK stream lifecycle (unreleased engine 1)

`h3.qpack.streams` selects an implemented generic lifecycle:

| Choice | Stream IDs | First bytes |
| --- | --- | --- |
| `eager` | Reserved in `h3.qpack.stream_order` during local setup | Type prefixes are sent immediately. |
| `lazy` | Allocated when each writer first has an instruction | Prefix and instructions are sent on demand; allocation follows demand. |
| `deferred` | Reserved in `h3.qpack.stream_order` during local setup | No stream bytes are sent until that writer has an instruction. |

The current Chrome155/macOS candidate selects `deferred` and `[3,2]` in JSON.
With control stream2 this reserves decoder6/encoder10 while a static-only cold
exchange exposes neither prefix. A later encoder instruction or decoder feedback
activates its own stream without changing the reserved identity. Other profiles
keep their previous lifecycle choices pending separate browser measurement.

The same measured profile excludes `authorization`, `proxy-authorization` and
`set-cookie` from QPACK insertion/reference. It allows `cookie`: repeated
controlled cookie updates in Chrome use the dynamic table. The earlier blanket
cookie exclusion preserved values but produced different compressed sections.
This correction uses the existing JSON primitive; it requires no extra engine
change. Other profiles retain their own explicit policies.

Reservation and first-write synchronization are engine primitives. A writer may
queue feedback while setup finishes; only its I/O goroutine waits for reservation,
without holding a table lock. Cancellation/connection failure terminates that
wait. Existing bounded queues, protocol errors and JSON-owned diagnostics remain.
The deferred-QPACK primitive was introduced by engine5→6. Original engine5 files remain
archived; all15 new candidates explicitly pin6. Metadata migration alone does
not transfer browser acceptance to another profile or platform.


## HTTP/3 dynamic control stream (unreleased engine 1)

The current Chrome155/macOS candidate owns these rules in JSON:

| Profile key | Selection | Runtime meaning |
| --- | --- | --- |
| `h3.control_order` | `["settings","grease"]` | Initial control components in wire order. SETTINGS is required first. |
| `h3.grease_payload_lengths` | `[0,1,2,3]` | For frame type `31*N+33`, select length at `N mod vector_length`, then generate fresh random payload bytes. |
| `h3.priority_updates` | `"per-request"` | Emit PRIORITY_UPDATE for each actual request stream, including reused connections. |
| `h3.priority_source` | `"header"` | Use the current request's Priority field, falling back to JSON `h3.priority_value`. |

`initial` priority mode retains the historical single initial update; `disabled`
omits updates. `profile` priority source uses the JSON fallback for every update.
Initial mode requires `priority` in the control order; per-request/disabled modes
exclude it. Other explicitly migrated profiles/catalogue templates preserve their
prior initial-mode policy and empty GREASE payload through `[0]` until measured.
No captured random bytes, stream IDs, request priorities or cookies are replayed.

The writer applies to RoundTrip and OpenRequestStream/SendRequestHeader. Control
writes serialize outside QPACK/header locks. Request cancellation stops the caller's
wait without resetting a critical stream; at most one bounded frame write remains
in flight, and connection shutdown terminates it. Protocol ordering, cryptographic
random generation, synchronization and hard resource ceilings are engine mechanisms.
Those H3 mechanisms were introduced in internal snapshot6 and remain part of the same unreleased engine1.

Repeated original-wire measurements and scope/negative controls are maintained in
`../net-fp-server/docs/DYNAMIC_FIELDS_2026-10-23.md`. RFC-valid random lengths alone
are insufficient: the measured N/length relationship and lifecycle must also hold.


## Initial HTTP/2 input scheduling (unreleased engine 1)

`h2.read_loop_start` is required in every current explicit profile and selects
one generic initial connection policy:

| JSON choice | Reader starts |
| --- | --- |
| `connection` | During connection setup, retaining the previous concurrent behavior. |
| `first-headers` | After the first request's complete HEADERS/CONTINUATION write, before body/response waits. |

The measured Chrome155/macOS candidate selects `first-headers`. This prevents
already-buffered peer SETTINGS from changing the first request's HPACK block or
sending an ACK ahead of it. Subsequent SETTINGS apply normally: the encoder still
shrinks to0/128, grows to4096/65536 or the current allowed peer maximum, preserves
intervening minima, evicts entries and emits required table-size updates. Never
replace this ordering policy with a permanent4096encoder cap or a fixed block.

ALPS is interpreted before the first request as before. If ALPS leaves a request
waiting for a stream slot, the reader starts so later peer SETTINGS can unblock
it. Explicit PING/Shutdown operations also require input without a request.
Close and idle close start/terminate the single reader for normal cleanup.
There is no timing sleep or arbitrary wall-clock grace in the runtime mechanism.
Other14 profile candidates and catalogue/legacy/migration policies explicitly
retain `connection` until measured for their own browser/platform.

This generic scheduling mechanism is part of the same unreleased engine1; Go uses the unsuffixed module, CLI/SDK1.0.0 and profiles engine_major1 agree. Original engine6 files/binary/source are
preserved in the immutable `hpack-20261023-r22` before-build archive. Profile
migration alone is not browser acceptance. The scoped repeated Chrome results
are maintained in `../net-fp-server/docs/HPACK_STARTUP_2026-10-23.md`.


## Request body presence and Content-Length

The current unreleased engine remains1.0.0/engine_major1. These mandatory JSON
choices replace the transports' old hardcoded zero-length method list:

| Key | Meaning / Chrome155 macOS choice |
| --- | --- |
| `http.zero_content_length_methods` | Exact method tokens that emit0 when no body exists; `["POST","PUT"]`. |
| `http.content_length_empty_body` | Emit a derived zero length for an explicit empty upload; `true`. |
| `h1.zero_length_identity` | Retain the old raw H1 identity-transfer fallback; Chrome profile `false`. |
| `h1.zero_length_identity_excluded_methods` | Methods excluded from that compatibility fallback; `["GET","HEAD"]`. |

These are selectors, not a length template. Positive lengths come from actual
bytes; unknown-length streams never get a fabricated numeric length. Empty
selector lists are valid, duplicate/invalid method tokens and wrong types are
rejected. Profile names and browser versions do not dispatch the mechanism.
Legacy/canonical catalogue and other14 profile data retain their prior
POST/PUT/PATCH zero-method selection and disabled explicit-empty override.

The Go request body distinguishes nil from a non-nil empty slice. The daemon
preserves absent/null versus an explicitly empty body field. Node/Python already
serialize that distinction. CLI omits a body unless -d is provided; -d "" is an
explicit empty upload. This preservation applies to redirects and retry copies,
while transitions that remove the upload must keep it absent. Fetch GET/HEAD
refuses any explicitly provided body before origin contact. Raw fhttp header
overrides retain their separately tested contract.

No version is incremented for another change within this unpublished major1.
Historical profiles/captures keep their original bytes; JSON migration is explicit
and is not fresh old-browser acceptance. Actual minimized Chrome series and
complete packet/HPACK/QPACK witnesses determine the bounded parity result.


## Connection lifecycle (unreleased engine 1)

How a connection is kept and let go of over time is profile data too: what a
one-request comparison never sees, and what a server that keeps a connection
open sees on every one. Absent fields keep the engine's earlier behaviour
(Go's 15 s keep-alive, close_notify, one idle timeout for both protocols, a
connection kept after a GOAWAY until its server closes it); the 15 shipped
Chrome profiles say Chrome's, and catalogue, legacy and migration policies
keep the earlier behaviour until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `tcp.keepalive` | Whether the system probes an idle TCP connection (SO_KEEPALIVE); `true` (Chrome sets it on every connection but on Android and iOS). |
| `tcp.keepalive_idle_seconds` | Idle time before the first probe, 0 the system's; `45` (`kTCPKeepAliveSeconds`, TCPSocketPosix::SetDefaultOptionsForClient). At most 32767. |
| `tcp.keepalive_interval_seconds` | Between unanswered probes, 0 the system's; Linux and Windows `45`, macOS `0` (Chrome sets TCP_KEEPALIVE alone there: the system's 75 s). At most 32767. |
| `tcp.keepalive_count` | Unanswered probes before the connection is dropped, 0 the system's; `0`. At most 127. |
| `tls.close_notify` | Whether closing a connection sends a TLS close_notify alert first; `false`: Chrome's SSLClientSocketImpl::Disconnect calls no SSL_shutdown, so a connection ends with the TCP FIN alone, also when the server's close_notify came first. `CloseWrite` keeps its alert. |
| `h1.idle_connection_timeout_ms` | How long an idle HTTP/1.1 connection is kept; `300000` (`g_used_idle_socket_timeout_s`). Without it, `http.idle_connection_timeout_ms` applies. |
| `h1.idle_reap` | `timer` closes a connection when it has been idle that long; `on-request` closes it only when the client next asks for a connection, to any host, as Chromium's socket pool cleans up its idle sockets in RequestSocket (`CleanupIdleSockets`) and never by itself; Chrome `on-request`. |
| `h2.idle_connection_timeout_ms` | How long an idle HTTP/2 connection is kept, 0 never; `0`: a SpdySession has no idle timer and is kept until its server closes it. Without it, `http.idle_connection_timeout_ms` applies. |
| `h2.close_on_goaway` | Close a connection as soon as a GOAWAY leaves it no stream, or its last stream ends after one, with no GOAWAY of the client's; `true` (SpdySession::MaybeFinishGoingAway). |

`tcp.keepalive_*` need `tcp.keepalive`, and with it false they must be 0;
`h1.idle_reap` needs `h1.idle_connection_timeout_ms`. A profile applies its
keep-alive on whatever system the client runs on: the TCP stack stays that
machine's.

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-23, `../net-fp-server/captures/review-20261023/`): the first probe
45.0 s after the last packet in four runs, every close without a client
alert, an idle HTTP/2 connection kept 100 s, an idle HTTP/1.1
connection reused after 100 s, and a GOAWAY'd connection closed the
millisecond its stream ended. Linux and Windows values come from Chromium's
source (`tcp_socket_posix.cc`, `tcp_socket_win.cc`), not from a measurement.
Not covered yet: Chrome's silence when a server closes an idle HTTP/1.1
connection (Chrome closes it only at its next pool cleanup; tls-forge's
reader sees the close at once and ends the connection with a FIN). Chrome's
PING on a connection idle for long is the next section.

Tests: `TestEveryConnectionIsProbedAsTheProfilesBrowserProbesIt` reads the
socket options of a request's connection; `TestAKeepAliveIsWhatTheProfileSays`;
`TestAChromeProfileClosesItsConnectionsWithoutCloseNotify`,
`TestAChromeProfileClosesASessionGoingAwayAtOnce`,
`TestAChromeProfileKeepsAnIdleHTTP2ConnectionOpen` and
`TestAChromeProfileReapsIdleHTTP1ConnectionsWhenItAsksForOne` change only JSON
and watch the server's side; `TestConnectionLifecyclePolicyIsTypedAndCoherent`
and `TestEveryShippedChromeProfileKeepsItsConnectionsAsChrome` hold the data.
The forks: utls `TestCloseSendsCloseNotifyAsThePolicySays`, fhttp
`TestASessionGoingAwayIsClosedOnceItHasNoStream` and
`TestIdleConnReapOnRequestClosesOnlyWhenAConnectionIsAskedFor`, tls-client
`TestTheTransportsKeepIdleConnectionsAsTheirOptionsSay`.


## The connection's own PING (unreleased engine 1)

Chrome tells a dead HTTP/2 connection from a quiet one by a PING of its own
(SpdySession::MaybeSendPrefacePing, WritePingFrame, CheckPingStatus): when it
writes a request's HEADERS, or a DATA frame that carries any of a body, to a
connection that has read nothing for longer than 10 s, a PING goes with it,
after the HEADERS and before the DATA, each in a TLS record of its own. A
server sees it on every request that comes after a pause, so the shipped
Chrome profiles do the same. Absent fields keep the engine's earlier
behaviour, no PING; catalogue, legacy and migration policies keep it until
measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `h2.preface_ping_idle_ms` | Read nothing for longer than this and the connection pings with its next HEADERS or DATA; 0 never; `10000` (`kSpdyDefaultConnectionAtRiskOfLossSeconds`). |
| `h2.preface_ping_first_id` | The eight bytes of the connection's first PING, a big-endian count, one more for each after; `1` (`next_ping_id_`). Required with a nonzero `h2.preface_ping_idle_ms`. |
| `h2.preface_ping_hung_ms` | How long a PING may go unanswered with nothing read before the connection is given up, 0 never; `10000` (`kHungIntervalSeconds`). A read after the PING, its answer aside, puts it off until nothing has been read for that long. |
| `h2.preface_ping_failed_goaway_code` | The GOAWAY a connection given up says before it closes (last stream 0), absent none; `1`, PROTOCOL_ERROR (`MapNetErrorToGoAwayStatus` of ERR_HTTP2_PING_FAILED). |
| `h2.preface_ping_failed_goaway_debug` | That GOAWAY's debug data; `"Failed ping."`. At most 1024 bytes. |

A request without an answer yet whose connection is given up goes again on
another as `h2.retry_errors` (`ping-failed`) and `h2.retries` say, below
(«Requests sent again»).

No other PING goes while one is unanswered, nor while the check of one is
pending (`h2.preface_ping_hung_ms` after it, answered or not), as Chrome's.
Any acknowledgement answers the connection's PING, whatever it says; one that
answers nothing is still the connection error
`h2.reject_unsolicited_ping_ack` makes it. A connection given up fails its
streams first, then says its GOAWAY and closes, so that a request may go
again on another connection while the GOAWAY is written, as Chrome's
session ends its streams before its write loop writes the GOAWAY. A write
the dead connection holds up gives up within `h2.preface_ping_hung_ms`.

`h2.preface_ping_first_id` and `h2.preface_ping_hung_ms` need
`h2.preface_ping_idle_ms`; `h2.preface_ping_failed_goaway_code` needs
`h2.preface_ping_hung_ms`;
`h2.preface_ping_failed_goaway_debug` needs the code. The same applies on an
HTTPS proxy's HTTP/2 connection, which takes the profile's policy, and to a
tunnel's DATA through it.

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-23, `../net-fp-server/captures/review-20261023/`): after 15 s and 50 s
of nothing read, the next request's HEADERS and then a PING saying 1, then 2,
records of their own in the same millisecond, the PING acknowledged; a PING
left unanswered with nothing read: GOAWAY PROTOCOL_ERROR "Failed ping." 10.01 s
after it, the FIN in the same millisecond, and the request again on a new
connection (its SYN 70 µs before the GOAWAY), answered there with no PING.
A `fetch()` streaming its body (`duplex: "half"`), its second byte 15 s after
its first: PING 1, then that DATA and the empty DATA that ends the stream,
each a record of its own. Chromium's source agrees and says 151 to 155 alike;
Linux and Windows are not measured. tls-forge with these values on the same
bench (`ping-1`, `ping-hang`): the same records, 1 then 2, 70 and 144 µs
after the HEADERS (Chrome's 25 to 35), and the same GOAWAY 10.001 s after an
unanswered PING, the request again on a new connection; its SYN went 1.5 ms
after the GOAWAY, Chrome's 70 µs before it.

Tests: `TestAChromeProfilePingsAConnectionThatHasReadNothingForLong` changes
only the JSON's times and holds the wire to Chrome's: the PING after the
HEADERS in a TLS record of its own, 1 then 2, none to a connection that has
just read or while a check is pending, and the GOAWAY and the request again on
another connection; `TestAChromeProfileWithoutItsPingNeverPings` is its
control; `TestPrefacePingPolicyIsTypedAndCoherent` and
`TestEveryShippedChromeProfilePingsAsChrome` hold the data. fhttp's
`prefaceping_test.go` holds the mechanism: after HEADERS and trailers, before
DATA, the count, one unanswered or a check pending holding the next, any
acknowledgement answering it, the giving up put off by a read, a connection
held up in a write given up too, how often and how soon a request goes again
and what a body that cannot go again says.


## Stream dependencies in HEADERS (unreleased engine 1)

Chrome's HEADERS frames say which stream they depend on, and it is not
always none: requests open at once on one connection form chains
(net/spdy/http2_priority_dependencies.cc). The shipped Chrome profiles do
the same; absent, a stream depends on none, as before, and catalogue, legacy
and migration policies keep that until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `h2.priority_dependency` | `root`: every HEADERS depends on stream 0. `nearest-weight`: a new stream depends, with the exclusive flag and weight its priority says, on the stream most recently opened among the open ones of the lowest weight not below its own, or on none; the weight is Chrome's priority on the wire (255 a page, 219 a `fetch()`, 146 a CONNECT through a proxy). A stream stops being depended on when its answer ends or it is reset; a request whose HEADERS carry no priority joins no list. Chrome: `nearest-weight`. |

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-23, `../net-fp-server/captures/review-20261023/`): four `fetch()`es
at once went as streams 1, 3, 5, 7 depending on 0, 1, 3, 5 (`chrome-par`,
`chrome-par2`); a page that opened `fetch()`es (219), `fetch()`es with
priority low and an async script (146) and style sheets (255) at once, one
of them ending before the next three began (`chrome-prio`), had each depend
on the last open stream of the nearest weight not below its own (a `fetch()`
on the first `fetch()`, not on a style sheet opened after it), no PRIORITY
frame. tls-forge with these values on the same bench (`dep-par`,
`dep-prio`): the same chains for the weights it has, 219 and 255.

Tests: `TestAChromeProfileChainsItsStreamsAsChromeDoes` changes only the
JSON and holds a client's HEADERS to the rule on the wire (and "root" to
none); `TestABrowserContextSendsWhatChromeSent` holds every replayed request
to the dependency Chrome's fixture recorded (none: they were sequential);
`TestPriorityDependencyIsAChoiceOfTheEngines` and
`TestEveryShippedChromeProfileChainsItsStreamsAsChrome` hold the data.
fhttp's `http2/dependency_test.go` replays Chrome's measured connection
stream by stream, on the lists and on the wire, with a stream cancelled,
one reset by the server and one without a priority. Not done: PRIORITY
frames when a request's priority changes (Chrome's `OnStreamUpdate`;
tls-forge changes none), and priorities tls-forge never sends (fetch
priority hints, sub-resources).


## Answers let go of unread (unreleased engine 1)

A request often goes on from an answer without reading its body: it follows
a redirect, answers a 401, starts a navigation again for its critical client
hints, or sends the request a preflight allowed. Chrome reads none of that
body (HttpNetworkTransaction's destructor and PrepareForAuthRestart,
HttpResponseBodyDrainer, the preflight's SimpleURLLoader), so a server that
holds a body back sees at once what a client does with it: over HTTP/2 a
RST_STREAM(CANCEL), over HTTP/1.1 a closed connection or the next request on
another one. Before, tls-forge read up to 2 KiB of a redirect's body (the
transport) and up to 64 KiB of the others' before it went on, so a body that
came 2 s late held the next request back 2 s. Absent fields keep that;
catalogue, legacy and migration policies keep it until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `h1.dropped_body`, `h2.dropped_body` | A redirect followed or refused, and a 401 answered no more (`http.max_auth_restarts` spent). Chrome: `drain` over HTTP/1.1, `close` over HTTP/2. |
| `h1.auth_body`, `h2.auth_body` | A 401 the request is sent again for with credentials. Chrome: `read-all` over HTTP/1.1, the same connection after; `close` over HTTP/2, the same connection after. |
| `h1.restart_body`, `h2.restart_body` | A navigation started again for its critical client hints (Critical-CH). Chrome: `close` over both: its loader had a read pending. |
| `h1.preflight_body`, `h2.preflight_body` | A CORS preflight whose request goes on at once. Chrome: `first-bytes` over both. |
| `http.drain_bytes`, `http.drain_ms` | What `drain` reads at most, and for how long: `16384` and `5000` (`kDrainBodyBufferSize`, `kTimeoutInSeconds`). Required with a `drain`, refused without one. |
| `http.first_bytes_ms` | How long `first-bytes` waits for the body's first bytes, 0 as long as the connection lasts; `0`. Required with a `first-bytes`, refused without one. |
| `h1.unread_grace_us`, `h2.unread_grace_us` | How long, at most, what is left of a body may take to come and still count as come with what came before, before `close`, `drain` or `first-bytes` lets it go; 0 none. Chrome: `2000` over HTTP/1.1, `500` over HTTP/2 (below). Refused for a protocol none of whose answers is let go of so. |

The ways, each of the engine's (`unread.go`; fhttp's `DrainBody`,
`AwaitBody`, `Detach`):

- `read`, or no field, or a protocol other than HTTP/1.1 and HTTP/2: as
  before. The request waits for what is read.
- `close`: what is left of the body, all in the transport's buffer or come
  within the grace, is read and the connection kept; otherwise the HTTP/1.1
  connection is closed, the HTTP/2 stream reset (CANCEL) unless the server
  ended it. The request goes on once that is decided.
- `drain`: read in the background, apart from the request (whose context
  ends nothing of it), at most `http.drain_bytes` within `http.drain_ms`;
  the connection is kept when the body ended within both, else let go of as
  `close` does. The request goes on once the body ended or the grace is
  over, so an HTTP/1.1 connection whose body came within it carries the next
  request, and any other leaves the next to a connection of its own.
- `read-all`: read to its end before the request goes on, bound only by the
  request's deadline, the connection kept; an answer the server closes its
  connection after (`Connection: close`, a body that ends with the
  connection) is let go of at once.
- `first-bytes`: the request goes on at once; in the background, the body's
  first bytes are waited for, then let go of as `close` does, the grace
  counted from them: a body that came whole keeps its connection, one that
  comes in parts has it closed (HTTP/1.1) or reset (HTTP/2) with its first.

`CloseIdleConnections` and `Close` end what the client reads in the
background and wait for it before they close the idle connections, so that
the next request opens one of its own (the CLI's one connection per try).

An HTTP/1.1 connection whose body is all in the transport's buffer is kept
without a grace; the grace takes in what came with the head but past what
one read of the buffer holds, as Chrome's reads take what has come.

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-23, `../net-fp-server/captures/review-20261023/runs/lg-*`, 25 runs):
a 302 whose body comes 2 s after its head: over HTTP/2 RST_STREAM(CANCEL) in
the millisecond of the head, the next hop on the same connection; over
HTTP/1.1 the next hop at once on a new connection, the first kept once its
body came within 5 s and 16 KiB, closed 5.0 s after the head when it came
7 s late, and on arrival when it was 20,000 bytes. Its body 1, 3 and 10 ms
late: over HTTP/2 reset each time before it came; over HTTP/1.1 the next hop
on the first's connection at 1 ms, on a new one at 3 and 10 ms. With the
head: no RST over HTTP/2, the same connection over HTTP/1.1. A 401: over
HTTP/2 reset at once, the request again on the same connection; over
HTTP/1.1 its body waited for (2 s), the request again on the same
connection, and with `Connection: close` the connection closed at once and
the request again on a new one. A navigation's Critical-CH: over HTTP/2
reset at once; over HTTP/1.1 the connection closed at once, the start again
on a new one, and with the body with the head, on the same one. A preflight
whose body comes late: its PUT right after the preflight's head (over
HTTP/1.1 on a new connection), the preflight's stream or connection waited
on 7 s until its body came, then ended or kept; a body in two parts 2 s
apart: reset (HTTP/2) or closed (HTTP/1.1) within 2 ms of the first.
Chromium's source agrees and says 151 to 155 alike. Linux and Windows are not
measured. tls-forge with these values on the same bench (`fg-*`, 21 runs):
over HTTP/2 the stream reset 1 to 2 ms after the head and the next request on
the same connection, none with the body with the head; over HTTP/1.1 the
next hop 3 ms after the head on a new connection, the first kept once its
body came, closed 5.000 s after the head when it was 7 s late and on arrival
at 20,000 bytes, the same socket with the body with the head or 1 ms late; a
401's body read whole first (2.004 s), and with `Connection: close` the
connection closed at once; a Critical-CH start closing its connection 3 ms
after the head; a preflight's PUT 1 ms after its head, its body awaited 7 s,
in parts reset 1 ms and closed 3 ms after the first. With the body 3 ms late
over HTTP/1.1 the hop took the first socket, and the connection dialed for
it closed after its handshake (a dial ends with its request, S01), where
Chrome's hop took the new one.

Tests: `TestAnAnswerIsLetGoOfUnreadAsTheProfileSays` changes only the JSON
and holds the server's view, for each kind and way over both protocols, to
when the next request came and on which connection, whether the held body
was sent or given up and when, and when the connection closed;
`TestA401AnsweredNoMoreIsLetGoOfAsADroppedAnswer`,
`TestClosingIdleConnectionsLetsGoOfWhatADrainHolds`,
`TestAClosedClientLetsGoOfWhatItDrains`,
`TestAnAnswerOfAnotherProtocolIsReadAsAlways` and the CLI's
`TestATryAfterARedirectWhoseBodyIsDrainedGoesOutOnAConnectionOfItsOwn` hold
the rest;
`TestUnreadAnswerPolicyIsTypedAndCoherent` and
`TestEveryShippedChromeProfileLetsGoOfAnswersAsChrome` hold the data.
fhttp's `drain_test.go`, `drain_internal_test.go`,
`http2/drainbody_test.go` and `internal/chunked_buffer_test.go` hold the
mechanism. Not done: a grace of each kind's own (Chrome's window is its
processes' passing the answer on, from under 1 ms for an HTTP/2 redirect to
about 4 ms for a Critical-CH start again); HTTP/3.

## Requests sent again (unreleased engine 1)

A request that a server refuses, sends a GOAWAY above, or whose connection it
closes before answering, goes again or fails as the browser decides
(HttpNetworkTransaction::HandleIOError, ShouldResendRequest and
DoReadHeadersComplete; SpdySession::OnRstStream and OnGoAway), and a server
sees which: how many times, on which connection, how soon, and whether a POST
comes back. Before, tls-forge did as Go's transports do: over HTTP/2 up to
seven tries after a refused stream or a stream above any GOAWAY, the second a
second after the first and each later one longer, and none after a lost
connection; over HTTP/1.1 the request of a lost reused connection again only
when idempotent, and a 408 the answer. Absent fields keep that; catalogue,
legacy and migration policies keep it until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `h2.retries` | How many times at most a request goes again for the HTTP/2 failures `h2.retry_errors` names, all of them together; `2` (`kMaxRetryAttempts`, which ERR_HTTP2_PING_FAILED and ERR_HTTP2_SERVER_REFUSED_STREAM share). At most 16. |
| `h2.retry_errors` | The failures that send a request again: `refused-stream` (RST_STREAM REFUSED_STREAM: on its connection, while it takes streams), `goaway-no-error` and `goaway-error` (a stream above the last a GOAWAY with NO_ERROR, or with another code, says the server took: on another connection), `ping-failed` (its connection given up for its PING, which needs `h2.preface_ping_hung_ms`). Each once. Chrome: `["refused-stream","goaway-no-error","ping-failed"]`; a GOAWAY with an error code fails the streams above it (ERR_HTTP2_PROTOCOL_ERROR). Goes with `h2.retries`. |
| `h2.retry_delay_ms` | How long a request waits before it goes again for one of them; `0`. At most 60000. Needs `h2.retries`. |
| `http.connection_error_retries` | How many times at most a request goes again, at once, on another connection, when the reused connection it went on was lost under it (closed or reset by the server, or a write to it failed) before any of its answer came, not even a 1xx; `50` (`kMaxRetryAttemptsOnConnectionErrors`). At most 1000. Over HTTP/2 a connection is reused when it had read a frame before the request's stream opened (SpdySession::IsReused counts frames received), over HTTP/1.1 when it had carried a request before. A loss on a new connection is final, as Chrome's. Needs `h2.retries`. |
| `http.connection_error_methods` | Which requests may go again for a lost connection: `any`, or `idempotent` (GET, HEAD, OPTIONS, TRACE, or one with an Idempotency-Key, as Go's net/http sends one again). Chrome: `any`, a POST with its body. Goes with `http.connection_error_retries`. |
| `h1.request_timeout_resend` | A 408 on a reused HTTP/1.1 connection is not the answer: the client closes the connection, the 408 unread, and sends the request again on another (DoReadHeadersComplete). A 408 on a new connection, or over HTTP/2, is the answer. Chrome: `true`. |

Both counts are a hop's, as Chrome keeps them for a transaction: a hop's
answers to its 401 and its 421 share them, and the next hop of a redirect
starts from none (`chain.resends`; fhttp's `Resends`). A request whose body
cannot be read again cannot go again, and fails saying so. A request given a
connection that could take it no more before anything of it was sent goes
again at once, seven times at most, whatever the profile says.

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-24, `../net-fp-server/captures/review-20261023/runs/rc-*`, 29
runs, one a scenario; `bench/retry`, a server speaking HTTP/2 frame by frame
and HTTP/1.1 line by line, the request after two pages so that it goes on a
reused connection):
over HTTP/2 a refused stream again at once on its connection, twice at most,
then the request failed, a POST with its body; a stream above a GOAWAY with
NO_ERROR again at once on a new connection, counted with the refusals
(refused, GOAWAY, refused: failed at the third); a GOAWAY with PROTOCOL_ERROR,
INTERNAL_ERROR or ENHANCE_YOUR_CALM failed the request; the reused
connection closed or reset under it, or closed after a GOAWAY that took its
stream, again at once on a new one, a POST too, and that one's loss failed
it, as a new connection's did; two refusals and then the connection's loss:
again all the same, the loss counted apart; a 408 the answer. Over HTTP/1.1,
a reused connection closed or reset before any of the answer: again at once
on another, a `fetch()` POST and a form's POST with their bodies; a status
line cut short: failed; a 408 on a reused connection: closed by Chrome at
once and the request again on another. Chrome's error page reloads itself
about 1 s after a navigation that failed, with `Cache-Control: max-age=0`:
its renderer's, not modelled. Chromium's source for 151 (branch 7922) and 155
(8059) agrees line by line. Linux and Windows are not measured.

tls-forge with these values on the same bench (`rf1-*`, 29 runs): each
scenario as Chrome's, the request again 0 to 4 ms after the failure (a new
connection's dial). Before (`rf0-*`): a second refusal's try a second late
and a third's two more, a request refused three times answered at its
fourth, a stream above a GOAWAY with an error code sent again, the request of
a lost HTTP/2 connection and the POST of a lost HTTP/1.1 one failed, a 408
the answer.

What still differs: Chrome's navigation preconnects a socket over HTTP/1.1,
which, idle and unused, counts as reused (HttpBasicState::IsConnectionReused):
a navigation whose first connection to an origin is lost, or answered 408,
goes again there, and once more after a loss on that socket, where
tls-forge, which preconnects nothing, fails it or takes the 408 (`rc-h1-
close-fresh`, `-408-fresh`, `-close-twice`, `-408-twice`). A GOAWAY with
HTTP_1_1_REQUIRED, which Chrome answers by going again over HTTP/1.1, fails
the streams above it as any error code does; HTTP/3 keeps its own keys.

Tests: `TestARequestGoesAgainAsChromeSendsItAgainOverHTTP2` and
`TestARequestGoesAgainAsChromeSendsItAgainOverHTTP1` change only the JSON
and hold what the server is asked, and on which connection, to each measured
scenario, the hop's count shared by the answer to a 401 and fresh after a
redirect, and Go's rules without the keys; `TestRetryPolicyIsTypedAndCoherent`
and `TestEveryShippedChromeProfileRetriesAsChrome` hold the data. fhttp's
`http2/resend_test.go`, `resend_test.go` and `resend_internal_test.go` hold
the mechanism: each kind of failure, the counts and their limits, the delay,
reused and new connections, a 1xx, the methods, writes that fail, a body that
cannot go again, and the transports' own rules without the keys.

## Requests without a context, and requests a browser sent (unreleased engine 1)

A request without a browser context was the profile's headers with the
caller's laid over them: a field the profile has no name for after its last,
after Priority, and the transport's Content-Length last, by any method, a
navigation with a JSON body included. Chrome sends no such request: a
navigation is a GET with no body, and every field it writes has its place. And
a request an intercepting proxy is given by a browser, with the Sec-Fetch-* a
browser gives every request, went the same way, every image, script and XHR as
a typed navigation with the browser's own fields after Priority, and every GET
with `content-length: 0`. Absent fields keep the old way; catalogue, legacy and
migration policies keep it until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `headers.without_context` | `typed-navigation`: a request without a browser context goes as a navigation typed into the address bar, worked out as one in a context is (`headers.navigation_order` and the rest, the client hints an origin asked for, Accept-CH, Critical-CH and ALPS), a GET with no body, any other refused (`ErrNeedsContext`); `as-given`: the profile's headers with the request's own over them. Needs `headers.browser_context` and `@given`. Chrome: `typed-navigation`. |
| `@given` | In `headers.navigation_order`, `form_order`, `redirected_order` and `restarted_order`, all four or none, once each: where the fields a request was given go that no other slot of the order names, as Chrome driven over DevTools writes the extra headers it is given (`Network.setExtraHTTPHeaders`): after User-Agent; after Origin in a form's and a redirect's. A field a slot names goes in it, in place of what the browser would give it. |
| `pragma`, `cache-control`, `if-none-match`, `if-modified-since` | Slots for what Chrome writes of a reload (Pragma and Cache-Control before Authorization: `no-cache` both for a hard one, `max-age=0` for a reload) and of a revalidation (after the cookies), in the four orders; the validators after the cookies in `headers.script_trailing` too. |
| `headers.given_order` | How the fields in `@given` go: `bytes`, by the bytes of their names as first given, as DevTools gives Chrome them; or `as-given`. Needs `@given`. Chrome: `bytes`. |
| `headers.given_redirect_drops` | The fields a request was given that no hop of its redirects goes with; `["cookie"]`, as Chrome makes each hop's Cookie of its jar. Lower-case names. Needs `@given`. |
| `headers.sent_priority` | The Priority Chrome writes over HTTP/2 for a request a browser sent without one, as it sends none over HTTP/1.1, by what it is for (Sec-Fetch-Dest), `destination=Priority`, each once; a destination not named, and one with nothing after `=`, none. Needs `h2.urgency_weights`. |
| `h2.urgency_weights` | The weight of a HEADERS frame on the wire for each urgency of RFC 9218, 0 to 7, of a request a browser sent; eight of them. Chromium's Spdy3PriorityToHttp2Weight less one: `[255,219,182,146,109,73,36,0]`. |
| `headers.renderer_origin_dests` | The destinations of a request a browser sent whose Origin its renderer gives, in the renderer's map: `["font"]`; any other's goes after Accept, as the network stack gives fetch()'s. |

A request in a context with `BrowserContext.Sent` is a browser's: the fields
it is given are all it goes with, in its kind's slots, a script's own and a
page's subresource's in the renderer's map (`headers.renderer_*`), but the
profile's user agent, client hints, Accept-Language and Accept-Encoding
(`headers.browser_base_fields` and the client hints the profile has values
of), as the handshake says the profile. Nothing the browser works out is
worked out again: no Origin, Referer, Sec-Fetch-* or client hints of
tls-forge's, no preflight, no CORS check, no answer to a 401, no start again
for Critical-CH, no redirect followed, no answer kept. `tls-forge proxy` sends
a request with Sec-Fetch-Mode so: `navigate` a navigation (typed when
Sec-Fetch-Site says `none`) or a form's POST, `cors`, `no-cors` and
`same-origin` fetch() in that mode, the page its Referer or Origin names, with
credentials when it carries a Cookie or an Authorization.

Measured on Google Chrome 155.0.8059.85, headed, macOS, over its DevTools
port as Playwright drives it (2026-10-24, `../net-fp-server/captures/
review-20261023/runs/oc-*` and `op-*`, an own server keeping each request's
fields as they came and each HEADERS frame's priority, `bench/order`, `oc.sh`,
`op.sh`, `cdp.mjs`): 25 scenarios over HTTP/2 and HTTP/1.1, 50 runs
(`testdata/chrome155-given.json`). The extra headers of a navigation go after
User-Agent and before Accept, by the bytes of their names as given, spelt as
given over HTTP/1.1; one Chrome writes before them (the client hints,
Upgrade-Insecure-Requests, User-Agent) in its place with the value given; a
Referer in its own slot, Sec-Fetch-Site still `none`; Accept, Accept-Language,
Accept-Encoding, Priority, Authorization, Cache-Control, Pragma, Origin,
Content-Type, If-None-Match, If-Modified-Since and Range among them, Accept and
Sec-Fetch-Site with Chrome's values and Accept-Encoding `identity` beside a
Range; a Cookie given there too, the jar's in its place when the jar has some;
on a redirect's hop the same after User-Agent (after Origin), the Cookie gone,
Authorization kept even across origins, an Origin `null` across them; on the
start again for Critical-CH all of them, the Cookie too, the hints after
Accept; in a form's POST after Origin. Chrome's own: a reload's
`cache-control: max-age=0` and a hard reload's `pragma` and `cache-control:
no-cache` first, before the client hints; a revalidation's If-None-Match and
If-Modified-Since after the cookies. tls-forge puts a field Chrome writes in a
slot of its own there instead, as Chrome writes it when it is its own, keeps
the values it was given, and sends no Authorization across origins: the
differences `givenApart` names in `TestARequestWithoutAContextGivesItsFields
AsChromeOverDevToolsDid`, which holds every other field of every scenario to
Chrome's. A page loading an image, a script, a style sheet, a font and a
frame, fetch()ing a GET and a POST of JSON, sending an XHR and posting a form
(`testdata/chrome155-subresources.json`): a document's and a frame's
Priority `u=0, i` (255), a style sheet's and a font's `u=0` (255), an image's
`i` and a script's none (146), fetch()'s and the XHR's `u=1, i` (219); a
font's Origin first. Chrome behind `tls-forge proxy` before: 0 of 9 requests
as Chrome sends them directly; with these values 11 of 11, over HTTP/2 and
HTTP/1.1. Linux and Windows are not measured; nor are subresources but these,
service workers, beacons, prefetches and WebSockets (the proxy answers 501).

Tests: `TestTheFieldsARequestIsGivenGoWhereChromeWritesThem`,
`TestTheFieldsChromeAddsItselfGoInItsSlotsWhenARequestIsGivenThem`,
`TestARedirectTakesFromARequestWithoutAContextWhatChromeTakes`,
`TestACriticalHintRestartsARequestWithoutAContextWithItsOwnFields`,
`TestARequestWithoutAContextIsSentAgainForTheHintsALPSAsksForWithItsOwnFields`,
`TestARequestWithoutAContextThatIsNoTypedNavigationIsRefusedAndNothingIsSent`
and the replay above (typed.go); `TestARequestABrowserSent*`,
`TestARequestABrowsersPageSentGoesAsFetchInItsModeDoes` and
`TestAFormABrowserPostedGoesAsChromePostsOne` (sent.go); the proxy's
`TestABrowsersRequestsReachTheSiteAsChromeSentThemThere` and
`TestTheContextARequestSaysItWasSentIn`; `TestGivenFieldsPolicyIsTypedAndCoherent`
and `TestEveryShippedChromeProfileGivesFieldsAsChrome` hold the data.

## A page reloaded, and a click (unreleased engine 1)

Without them, a request made again was the first one again: the same fields on
a new connection, as `fetch --retry` makes each try. Chrome, when a person
reloads the page (Ctrl+R) after a 403, asks the page the answer is at again on
the connection it came on, afresh and as the person's, with what the answer
set; and a navigation or a form a person's click sends says so, where the
page's script's does not. Absent keys keep the old way: a reload is refused for
such a profile (`Request.Reload`), and a click goes without Sec-Fetch-User in a
form's order without its slot.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `headers.reload_cache_control` | The Cache-Control of a page reloaded, in its `cache-control` slot, first in a navigation's order: `"max-age=0"`. Said with `headers.form_reload_order` and `headers.navigation_fetch_user`, which a reload sends as Sec-Fetch-User however the page was first asked for. |
| `headers.form_reload_order` | The order of a form posted again from the page it opened: as `headers.form_order`, its Content-Type after Origin, no `@given` (a form is given no fields). Its ALPS anchor (`headers.alps_after`) where a browser context is. |
| `headers.form_order` | Has a `sec-fetch-user` slot, between `sec-fetch-mode` and `sec-fetch-dest`, for a form a person's click submits (`BrowserContext.Clicked`). |

Measured on Google Chrome 155.0.8059.85, headed, macOS, over its DevTools
port, 5 s after it started (Page.reload, which Ctrl+R's chrome::Reload calls
the same way, the repost dialog aside; Input.dispatchMouseEvent for a click):
12 scenarios over HTTP/2 and HTTP/1.1, two runs each, alike
(`testdata/chrome155-reload.json`). The other 14 shipped profiles carry the
same values, not measured on their own platforms or builds.

