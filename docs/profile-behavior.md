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
| `h1.max_connections` | `6` |
| `h1.max_idle_connections` | `6` |
| `h1.merged_head_body_bytes` | `1400` |
| `h1.missing_status` | `200` |
| `h1.preserve_framing_fields` | `true` |
| `h1.response_header_bytes` | `262144` |
| `h2.allow_huffman_expansion` | `true` |
| `h2.alps_settings` | `[1,3,4,8,9]` |
| `h2.connection_window_overflow_error` | `1` |
| `h2.data_frame_payload` | `16375` |
| `h2.encoder_table_bytes` | `4294967295` |
| `h2.enforce_advertised_frame_limit` | `true` |
| `h2.header_frame_payload` | `16374` |
| `h2.hpack_first_static_name` | `true` |
| `h2.hpack_index_oversized` | `true` |
| `h2.hpack_indexed_exceptions` | `[":authority"]` |
| `h2.hpack_unindexed_prefixes` | `[":"]` |
| `h2.reject_unsolicited_ping_ack` | `true` |
| `h2.reset_data_before_headers` | `true` |
| `h2.strict_max_streams` | `true` |
| `h2.tolerated_response_fields` | `["connection","keep-alive"]` |
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
| `headers.form_order` | `["content-length","cache-control","authorization","@hints","upgrade-insecure-requests","content-type","user-agent","origin","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","priority"]` |
| `headers.h1_connection_default` | `"keep-alive"` |
| `headers.h1_generated_priority` | `false` |
| `headers.h1_prefix` | `["host","connection"]` |
| `headers.navigation_fetch_user` | `"?1"` |
| `headers.navigation_order` | `["authorization","@hints","upgrade-insecure-requests","user-agent","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","priority"]` |
| `headers.preflight_order` | `["accept","access-control-request-method","access-control-request-headers","origin","user-agent","sec-fetch-mode","sec-fetch-site","sec-fetch-dest","referer","accept-encoding","accept-language","priority"]` |
| `headers.priority_fetch` | `"u=1, i"` |
| `headers.range_accept_encoding` | `"identity"` |
| `headers.range_cache_control` | `"max-age=0"` |
| `headers.redirected_hints_after` | `"sec-fetch-dest"` |
| `headers.redirected_order` | `["content-length","cache-control","authorization","upgrade-insecure-requests","content-type","user-agent","origin","accept","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","@hints","referer","accept-encoding","accept-language","cookie","priority"]` |
| `headers.renderer_default_hints` | `["sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform"]` |
| `headers.renderer_extra_fields` | `["user-agent"]` |
| `headers.renderer_hint_insertion_order` | `["device-memory","sec-ch-device-memory","rtt","downlink","ect","sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-arch","sec-ch-ua-platform","sec-ch-ua-platform-version","sec-ch-ua-model","sec-ch-ua-full-version","sec-ch-ua-full-version-list","sec-ch-ua-bitness","sec-ch-ua-wow64","sec-ch-ua-form-factors","save-data","sec-ch-prefers-reduced-transparency","sec-ch-prefers-reduced-motion","sec-ch-prefers-color-scheme","dpr","sec-ch-dpr","viewport-width","sec-ch-viewport-width","viewport-height","sec-ch-viewport-height","width","sec-ch-width"]` |
| `headers.renderer_initial_buckets` | `8` |
| `headers.renderer_load_denominator` | `2` |
| `headers.renderer_order` | `"utf16-rapidhash-quadratic-v1"` |
| `headers.restarted_order` | `["authorization","upgrade-insecure-requests","user-agent","accept","@hints","sec-fetch-site","sec-fetch-mode","sec-fetch-user","sec-fetch-dest","referer","accept-encoding","accept-language","cookie","priority"]` |
| `headers.script_leading` | `["content-length"]` |
| `headers.script_metadata` | `["sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-storage-access"]` |
| `headers.script_priority_exclusive` | `true` |
| `headers.script_priority_weight` | `219` |
| `headers.script_trailing` | `["referer","accept-encoding","accept-language","cookie","range","priority"]` |
| `headers.storage_access` | `"active"` |
| `headers.untrusted_drop_codings` | `["br","zstd"]` |
| `headers.untrusted_prefixes` | `["sec-ch-","sec-fetch-"]` |
| `headers.withhold_untrusted` | `true` |
| `http.auth_cache_entries` | `20` |
| `http.auth_cache_paths` | `10` |
| `http.auth_scheme_order` | `["basic","digest","ntlm","negotiate"]` |
| `http.body_read_bytes` | `8192` |
| `http.content_codings` | `["gzip","x-gzip","deflate","br","zstd"]` |
| `http.digest_algorithms` | `["MD5","MD5-sess","SHA-256","SHA-256-sess"]` |
| `http.digest_cnonce_bytes` | `8` |
| `http.gzip_decoder` | `"prefix-first-member"` |
| `http.idle_connection_timeout_ms` | `90000` |
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
| `tls.alpn_mismatch_alert` | `47` |
| `tls.certificate_decode_alert` | `50` |
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
