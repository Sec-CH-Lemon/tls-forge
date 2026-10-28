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

Whatever its schema, an executable profile of the current engine runs only with `http.max_content_codings`, `http.content_coding_overflow`, `http.ignored_content_codings` and `cookie.prefixes`: an explicit `behavior` of schema 0-2 without them is refused before any I/O, as schema 3 and 4 are, and one with no `behavior` runs on the frozen templates, which have them. `Inspect` still reads such a file offline.

Existing shipped TLS capture bytes, ordered settings, header values, machine data and original provenance are preserved. Added behavior sections materialize the pre-existing runtime policy, including the newer policy previously applied to older Chromium profiles; this is not fresh acceptance of Chrome 151-154.

Unknown keys, duplicate behavior keys, null or wrong types, invalid ranges and unsupported algorithm names are errors. H3 ALPS, ORIGIN/coalescing and cross-version profile negotiation remain unavailable; they must not be advertised through arbitrary data. Missing-API catalogue scenarios remain open.

Certificate verification, authenticated Finished processing, nonce safety, protocol wire encodings, fresh keys/randomness, parser/state-machine mechanisms and safe finite resource bounds remain engine responsibilities. New algorithms/protocol features require engine code; existing parameter/ordering/timer changes require only profile data. A profile cannot replace the host kernel TCP stack. Explicit caller transport options retain their documented override precedence.

Response parsing enforces bounded HPACK/CONTINUATION processing and strict,
bounded chunk-size framing. The HTTP/2 field-list budget still comes from the
profile's SETTINGS; a profile cannot disable parser integrity checks. Caller
credential headers are removed permanently once a redirect chain leaves its
initial origin, including a different subdomain or port. This does not suppress
cookies selected by the jar for the destination or independently scoped HTTP
authentication. These fixes remain in the unpublished engine major 1 and do not
relabel historical browser measurements as fresh acceptance.

### Content-coding depth (unreleased engine 1)

| Key | Meaning |
| --- | --- |
| `http.max_content_codings` | Maximum selected decoder layers, integer 0–64. The engine ceiling 64 is a resource bound, not a browser default. |
| `http.content_coding_overflow` | `error` rejects the response before decoder creation; `raw` keeps its complete encoded body and metadata. |
| `http.ignored_content_codings` | Explicit no-op normalization tokens: `[]` or `["identity"]`. Unsupported tokens leave the whole chain raw. |

Chrome 156.0.8078.48/macOS was measured in nine fresh minimized headed contexts,
over H1/H2: ten gzip layers decode, eleven fail even on an empty body, and a
chain containing identity or an unknown coding stays raw. The shipped earlier
Chrome profiles explicitly inherit this policy; this is not fresh acceptance
of their original builds or other platforms. Generic compatibility data keeps
its former identity normalization and selects the hard ceiling explicitly.
The original legacy JSON files are frozen; new compatibility choices live in
separate engine-1 addition files. Missing current execution choices fail before
request I/O. Offline Inspect/Save/Clone preserve archives; explicit Migrate
materializes additions and still requires browser acceptance. Decoder creation
is lazy and each initialized decoder is closed, including after errors.

The shared policy registry in `github.com/igor-lemon/utls/behavior` contains supported keys/types and engine bounds. Browser values live in profile JSON. The forks are required at the commits pushed to their `tls-forge` branches; the engine itself is unreleased.

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


## Encrypted Client Hello from DNS HTTPS records (unreleased engine 1)

A direct connection to a name asks the name's HTTPS records (RFC 9460) as
Chrome's host resolver does, and offers ECH (RFC 9849) with the configs the
record it takes gives, as BoringSSL offers it in Chrome. A server that opens
the inner hello sees Chrome's; one that does not sees Chrome's outer hello,
its `encrypted_client_hello` the real one, to the config's public name.
Before, every connection sent GREASE ECH and no name was asked for its
records. Absent fields keep that; catalogue, legacy and migration policies
keep it until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `dns.resolver` | Who asks a direct connection's names: `built-in`, a DNS client of tls-forge's own that reads the machine's DNS servers (resolv.conf, an adapter's on Windows) and its hosts file and asks the servers itself, as Chrome's built-in client does (`kAsyncDns`, InsecureDnsMode `kEnabledBuiltIn`, on by default on macOS, Windows, Linux, Android and ChromeOS in Chrome 155); or `system`, the machine's resolver, with its cache. With `built-in`, a name under `.local` stays the machine's (Chrome's system task), and `localhost` and names under it too (Chrome answers them itself); where the machine names no DNS server, its resolver answers and no record is asked (Chrome's client cannot run then, `CanUseInsecureDnsTransactions`). A server named with `--dns-server` (`WithDNSServer`) is asked every name whatever this says. Absent: `system`. `built-in`. |
| `dns.https_records` | Ask a name's HTTPS records for a direct connection to it, as Chrome does for http, https, ws and wss (`kUseDnsHttpsSvcb`): of the same servers as its addresses, at the same time, for `_PORT._https.NAME` where the port is not 443 (`GetNameForHttpsQuery`). Not for an address, `localhost` and names under it, or `.local`. Needs `dns.resolver` `built-in`: a record asked apart from addresses the machine's resolver answers from its cache would come later than the wait every time. `true`. |
| `dns.https_wait_percent`, `dns.https_wait_min_ms`, `dns.https_wait_max_ms` | Once the addresses are in, how long a connection waits for the records: this percent of the time the lookup has taken so far, at least the floor, at most the ceiling (0: none); after it the connection goes on without them (`HostResolverDnsTask::MaybeStartTimeoutTimer`). `20`, `5`, `50`. Need `dns.https_records`. |
| `dns.https_upgrade` | A request to plain http whose name has a record Chrome takes goes to https without being sent (Chrome fails its host resolution with ERR_DNS_NAME_HTTPS_ONLY and its URLRequestHttpJob redirects it, 307, `Non-Authoritative-Reason: DNS`): the hop after it is a redirect's, its fields where a redirect's are. Port 80 goes to 443, another stays. `true`. Needs `dns.https_records`. |
| `tls.ech` | Offer ECH with the configs a connection's records gave. `true`. Needs every key below. |
| `tls.ech_inner_own` | The extensions of the outer hello the inner one writes itself, in the outer's order: the server's own name, the supported versions of `tls.ech_inner_min_version` and up (GREASE kept), the inner `encrypted_client_hello` (`01`). Must name 0 and 65037. Chrome: `[0, 43, 65037]`. |
| `tls.ech_inner_omitted` | The extensions of the outer hello the inner one leaves out. Chrome: `[11, 23, 35, 65281]` (ec_point_formats, extended_master_secret, session_ticket, renegotiation_info). Every other extension of the outer goes in the inner after its own, in the outer's order, its encoding naming them in one `ech_outer_extensions`; then a session's `pre_shared_key`, whose binders are over the inner. The padding extension is the outer's alone, and `pre_shared_key` and `ech_outer_extensions` are the engine's to place: neither list may name them. |
| `tls.ech_inner_min_version` | The inner's supported versions and cipher suites are those of this version and up, and the outer's GREASE. `772` (TLS 1.3). |
| `tls.ech_padding_block` | The encoding is padded as RFC 9849 section 6.1.3 says, past the name to the longest the config allows, then to a multiple of this; `32`. 0 pads to no block. |
| `tls.ech_kems`, `tls.ech_kdfs`, `tls.ech_aeads` | The HPKE primitives a config may use: the first config of the list with one of these KEMs and a cipher suite of these KDFs and AEADs, a public name that is a DNS name (not one the URL parser takes for an IPv4 address) and no mandatory extension is the one offered, with the first such suite of its own. Chrome: `[32]` (DHKEM X25519), `[1]` (HKDF-SHA256), `[1, 2, 3]` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305). |
| `tls.ech_chacha_without_aes` | Where the machine has no AES hardware, ChaCha20-Poly1305 rather than the first suite when the config lists it (BoringSSL's `select_ech_cipher_suite`). `true`. |
| `tls.ech_outer_psk` | What the outer hello says of a session the inner resumes: `none`, no `pre_shared_key`. |
| `tls.ech_retries` | How many times a connection whose ECH a server refused is made again, on a new connection: with the configs the refusal sent, and, when it sent none, without ECH when `tls.ech_retry_without` says so (GREASE ECH then); a second refusal fails the request. `1` (`SSLConnectJob`'s `ech_retry_configs_`). |
| `tls.ech_retry_without` | `true`. |

A refusal is believed only from a server whose certificate is good for the
config's public name, as the outer hello named it (RFC 9849 section 6.1.7);
with `WithInsecureSkipVerify` no certificate is checked. A connection made
again after a refusal asks the records of nothing: they are kept for their
time to live. ECH goes on direct connections alone: through a proxy the
names are the proxy's to look up, as Chrome's are.

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-24, `../net-fp-server/captures/review-20261023/bench/ech`: a DNS over
HTTPS resolver that Chrome's Local State points secure DNS at, answering A,
AAAA and HTTPS records, and TLS servers of Go's that keep every ClientHello and
open the inner one with the bench's HPKE keys whether they took it or not; 36
scenarios in two cohorts, testdata/chrome155-ech-dns.json): the inner hello is
the outer's as the table says, byte for byte from the outer (the server's name
and its random aside), in every one of 51 hellos opened, a resumed one and
both of a HelloRetryRequest among them; the encoding padded to 128 bytes for
names up to 15 letters with a config of no maximum length, 208 with 64; a
config of ChaCha20 first taken with it, a list of P-384, P-256 and X25519
configs given the X25519 one; a refusal with retry configs made again once
with them, one without again without ECH, a second refusal
ERR_ECH_NOT_NEGOTIATED; a record of TargetName "." for a name of a port not
taken (the target is the record's own name, which the addresses are not for);
records later than 5 ms after addresses that came at once not waited for,
records after addresses 300 ms late waited for up to about 55 ms; an http://
URL with a record sent to https, the request's client hints after
Sec-Fetch-Dest, as a redirect's hop, `Sec-Fetch-Site: none` typed and
`cross-site` from a link. Chrome opens a second connection at a navigation's
start, which makes its own ECH offer; tls-forge opens none.

On the machine's own DNS (2026-10-24, a home router answering A in about
4 ms and HTTPS records in 7 to 10 ms, so that a record comes near the 5 ms
floor), at cloudflare-ech.com, which says whether the SNI went encrypted:
Chrome took ECH in 3 of 5 visits, and in 8 of 8 later; tls-forge, while it
asked addresses of the machine's resolver, in 2 of 5 (and 0 of 6, but 5 of
6 with the router named by `--dns-server`); with `dns.resolver` `built-in`,
in 8 of 8, by turns with Chrome's. Chrome reads its own DNS client's
answers there, as Chromium 155's source says (`ConfigureStubHostResolver`
with `kEnabledBuiltIn`).

Not modelled: the HTTP/2 pooling of a name onto another's
connection whatever their ECH (Chrome pools them, measured); Chrome's DNS
queries as they are on the wire (its EDNS0 and padding, its AAAA only with
IPv6, its host cache for addresses: tls-forge asks its resolver again for a
connection made again); the machine's DNS configurations Chrome's built-in
client leaves to the system (a macOS configuration of several resolvers,
a VPN's domains, say, or resolv.conf options it does not know: tls-forge's
client asks the servers anyway). A server that negotiates
TLS 1.2 with an ECH offer is refused as BoringSSL refuses it, read in its
source, not measured.

## HTTP/3 from DNS HTTPS records (unreleased engine 1)

A direct https request to a name whose HTTPS record names `h3` goes over
HTTP/3 as Chrome's DNS ALPN job sends it (`HttpStreamFactory::JobController`
with `kUseDnsHttpsSvcbAlpn`): a QUIC connection to the name's first address,
offering the ECH of that record, and the request's TCP connection held back
behind it as the profile says; the first of the two up takes the request, and
the other is made anyway. A QUIC connection up takes every later request to
its origin until it goes away (idle past its timeout, or closed by the
server), when the next races again; a TCP connection that lost waits unused
for the next request over TCP. A QUIC connection that failed where TCP did not leaves QUIC to the
origin untried for a while. Before, a request went over HTTP/3 only with
`WithTransportOption(tls_client.WithProtocolRacing())`, to any origin, racing
TCP after 300 ms. Absent fields keep that; catalogue, legacy and migration
policies keep it until measured.

The record is read as for ECH (above): of the records for the name itself
(`.` only where it is the record's own name) that say no other port, the
lowest priority one that names `h3`, its own ECH configs. Where every record
says `no-default-alpn`, none is taken, as Chrome takes none
(`ExtractHttpsResults`): the request goes over TCP alone, as it does for a
record of `h2` alone, or none.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `dns.https_h3` | Go over HTTP/3 where the record names `h3`, as above. `true`. Needs `dns.https_records`, `quic.enabled` and every key below. |
| `quic.tcp_wait_cold_ms` | How long the request's TCP connection waits once its QUIC one has sent its first packet, while QUIC has not worked in the session (`IsQuicKnownToWorkOnCurrentNetwork`). `0`. |
| `quic.tcp_wait_broken_ms` | The wait for a server whose QUIC broke lately (below), or is broken now. `0`. |
| `quic.tcp_wait_rtt_percent`, `quic.tcp_wait_default_ms`, `quic.tcp_wait_extra_ms`, `quic.tcp_wait_max_ms` | Otherwise: this percent of the smoothed RTT the server's last QUIC connection measured, or the default where none is known, plus the extra, at most the maximum (`QuicSessionPool::GetTimeDelayForWaitingJob`). `150`, `300`, `0` (Chrome adds 100 ms on Android), `3000`. A QUIC connection that fails ends the wait: TCP goes at once. |
| `quic.tcp_waits_with_connection` | Whether TCP waits when the origin has a TCP connection already, made or being made, asked before the connections that wait are cleaned up (`TargettedSocketGroupHasActiveSocket`, asked before the main job's socket request cleans up). `false`: the request goes on it at once, and a QUIC connection is made apart for the requests after it; where that connection went as they were cleaned up (past its time, or closed by its server), TCP goes at once beside QUIC, the first up taking the request. |
| `quic.retry_over_tcp` | Whether a request its QUIC connection failed before its answer, for whatever reason but its own context's (its stream reset, its connection closed by either side), goes again over TCP, its body again where it can be had (`GetBody`, or none), and QUIC to the server is broken once TCP's answer came: Chromium's `QuicHttpStream::ComputeResponseStatus` says `ERR_QUIC_PROTOCOL_ERROR` of any request it sent that failed, which `HttpNetworkTransaction::HandleIOError` restarts with alternative services off (`retry_without_alt_svc_on_quic_errors`), marking the alternative service broken once the restart has read its body (`MarkAlternativeServiceBroken`). `true`. A request its QUIC connection could not take (gone before it went, or refused unprocessed) goes over TCP whatever this says, and breaks nothing. |
| `quic.broken_ms`, `quic.broken_doublings`, `quic.broken_max_ms` | A QUIC connection that failed where the request's TCP one worked has QUIC to the server not tried for this long, doubled for each break before it lately, this many times at most, and at most this long (`BrokenAlternativeServices`, with its exponential backoff on the first delay). `300000` (5 minutes), `18`, `172800000` (2 days). A QUIC connection that works ends the server's breaks, its recent ones too. |
| `quic.broken_recent_max`, `quic.server_rtts_max` | How many servers' recent breaks and how many servers' RTTs are kept, the least recently used forgotten first. `200`, `500`. |
| `http.unused_idle_connection_timeout_ms` | How long a TCP connection that lost to QUIC waits unused for a request, closed by the next request after that which asks the client for a connection: one to another address, or one to its own that goes over TCP (one on the QUIC connection asks for none; one QUIC failed, sent again over TCP, does), as Chrome's pool cleans up its idle sockets when a socket is asked of it (`unused_idle_socket_timeout`, `CleanupIdleSockets`, no timer). `60000`. A request it takes and loses before any of its answer goes again, as on a socket Chrome's pool kept idle (`http.connection_error_retries`). |

A server is the client's top-level site and the origin's host and port, as
Chrome keys them (`NetworkAnonymizationKey`); what is known of QUIC is the
session's, shared by its `Fresh` clients. Through a proxy, or for a client
given transport options of the caller's (which may race HTTP/3 its own way,
`tls_client.WithProtocolRacing`), a record names no protocol: the names are
the proxy's, or the caller's dialer's, to look up. The TCP connection is made
apart from the request that started it, within its deadline, as a connect
job goes on for its pool; a QUIC connection goes on until its own handshake
timeout.

A TCP connection waiting unused is read from its handshake on, as Chrome reads
each of its connections whether or not anything reads it yet (`DoPeek`): its
session tickets are cached as they come, and what the server sends after them
is left for the request that takes it up; one its server closed is cleaned up
as one past its time is (the reading met its end; else its socket is peeked,
as Chrome asks `IsConnected` of an idle socket). The sessions of QUIC
connections are kept apart from those of TCP's, as Chrome keeps them (its QUIC
session cache and `SSLClientSessionCache`): a ticket a server gave over one is
offered only over the same.

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-24 and 2026-10-25, `../net-fp-server/captures/review-20261023/bench/h3`:
a DNS over HTTPS resolver that Chrome's Local State points secure DNS at,
answering A and HTTPS records, and servers that speak TLS over TCP and HTTP/3
over QUIC on one loopback port; listeners whose QUIC answers come 50 ms or
1 s late, whose UDP is unreachable or never answered, and whose TCP answers
10 ms late, as on a network, where TCP's handshake takes a round trip more;
18 scenarios in two cohorts and three more in two others):

- a record of `h3,h2`: QUIC's Initial 1 to 3 ms after the record's answer,
  TCP's SYN 0.7 to 0.9 ms after the Initial; QUIC up first, the request and
  the next over HTTP/3, the TCP connection made and kept unused;
- `h2` alone, no record, or `h3` with `no-default-alpn`: no QUIC;
- ECH in the record: offered over QUIC, the outer hello to the public name;
- UDP unreachable or never answered: the request over TCP; QUIC never
  answered given up about 5 s after its first Initial, not tried again for
  the next request 20 s later;
- QUIC answered 50 ms or 1 s late in a fresh profile: the request over TCP,
  QUIC up apart, the next request over it; once QUIC had worked on another
  origin, TCP waited 300 ms (no RTT known): QUIC 50 ms late took the request
  with no TCP connection made, QUIC 1 s late lost to TCP at 310 ms, and the
  next went over it; UDP never answered, TCP at 310 ms;
- records later than the wait (10 ms to 1 s): no QUIC;
- TCP 10 ms late: HTTP/3, the next request too;
- a TCP connection that lost to QUIC and waited unused: kept while nothing
  asked Chrome's pool for a socket (52 s, until Chrome was closed), closed
  66.7 s after it was made, as a background request of Chrome's to another
  host asked for one; its session ticket cached at once, a TCP connection made
  62 s later resuming with it;
- a page's `fetch()` 40 s after the page (QUIC's connection gone, idle 30 s):
  over HTTP/1.1 on the connection waiting unused, and a QUIC connection made
  apart, resumed with QUIC's ticket; 62 s after, the connection there past its
  time: closed as the request came and a new one made at once beside QUIC,
  which took the request;
- a typed navigation 40, 50 or 70 s after the page: over HTTP/3 on a QUIC
  connection Chrome's preconnect for the navigation made 3 to 5 ms before the
  request (its net log), the connection waiting unused left alone.

The library (one client, `Do` after `Do`, `bench/h3client`) did as Chrome in
every scenario, four cohorts: but on loopback with nothing late, where both
handshakes take about a millisecond of the processor's, its TCP SYN went
0.1 ms after QUIC's Initial and the request went over HTTP/3 in 16 races of
28, where Chrome's went over it in 14 of 14 (with TCP 10 ms late, over
HTTP/3 in every run of both). At cloudflare-ech.com over a home router, by
turns with Chrome 155 (2026-10-25): tls-forge over HTTP/3 with ECH in 4
visits of 4; Chrome in 2, and in the other 2 over HTTP/2 without ECH, its
record having come after the wait. The TCP connection that lost
(`bench/unused`, the page's `fetch()` 40 and 62 s after it, two cohorts): as
Chrome's, request by request, connection by connection and ticket by ticket.

Not modelled: a navigation's
preconnect (for an origin whose record names `h3` a QUIC connection made
before the request: after QUIC's connection went away, Chrome's typed
navigation goes over HTTP/3 on it where tls-forge's goes over the TCP
connection waiting unused, or races again). The QUIC handshake itself is
below.

## HTTP/3 from an answer's Alt-Svc (unreleased engine 1)

An answer to a direct https request whose `Alt-Svc` advertises `h3` (RFC
7838) sends its origin's later requests over HTTP/3 to that alternative, as
Chrome's alternative job sends them (`HttpStreamFactory::JobController`): a
QUIC connection to the alternative's host (the origin's where it names none)
and port, named as the origin is, and the request's TCP connection held back
behind it as for a record's `h3` (above), by the wait the origin's QUIC
connections measured; but at once on an HTTP/2 connection the origin has, the
QUIC connection made apart. The QUIC connection up takes the origin's later
requests while the origin still advertises its alternative, and keeps its RTT
for the origin. Before, `Alt-Svc` was not read. Absent fields keep that.

The value is read as Chrome's quiche reads it (`SpdyAltSvcWireFormat`), its
fields joined: one it cannot read whole is not taken at all; `clear` forgets
the origin's alternatives; `ma` is how long each is kept, 24 hours without.
Each answer, a 421's aside, replaces what its origin advertised. Only `h3`
(QUIC version 1) is taken, the first one the profile allows that is not
broken: `h3-29`, `hq` and `h2` are passed over. An alternative whose QUIC
connection failed where TCP worked is broken as a record's server is
(`quic.broken_*`), and the next is taken. Alternatives are the session's,
kept for the origin and the client's top-level site, as many origins as
`quic.server_rtts_max`.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `quic.alt_svc` | Follow `h3` alternatives, as above. `true`. Needs `dns.https_h3` and the keys below. |
| `quic.alt_svc_user_ports` | Whether an alternative on a port of 1024 or more is taken for an origin on a port below it (`enable_user_alternate_protocol_ports`). `false`. |
| `quic.alt_svc_remote_hosts` | Whether an alternative on another host is taken (`allow_remote_alt_svc`). `true`. |
| `quic.alt_svc_tcp_waits_with_h2` | Whether the request's TCP connection waits behind QUIC where the origin has an HTTP/2 connection (`delay_main_job_with_available_spdy_session`). `false`: the request goes on it at once. |

Measured on Google Chrome 155.0.8059.85, macOS 27.0.1 arm64, on an own bench
(2026-10-25, `../net-fp-server/captures/review-20261023/bench/alt`: the same
DNS over HTTPS, a listener speaking TLS over TCP and HTTP/3 over QUIC on one
port, one for HTTP/1.1 and QUIC, another QUIC port, a UDP port that never
answers; 17 scenarios, each in two or three cohorts):

- an answer of the page advertising `h3` on its port: a `fetch()` right after
  it or 2 s later over HTTP/2 on the page's connection, a QUIC connection
  made at once apart, whether QUIC had worked on another origin or not; the
  next request over HTTP/3;
- the alternative on another port or another host: QUIC there, the origin's
  name in its hello, the next request over it;
- an origin over HTTP/1.1: with QUIC not yet working in the browser, the
  request at once on the idle HTTP/1.1 connection, QUIC made apart; once QUIC
  had worked on another origin, over HTTP/3 within the 300 ms wait, the idle
  connection not taken; after the page's HTTP/2 connection went, QUIC and TCP
  raced and QUIC took the request;
- two alternatives, the first a port that never answers: the requests over
  HTTP/2 while it was tried, then the second's QUIC connection made;
- `ma=1`: not gone to 3 s later; `clear`, then QUIC's connection closed: the
  next request over HTTP/2; `h3-29` and `h2`: no QUIC;
- advertised to a no-cors `fetch()` from a page of another site: not gone to
  by a navigation to the origin.

The library (one client, `Do` after `Do`, `bench/alt-lib.sh`, two cohorts of
15 scenarios, the page's `fetch()` a request like any other) did as Chrome in
each, request by request and connection by connection, but where Chrome's
navigation preconnect made the QUIC connection before the request, and where
a record's `h3` raced TCP on loopback (above).

Not modelled: Chrome's preconnects (in 9 runs of 16 a QUIC connection was
made 5 to 15 ms after the page's answer, by a preconnect for the page as one
net log shows, so that the next request, even 2 s later, went over HTTP/3
where tls-forge's goes over HTTP/2 and makes QUIC apart; a navigation's
own); the hints of the `IncreaseHttp3Usage` field trials (canonical
suffixes, known QUIC hosts); a record's DNS ALPN job beside an alternative's
to another destination (Chrome runs both); versions of QUIC other than 1.

## QUIC's handshake as Chrome's (unreleased engine 1)

A Chrome profile's QUIC client goes through its handshake as Chrome 155's
does (quiche at Chrome 155's DEPS revision `0b2bc13f`, the same code at
Chrome 151's `4729ceb2`): one packet number counter for the three packet
number spaces, from 1, a number as long as quiche's window rule makes it;
the first flight laid out as `QuicChaosProtector` and
`MultiPacketChaosProtect` lay it out; probes as quiche sends them, one a
time, a number skipped before each; at the end of its handshake's idle time
a `CONNECTION_CLOSE` in an Initial with quiche's reason; a UDP socket
connected to the server, so that an ICMP unreachable ends QUIC at once.
Absent fields keep quic-go's ways; catalogue, legacy and migration policies
keep them until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `quic.packet_numbers` | `separate` (a counter of each space's own, quic-go's, its application space skipping a number now and then) or `shared`: one counter for the Initial, Handshake and 1-RTT packets, with no random skips. `shared`. |
| `quic.first_packet_number` | The counter's first number (`shared` alone). `1`. |
| `quic.packet_number_length` | `two-byte-minimum` (quic-go's) or `window` (`shared` alone): a number in as few bytes as four times the larger of the packets the peer has yet to acknowledge and the congestion window in packets of the room left take (`UpdatePacketNumberLength`), the room what is left of the datagram while packets are coalesced before the handshake is confirmed; one byte, then two, then four. `window`: the first Initial's number one byte, the second's two (the datagram had no room left), the Handshake's and the first 1-RTT's one. |
| `quic.pto_skip` | `application` (quic-go's) or `every-space` (`shared` alone): a number skipped at every probe timeout, whatever space it probes (`OnRetransmissionAlarm`). `every-space`. |
| `quic.pto_probes` | Packets a probe timeout sends, 1 or 2. `1`: the frames of the oldest packet outstanding. |
| `quic.pto_initial_rtt_ms`, `quic.pto_no_sample_multiplier`, `quic.pto_no_sample_min_ms` | Before an RTT sample, a probe timeout is the multiplier times the initial RTT, at least the minimum (`GetProbeTimeoutDelay`). `100`, `3`, `10`: 300 ms, doubling. |
| `quic.pto_rttvar_multiplier` | After one, the smoothed RTT and this many times the mean deviation. `2`. |
| `quic.alarm_slack_ms` | How late the client's alarms fire: its loss detection and idle alarms, and the ACK alarm of 1-RTT packets (`quic.ack_timer_ms` and this). The macOS kernel coalesces the timer of Chrome's network thread («How late a QUIC client's alarms fire» below). `4` in the macOS profiles (probes measured 304.5, 909.7 and 2112.8 ms after the first flight on 2026-10-26); none, on time, in the Linux and Windows profiles, where it is not measured. |
| `quic.handshake_idle_timeout_ms` | The handshake's idle time: Chrome's `max_idle_time_before_crypto_handshake` less the client's second (`SetNetworkTimeouts`). `4000`. |
| `quic.handshake_timeout_ms` | The longest a handshake may take (`max_time_before_crypto_handshake`), at least the idle time. `10000`. |
| `quic.handshake_ack_timer_ms` | How long an ACK of an Initial or Handshake packet may wait (`kAlarmGranularity`): a handshake that ends within it never acknowledges the server's Initial. `1`. |
| `quic.idle_close` | `silent` (quic-go's: an idle connection ends without a word) or `after-pto`: one whose probes went unanswered sends a `CONNECTION_CLOSE` (`OnIdleNetworkDetected`). `after-pto`. |
| `quic.idle_close_code`, `quic.idle_close_reason`, `quic.handshake_idle_close_reason` | Its transport error code and reasons, after the handshake and during it; `{elapsed}` and `{timeout}` as quiche writes a `QuicTime::Delta`, `{undecryptable_count}` and `{undecryptable}` the packets kept undecrypted, `{{` and `}}` braces. `0`, `25:No recent network activity after {elapsed}. Timeout:{timeout}` and the same with ` num_undecryptable_packets: {undecryptable_count} {{{undecryptable}}}`. |
| `quic.undecryptable_level_names` | The four encryption levels' names in that list. `ENCRYPTION_INITIAL`, `ENCRYPTION_HANDSHAKE`, `ENCRYPTION_ZERO_RTT`, `ENCRYPTION_FORWARD_SECURE`. |
| `quic.initial_layout` | `scramble` (quic-go's) or `chaos`: the ClientHello's first `quic.chaos_first_frame_min` + a draw below `quic.chaos_first_frame_spread` bytes and its end in the first Initial, its middle in the next, split evenly; each Initial with CRYPTO and PADDING split into `quic.chaos_crypto_splits_min`..`max` more CRYPTO frames, given `quic.chaos_pings_min`..`max` PINGs, its padding spread and its frames shuffled, an ACK first. `chaos`, `55`, `32`, `2`..`10`, `2`..`10`. |
| `quic.padding_position` | `after-ack` (quic-go's) or `end`: an Initial's padding after its frames. `end`. |
| `quic.connected_socket` | The QUIC connection's own UDP socket connected to the server (needs `quic.dedicated_socket`): an ICMP unreachable is the next read's or write's error and ends the connection at once, as Chrome's `QuicChromiumPacketReader` ends it. `true`. |
| `quic.close_early_application` | `transport` (RFC 9000, section 10.2.3, quic-go's: an application close in an Initial or Handshake packet becomes `APPLICATION_ERROR` with no reason) or `application`: it goes as it is in them too, as quiche sends it. `application`. |

Measured on Chrome 155.0.8059.85 on macOS (2026-10-25,
`../net-fp-server/captures/review-20261023/bench/h3`, cohorts `h3a` and `h3b`,
tshark 4.6.9 opening the Initials): its first Initial numbered 1 with 2 to 10
PINGs among its CRYPTO frames, the hello's first 55 to 86 bytes and its end
in it, its middle in the second, numbered 2 in two bytes, both 1250 bytes;
into UDP never answered one probe 308.7 ms after the first flight, then at
917 and 2125 ms, numbers 4, 6, 8 after the skips; at 4 s a close in an Initial,
code 0, `25:No recent network activity after 4008694us. Timeout:4s
num_undecryptable_packets: 0 {}`; no ACK of the server's Initial when the
handshake ends within a millisecond; QUIC to a closed port given up at once.
The library (`bench/h3client`, cohorts `h3x1`, `h3x2`) did the same, its
probes within about 2 ms of Chrome's. Those cohorts' alarms were about 8 ms
late; the same Mac's Chrome probed at 304.5, 909.7 and 2112.8 ms and closed
at 4004.2 ms on 2026-10-26 (cohort `t1`), the lateness the profiles say
since («How late a QUIC client's alarms fire» below). `quicwire_test.go` holds the first
flight, the probes and the close through `Client.Do`, the JSON alone
changing them; quic-go-utls's `send_policy_test.go`, `chaos_test.go`,
`chrome_packer_test.go`, `idle_close_test.go` and tls-client's
`connected_socket_test.go` hold the rules.

What the client sends after its handshake is in «QUIC after the handshake
as Chrome's» below. Not modelled: Chrome's idle timeout of the negotiated
time less a second after the handshake.

## ALPS for HTTP/3 (unreleased engine 1)

Chrome's QUIC ClientHello offers ALPS (application_settings, 17613) for
`h3`, with no settings of its own; a server that gives settings in it is
answered with empty ones in the client's EncryptedExtensions, before its
Finished. What the server gives is HTTP/3 frames, read once the handshake is
done and before the connection says it is (quiche's
`TlsClientHandshaker::FinishHandshake`, `QuicSpdySession::OnAlpsData`, its
`HttpDecoder` and `AlpsFrameDecoder`): one SETTINGS frame, taken as the
control stream's would be, so that the first request's QPACK encoder has the
table it gives (Chrome's first request sets that capacity and inserts into
it, though the control stream's SETTINGS come later); ACCEPT_CH frames,
whose hints a page's request to the origin carries; unknown frames passed
over; anything else refused, which closes the connection before its Finished
goes. The control stream's SETTINGS are then held to what ALPS gave
(`QuicSpdyClientSessionBase::OnSettingsFrame`, `QuicSpdySession::OnSetting`).
A profile that keeps 17613 (or 17513) in `quic.preserve_extensions` offers
ALPS and must say all of the keys below; one that keeps neither says none.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `quic.alps_protocols` | The protocols the QUIC hello offers ALPS for, each of `quic.alpn`. `["h3"]`. |
| `h3.alps_reader` | How a server's ALPS is read: `quiche`, the only reader. |
| `h3.alps_origin_frames` | An ORIGIN frame (0x0c) in ALPS: `skip` (passed over unread, as an unknown frame), `read` (read, refused cut short, passed over: quiche's `enable_h3_origin_frame` as written) or `abandon`: the connection ends without a word, where Chrome 155's network service crashes (`AlpsFrameDecoder::OnOriginFrameStart` is `QUICHE_NOTREACHED`; measured, a well-formed frame and one cut short alike). `abandon`. |
| `h3.alps_close_space`, `h3.alps_close_code`, `h3.alps_close_frame_type` | The close of a refused ALPS: a `transport` (`CONNECTION_CLOSE` 0x1c) or `application` (0x1d) close, its code, and for a transport one the frame type it says. `transport`, `10` (PROTOCOL_VIOLATION), `6` (CRYPTO). |
| `h3.alps_close_reason` | Its reason, `{detail}` the condition's text. `28:Error processing ALPS data: {detail}`. |
| `h3.alps_errors` | The text of each condition: `data`, `headers`, `goaway`, `max_push_id`, `priority_update`, `metadata` (a frame ALPS may not carry), `settings_twice`, `incomplete` (a frame cut short; a frame type cut short at the end is a frame boundary, and taken, as quiche takes it), `too_large`, `setting_id`, `setting_value`, `setting_twice`, `goaway_id`, `goaway_extra`, `max_push_id_id`, `max_push_id_extra`, `priority_update_id`, `accept_ch_origin`, `accept_ch_value`, `origin_origin`, `http2_frame` (`{type}`), `cancel_push`, `push_promise`. quiche's words: `DATA frame forbidden`, ..., `HTTP/2 frame received in a HTTP/3 connection: {type}`. |
| `h3.peer_settings` | How the server's settings are taken, ALPS's then the control stream's: `quiche`, the only rule (the QPACK table's capacity fixed once said other than 0, the field section and the blocked streams never made smaller, one given in ALPS said again on the control stream, the field section first, then the blocked streams, then the capacity; an HTTP/2 setting refused; a boolean said otherwise refused; the rest passed over). |
| `h3.settings_close_space`, `h3.settings_close_code` | The close of a refused setting. `application`, `265` (H3_SETTINGS_ERROR), sent in the Initial and Handshake packets too (`quic.close_early_application`). |
| `h3.settings_errors` | The text of each: `http2` (`{id}`), `boolean` (`{name}`, `{value}`), `capacity`, `field_section`, `blocked` (`{value}`, `{current}`), `omitted_field_section`, `omitted_blocked`, `omitted_capacity`. `169:received HTTP/2 specific setting in HTTP/3 session: {id}`, `207:Received {name} with invalid value {value}`, `164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: {value} while current value is: {current}`, ..., `164:Server accepted 0-RTT but omitted non-default SETTINGS_QPACK_BLOCKED_STREAMS`. |
| `h3.settings_http2` | The settings of HTTP/2 refused. `[2, 3, 4, 5]`. |
| `h3.settings_boolean`, `h3.settings_boolean_names` | The settings held to 0 or 1 and their names in the reason. `[8, 51]`, `SETTINGS_ENABLE_CONNECT_PROTOCOL`, `SETTINGS_H3_DATAGRAM`. |

The ACCEPT_CH entry of an origin is the first that names it as an Origin
header writes it (capitals, a trailing slash or another origin name none);
a page's request over the connection carries its hints with the profile's
values, a script's none, as over HTTP/2, where the ALPS of h2 asks for them.
`h3.qpack.encoder_warmup_sections` holds back the control stream's settings
alone: a table ALPS gave is written into from the first section.

Measured on Chrome 155.0.8059.85 on macOS (2026-10-25,
`../net-fp-server/captures/review-20261023/bench/h3alps`: the fork's QUIC and
uTLS server giving ALPS by the name asked, 51 variants, two cohorts, `hpa` and
`hpb`, alike in every one; tshark opening the client's packets with the
server's secrets): every refusal above, its code, frame type and reason, in
one datagram of 1250 bytes of an Initial (padded), a Handshake and a 1-RTT
packet, numbered 3, 4 and 5, its Finished never sent; a setting's close an
application one in all three (quic-go's server refuses it in the Initial,
`FRAME_ENCODING_ERROR`); the page then over HTTP/2. ACCEPT_CH's hints on the
first request and the next; the first entry of an origin. With ALPS's QPACK
settings and the control stream's 300 ms late, the first request set the
capacity 4096 and inserted 13 fields. A request its connection failed went
again over TCP, QUIC to the origin broken after (`quic.retry_over_tcp`,
above). The library (`bench/h3client`, cohort `hl3`, and `hl4` with TCP's
first answer 10 ms late) closed alike in 49 of the 51, its first request
writing into the table ALPS gave; in the two ORIGIN variants it falls back
to HTTP/2 where Chrome's network service crashed and the page failed. Its
requests went over the protocols Chrome's did in 34 of the other 49, the
rest where its TCP won the loopback race (as in «HTTP/3 from DNS HTTPS
records»): with TCP late, in each of the 12 variants run so, one of them as
Chrome's cohort `hpa` (in `hpb` Chrome made a second QUIC connection).

## QUIC after the handshake as Chrome's (unreleased engine 1)

After its handshake a Chrome profile's QUIC client sends what Chrome 155's
does (quiche at Chrome 155's DEPS revision `0b2bc13f`, the same code at
Chrome 151's `4729ceb2`): no packet marked for ECN, no path MTU probe, the
server's first connection ID kept, its HTTP/3 control stream in the datagram
that carries its Finished, and nothing on a request stream the server resets
but its QPACK decoder's Stream Cancellation. Absent fields keep quic-go's
ways; catalogue, legacy and migration policies keep them until measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `quic.ecn` | `ect0` (quic-go's: 1-RTT packets marked ECT(0) where the socket can, ECN validated as RFC 9000 section 13.4 says) or `none`: no packet marked, as quiche marks only for its Prague sender (ECT(1), the PRGC option) and Chrome's Cubic and BBR mark none (`EnableECT0` and `EnableECT1` false). `none`. |
| `quic.mtu_probes` | `search` (quic-go's: once the handshake is confirmed, PING and padding probes of larger and larger sizes, its packets growing to what the path takes) or `none`: no probe, packets no larger than `quic.initial_packet_bytes`, as quiche's client probes the path MTU only for the MTUH and MTUL connection options, which Chrome does not send. `none`. |
| `quic.connection_id_change` | `after-handshake` (quic-go's: the server's first connection ID retired for its next at once after the handshake, `RETIRE_CONNECTION_ID` in the first 1-RTT packet, then a change every 10,000 packets or so) or `when-retired`: the connection ID in use is kept until the server retires it (`retire_prior_to`), as quiche's client keeps it. `when-retired`. |
| `h3.control_stream` | `after-handshake` (quic-go's: written once the connection says its handshake is done, in a packet after the Finished) or `with-finished`: written on the connection's own goroutine as the handshake completes, before anything is sent with the 1-RTT keys (`quic.Config.InitialData`), so that it goes in the datagram of the Finished, as quiche's `QuicSpdySession::SendInitialData` writes it once encryption is established. `with-finished`. |
| `h3.peer_reset` | `frame-error` (quic-go's: a request stream the server resets is reset by the client too, `RESET_STREAM` H3_FRAME_ERROR, H3_REQUEST_INCOMPLETE within the answer's HEADERS) or `read-side`: its read side alone is closed, as quiche's `QuicStream::OnStreamReset` closes it in IETF QUIC; nothing more is sent for a request sent whole, and one still sending is cancelled with H3_REQUEST_CANCELLED, as Chromium's `QuicHttpStream::Close` cancels a request it gives up on (read in the source). A read the client cancelled itself is not the server's reset. `read-side`. |

Measured on Chrome 155.0.8059.85 on macOS (2026-10-25,
`../net-fp-server/captures/review-20261023/bench/h3`, cohorts `h3a` and
`h3b`, and `bench/h3alps` `qpack`, cohorts `hpa` and `hpb`; tshark opening the
packets with the runs' secrets, `bench/quic-after.py`): every datagram
Not-ECT, no probe, no `RETIRE_CONNECTION_ID`, the second flight a Handshake
packet of an ACK and the Finished and a 1-RTT packet of an ACK and the control
stream (156 and 157 bytes of UDP); after the server reset a request stream,
nothing on it, a Stream Cancellation on the decoder stream (or nothing,
where the table ALPS gave was none). The library before (`h3x2`, `hl3`):
ECT(0) on 1-RTT packets, probes of 1359 to 1447 bytes 26 to 103 ms after the
handshake, a `RETIRE_CONNECTION_ID` in its first 1-RTT packet (116 bytes, the
control stream in the packet after), `RESET_STREAM` H3_FRAME_ERROR. After
(2026-10-26, cohorts `y1` and `y2` of `bench/h3`, `y1` and `y2` of
`bench/h3alps` with TCP 10 ms late in `y2`): as Chrome in every run, the
second flight 154 to 161 bytes; the same build with `h3.control_stream` left
out (`h3client -set h3.control_stream=`) sent 112 bytes and its control stream
after, twelve runs of each. `quicafter_test.go` holds the five through
`Client.Do`, the JSON alone changing them; quic-go-utls's
`after_handshake_test.go`, `conn_id_manager_test.go` and
`http3/after_handshake_test.go` hold the rules.

How a request's writes and the decoder's instructions go into packets is in
«HTTP/3 writes in packets as Chrome's» below.

## HTTP/3 writes in packets as Chrome's (unreleased engine 1)

A Chrome profile's HTTP/3 client puts its writes in packets as Chrome 155's
does (quiche at Chrome 155's DEPS revision `0b2bc13f`, Chromium
155.0.8059.85): a request's PRIORITY_UPDATE, its QPACK encoder's
instructions and its HEADERS, with the FIN of a request without a body, in
one packet, and the QPACK decoder's instructions only in packets the
connection sends for something else, a Stream Cancellation of a request the
server resets in the packet that acknowledges the reset. Absent fields keep
quic-go's ways; catalogue, legacy and migration policies keep them until
measured.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `h3.request_writes` | `as-written` (quic-go's: each write is sent as it comes, the PRIORITY_UPDATE from a goroutine of its own and the encoder's instructions from the encoder stream's writer, in packets of their own) or `one-flush`: the request's writes are held back until it has made them all (`quic.Conn.BundleWrites`), then go out together, in as few packets as they fit in, the streams' frames in the order the streams were given them: the control stream's PRIORITY_UPDATE, the encoder stream's instructions (the request waits for their writer to write them, when it had nothing else to write and its stream is reserved or open), the request stream's HEADERS and FIN; as Chromium's `QuicHttpStream::DoLoop` writes them under one `ScopedPacketFlusher`. A request's body goes after; a write that has to wait for packets to go lets what was held go at once. `one-flush`. |
| `h3.qpack.decoder_writes` | `as-written` (quic-go's: each instruction sent as it comes) or `opportunistic`: the decoder's instructions wait, bounded, for the next packet the connection sends with an ACK, a DATAGRAM or other new frames, and go first in it (`quic.Conn.BundleOpportunistically`), as quiche's decoder stream sender buffers them until `QuicSpdySession::MaybeBundleOpportunistically`, which its packet creator calls before new data and `SendAllPendingAcks` before an ACK; a retransmission carries none. A server's RESET_STREAM of a request stream is taken on the connection's own goroutine (`quic.Stream.SetResetHandler`), so that its Stream Cancellation, made then unless the stream's FIN had come, goes in the packet that acknowledges the reset, as quiche's `QuicSpdyStream::OnStreamReset` makes it while the frame is processed. `opportunistic`. |

Measured on Chrome 155.0.8059.85 on macOS (2026-10-25,
`../net-fp-server/captures/review-20261023/bench/h3`, cohorts `h3a` and
`h3b`, and `bench/h3alps`, cohorts `hpa` and `hpb`; tshark opening the
packets with the runs' secrets, `bench/quic-bundle.py`): each request's
first packet `STREAM(2) [STREAM(10@0)] STREAM(0)` (131 of them, 462 to 576
bytes of UDP, an ACK first where one was due); the decoder's Stream
Cancellation in the first packet that acknowledged the server's reset (4 of
6 resets, the other 2 closing the connection first): 0.28 ms after it with
an ACK sent at once, 28 to 34 ms after it where its ACK waited (the server's
next packets came first). The library before (`hly1`, `hly2`): the
PRIORITY_UPDATE in a packet of its own (45 bytes), the HEADERS in the next,
the encoder's instructions in that one or after; the Stream Cancellation at
once, in a packet of its own. After (2026-10-26, `bench/h3alps` cohorts
`hlf1` to `hlf4` and `hlg1`, `hlg2`, every variant in `hlf3` and `hlg1`, and
`bench/h3` cohorts `h3f1`, `h3g1`): every request's first packet as
Chrome's (121 of them, 497 to 576 bytes); the Stream Cancellation in the
first packet that acknowledged the reset in 19 of 22 resets (the other 3
closing the connection first, as Chrome's), 0.04 to 0.16 ms after it with an
ACK sent at once, 24 to 27 ms after it with the delayed one. With the two
fields left out (`h3client -set h3.request_writes= -set
h3.qpack.decoder_writes=`, cohorts `hlfc`, `hlgc`, `h3fc`, `h3gc`) quic-go's
again: no request's first packet with its PRIORITY_UPDATE (26), the Stream
Cancellation at once (0.09 to 0.24 ms), 5 of 8 in a packet of its own.
`quicbundle_test.go` holds both through `Client.Do`, the JSON alone
changing them; quic-go-utls's `bundle_test.go`, `bundle_unit_test.go` and
`http3/bundle_test.go` hold the rules.

Still Chrome's alone: a body read at once in Chrome's flush (`DoLoop` goes
on to read a body held in memory and writes its first part with the
HEADERS; not measured: tls-forge's body goes after), and a Header
Acknowledgement or Insert Count Increment made as the answer's packet is
processed (tls-forge makes them as the answer is read, so they wait for the
next ACK after that; not measured, as the bench's servers use no dynamic
table). How long the delayed ACK a Stream Cancellation goes with waits is in
«How late a QUIC client's alarms fire» below.

## How late a QUIC client's alarms fire (unreleased engine 1)

A Chrome profile's QUIC client acknowledges a lone 1-RTT packet as late as
Chrome 155 does on macOS, its probes and its handshake's idle close as late
too. quiche (Chrome 155's DEPS revision `0b2bc13f`) sets the ACK of a lone
ack-eliciting packet 25 ms after it came (`GetMaxAckDelay`,
`local_max_ack_delay_` of `GetDefaultDelayedAckTimeMs`, before 100 packets
and an ACK_FREQUENCY frame), and its ACK says how long it waited. Every
alarm of a connection goes through one alarm of its `QuicAlarmMultiplexer`,
Chromium's `QuicChromeAlarm`, a `base::OneShotTimer` of the default policy
on the network service's IO thread (`MessagePumpKqueue` on macOS). Its task
leeway, 8 ms (16 on Windows), does not reach the kernel there: the
`TimerSlackMac` and `AlignWakeUps` features are off and no field trial of
the bench turns them on (`chrome://version/?show-variations-cmd`), and
`--enable-features=AddTaskLeeway:leeway/2ms` or `/20ms` left the ACKs as they
were. What makes them late is the macOS kernel, which coalesces the timer of
that thread (on the bench's Mac up to a quarter of its interval, 5 ms at
most, `kern.timer_coalesce_tier1_*`): `taskpolicy -l 2` on the bench Chrome's
network service moved its ACKs to 35.7 to 37.1 ms. The Initial and Handshake
ACK alarm (`quic.handshake_ack_timer_ms`, 1 ms) takes no slack: the kernel
coalesces a timer that short by a fraction of a millisecond.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `quic.alarm_slack_ms` | How late the client's alarms fire: its probes and loss detection, its handshake's idle close, and the ACK of a lone 1-RTT packet, `quic.ack_timer_ms` and this after the packet came. `4` in the macOS profiles; none in the Linux and Windows ones (quic-go's alarms on time), as the macOS value is its kernel's and neither is measured. |

Measured on Chrome 155.0.8059.85 on macOS (2026-10-26,
`../net-fp-server/captures/review-20261023/bench`: `ack-chrome.sh`, five
variants of `h3alps` with delayed ACKs, cohorts `d`, `d2`, `d3`, `d4`, `l2`
and `l20` (the leeway at 2 and 20 ms), `hl` (headless), `tnone` and `t0`, and
`h3-chrome.sh` cohorts `t1` to `t3`; `ack-delay.py` reading every client ACK
with the runs' secrets): its ACKs of a lone packet that carried nothing else
(pure, the alarm's) said 25.3 to 30.0 ms, a median of 28.9 (197 of them);
its probes into silence at 304.5 and 305.0, 908.6 and 909.7, 2112.8 and
2113.2 ms, its idle close at 4004.2 and 4004.4 ms. On 2026-10-25 the same
Mac's Chrome was later on every alarm (cohorts `h3a`, `h3b`, `hpa`, `hpb`:
ACKs 25.1 to 35.0 ms, all but two from 31.2, median 33.1 of 110, probes 7.2
to 8.8 ms late): a state of that day's, its cause not found. The library
before (cohort `b0`): 24.1 to 25.1 ms, a median of 24.8 (`quic.ack_timer_ms`
24, and Go's timer under the kernel's coalescing of its threads, 1 ms at
most). After (cohorts `a1` to `a6` and `la1` to `la4`, by turns with
Chrome's `d3`, `d4`, `t2`, `t3`, whose ACKs said a median of 28.9 of 59):
28.5 to 29.2 ms, a median of 29.1 (23 of them), its probes at 305.2, 910.2
and 2115.3 ms, its close at 4004.5 and 4005.1 ms; the same build with
`quic.alarm_slack_ms` left out (`h3client -set quic.alarm_slack_ms=`, cohorts
`ac`, `lac`) 24.1 to 25.6 ms, a median of 25.0, its probes at 301.4, 901.5
and 2102.7 ms. `quicack_test.go` holds the ACK through `Client.Do`, the JSON
alone changing it; quic-go-utls's `received_packet_tracker_test.go`,
`received_packet_handler_test.go` and `chrome_conn_test.go` hold the rule.

A server whose probe timeout counts the 25 ms Chrome says its ACKs may wait
(its max_ack_delay) can probe before such an ACK comes: the bench's quic-go
server probes 26 ms after a lone packet while its round trip estimate stays
under a millisecond, as the library's loopback samples keep it (Chrome's
first packets took about 2.5 ms, which put the server's probe timeout past
its ACK), and the client acknowledges the probe at once, as Chrome would; so
the library had fewer ACKs of a lone packet to measure. Not modelled: the kernel's coalescing as it
draws (tls-forge's slack is fixed, and Go's timer adds up to a millisecond),
a state such as that of 2026-10-25, and the lateness on Linux and Windows
(by Chromium's source, its IO pump there waits in whole milliseconds, on
Windows at the system timer's resolution). How a packet after the server's
100th is acknowledged, every tenth or a quarter of the least round trip
after it came, is in «How a QUIC client acknowledges a long download» below.

## How a QUIC client acknowledges a long download (unreleased engine 1)

A Chrome profile's QUIC client acknowledges a server's 1-RTT packets as
Chrome 155 does through a long download. quiche (Chrome 155's DEPS revision
`0b2bc13f`, `QuicReceivedPacketManager`, `QuicConnection`) acknowledges
every second ack-eliciting packet (`kDefaultRetransmittablePacketsBeforeAck`)
until one numbered the peer's first plus 100 comes
(`kMinReceivedBeforeAckDecimation`; the first is the least received,
`PeerFirstSendingPacketNumber`), and every tenth from then on
(`MaybeEnableAckDecimation`, `kMaxRetransmittablePacketsBeforeAck`). A packet
so numbered waits a quarter of the least round trip (`GetMaxAckDelay`,
`quic_ack_decimation_delay` of `min_rtt`, which is zero before a sample), no
more than its 25 ms and no less than a millisecond (`kAlarmGranularity`), and
the ACK goes that long after the first packet it waits for: a later packet
never puts it off (`MaybeUpdateAckTimeout` keeps the earliest). A packet that
leaves the highest range of those received no longer than four, while a gap
is below it, is acknowledged at once (`HasNewMissingPackets`,
`kMaxPacketsAfterNewMissing`): the four packets after a number the server
skipped each have an ACK of their own, where quic-go acknowledged a gap once,
when it was new. An ACK due goes right after the packet that made it so is
processed (`ProcessUdpPacket`'s `ScopedPacketFlusher`), where quic-go reads
up to 32 packets first. After 19 packets in a row that carried an ACK and
nothing ack-eliciting, the next ACK goes with the connection's window as it
stands in a MAX_DATA (`kMaxConsecutiveNonRetransmittablePackets`,
`OnAckNeedsRetransmittableFrame`, its flow controller's `SendWindowUpdate`),
where quic-go sends a PING. Chrome sends none of AKD3, AKDU and 1ACK, the
connection options that change these.

| Key | Meaning / Chrome 155 choice |
| --- | --- |
| `quic.ack_decimation_after`, `quic.ack_decimation_packets`, `quic.ack_decimation_rtt_percent`, `quic.ack_decimation_min_ms` | ACK decimation: from an ack-eliciting packet numbered the least received plus `after` on, an ACK every `packets` ack-eliciting packets; a packet so numbered waits `rtt_percent` of the least round trip (none before the first sample), at least `min_ms` and at most `quic.ack_timer_ms`, the ACK going that long after the first packet not acknowledged. All four or none; none acknowledges every second packet, after the timer's delay, as quic-go does. `100`, `10`, `25`, `1`. |
| `quic.ack_gap_packets` | While the packets received have a gap below their highest range (between two ranges, or below the least the peer knows was acknowledged), each ack-eliciting packet that leaves that range no longer than this is acknowledged at once. None: quic-go's rule, a gap at once when it is new. `4`. |
| `quic.ack_sent_after` | `batch` (quic-go's: the packets read together, up to 32, then the ACK) or `packet`: an ACK of 1-RTT packets due goes before the next packet is taken, and while it waits for room in the send queue the packets wait too. `packet`. |
| `quic.ack_only_max`, `quic.ack_only_frame` | How many packets that carry an ACK and nothing ack-eliciting go in a row, and the frame that makes the next one ack-eliciting: `ping` (quic-go's) or `max-data`, the connection's receive window as it stands, sent again if lost. Both or neither; neither is 19 and a PING. `19`, `max-data`. |
| `quic.ack_alarm_slack_percent` | The 1-RTT ACK alarm fires no later than this percent of its delay after it, `quic.alarm_slack_ms` at most (and needs it): the macOS kernel coalesces a timer by up to a quarter of how long it waits, which a decimated ACK's short delay shows. `20` in the macOS profiles, the median of Chrome's; none in the Linux and Windows ones, which say no slack. |

Measured on Chrome 155.0.8059.85 on macOS (2026-10-26,
`../net-fp-server/captures/review-20261023/bench`: `h3bench`'s `/big`, a
megabyte over HTTP/3 from quic-go's server, `ackdec-chrome.sh` on loopback
through the `tcp10` listener, once and twice on a connection, and through
`lag50` and `lag1000`, the server's datagrams 50 ms and 1 s late; cohorts
`c2` to `c4`; `ack-decimation.py` and `ack-decimation-compare.py` reading
every client ACK with the runs' secrets): on loopback 97% of its ACKs before
the server's packet numbered 102 (its first, 2, plus 100) acknowledged two
packets, and 86% to 91% after it ten, none more; the four packets after each
number the server skipped each acknowledged at once (12 of 12); MAX_DATA
15728640 in every twentieth ACK packet in a row (52 times), never a PING; the
ACKs an alarm sent after the mark said a median of 1.19 ms on loopback, 1.27
at most (its least round trip under 0.1 ms: the floor), came 13.4 to 16.0 ms
after the first packet they waited for 50 ms away, a median of 15.5 (a
quarter of its least round trip, 50.1 ms, is 12.5), and 25.1 to 30.4 ms 1 s
away, a median of 28.0 (its 25 ms). The library before (`lb1`, `lb2`): on
loopback a quarter of its ACKs before the mark or fewer acknowledged two
packets and the rest up to 32, after it two to 32, ten in 1%; a gap
acknowledged once (none of 8 with the four at once); a PING in every
twentieth ACK packet. After (`la3` to `la5`, by turns with Chrome's `c4`):
97% of two before the mark on loopback and 89% to 93% of ten after it, none
more; each gap's four at once (18 of 18); MAX_DATA after 19 ACK-only packets
every time (78); its alarm ACKs said a median of 1.32 to 1.37 ms on loopback (1.58
at most), came 15.5 to 17.1 ms after the first packet 50 ms away (16.2)
and 28.1 to 30.4 ms 1 s away (28.5): 0.1 to 0.9 ms after Chrome's, as macOS
coalesces Go's own timers too (by up to an eighth of their interval, 1 ms at
most), which tls-forge does not take off. `quicacks_test.go` holds the
counts, the gap, MAX_DATA and the alarm through `Client.Do`, the JSON alone
changing each; quic-go-utls's `ack_decimation_test.go` and
`ack_policy_test.go` hold the rules. The bench's `lag50` relay passed the
server's datagrams on in any order before (313 of 908 out of order in one
download), and Chrome then acknowledged nearly every packet at once: its
cohort `c1` says nothing of decimation 50 ms away.

Not modelled: ACK_FREQUENCY and IMMEDIATE_ACK frames (neither side offers
them), quiche's ACK at once of a packet that changes the marks to ECN-CE
alone (quic-go's of every CE packet: Chrome sends no ECN, a server's marks are
not measured), the 255 ranges quiche keeps (quic-go's 32), and an ACK of
Initial or Handshake packets, which their 1 ms alarm sends
(`quic.handshake_ack_timer_ms`).

### Cookie prefix storage rules (unreleased engine 1)

`cookie.prefixes` is a required array for current executable profiles. Every
rule explicitly supplies `prefix` (1..256 ASCII token bytes), `case_sensitive`
(boolean), `reject_nameless` (boolean), and `attributes` (array). Attributes
select implemented checks: `secure`, `http-only`, `host-only` (no Domain), and
`root-path` (explicit Path=/). Matching named rules are cumulative. A nameless
value matching a rule is rejected when `reject_nameless` is true; otherwise
that rule imposes no attribute checks on the nameless value. An empty array
selects no prefix rules. Independent origin/Secure, SameSite, size and jar
scope checks still apply.

The engine rejects unknown, duplicate, missing, null or wrongly typed nested
fields, duplicate prefixes (ASCII case folded), unsupported/repeated attributes,
and more than 64 rules. These are capability/resource bounds, not browser
choices. Load and constructors validate before network activity. Inspect/Save/
Clone preserve an old archive without silently adding this field; explicit
Migrate creates a current-engine candidate.

Chrome156/macOS data supplies four case-insensitive rules: __Secure- requires
Secure; __Host- requires Secure, no Domain and Path=/; __Http- requires Secure
and HttpOnly; __Host-Http- combines all four constraints. All reject protected
nameless values. The witness covers 48 cases, 432 observations in nine fresh
headed/minimized contexts over plain HTTP and TLS H1/H2. Source fixtures,
limitations and raw-evidence hashes are in the remediation report. Older
151–155 builds and other platforms inherit the data pending separate measurement.
No profile-name/UA branch or executable profile code selects these rules.

The nameless __Secure-/__Host- rejection follows
[6265bis storage step 22](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html#section-5.7).
All four prefixes are specified by the work-in-progress
[layered-cookies-02 storage algorithm](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-layered-cookies-02#section-5.4.3).
This acceptance concerns the prefix checks; it does not certify the entire
cookie storage model against either document.

### TLS1.3 PSK after HelloRetryRequest (A3/S03)

The engine rebuilds profile-shaped ClientHello2 before computing its PSK binder
against message_hash(ClientHello1), HRR and the actual truncated ClientHello2.
The profile still owns the extension permutation, GREASE/ECH generation rules,
ticket lifetime/age policy and supported algorithms; no new JSON field is needed.
An unsupported opaque PSK implementation cannot silently reuse its old binder.
The separate real-ECH retry mechanism is unchanged. This remains unpublished
engine1. See the A3 report for the bounded Chrome156/macOS witness and original
packet/binder controls; other profiles/platforms need their own measurements.

### TLS integrity checks (A3/S06, unpublished engine1)

A real profile ECH offer cannot use False Start when TLS1.2 is negotiated:
Finished must authenticate the rejection first (RFC9849). A GREASE ECH extension
alone is not an ECH offer and retains the configured False Start policy.

A compressed Certificate cannot bypass the existing engine Certificate-message
ceiling (262144 output bytes). The engine checks this before allocation, reads
at most the declared length plus one, and rejects a length mismatch with
bad_certificate. Zstd uses one worker and the same hard memory/window ceiling.
Brotli's window is cut to the least the declared length needs (2^18 bytes, or
2^19 past 262,128): its ring buffer is sized from the window and from what a
meta-block claims before any data comes, and four bytes claiming 2^24 of each
allocated 16 MiB. A stream that decodes to the declared length means the same
in either window. A brotli stream cut short before its last meta-block is a
codec failure.
Actual codec failures retain `tls.certificate_decode_alert` from JSON (the
measured Chrome policy selects50); this is separate from a length mismatch.
These resource/integrity bounds are engine capabilities, not browser defaults.

Every read-key transition rejects buffered handshake bytes from the old keys,
including post-handshake KeyUpdate. An HRR server also rejects trailing messages
before retry. Cached verified chains are checked against current roots/time
before TLS1.2 or TLS1.3 client/mTLS-server resumption. Invalid cached client
entries are evicted and a full handshake is required; existing explicit insecure
time/name options retain their semantics. The two Go security fixes are scoped
to CVE-2025-61730 and CVE-2025-68121; this is not an audit of every crypto/tls
change. No browser/profile JSON values, schema or pending major changed.


## Environment and explicit profiles

Executable profiles remain pinned to unpublished engine1, schema4. A4 changes
security mechanisms and policy propagation, not captured browser values; JSON
files and their original measurement provenance are unchanged.

`quic.initial_layout` owns the layout, including `scramble`, regardless of
`QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING`. Bare callers of the QUIC fork without
an explicit layout retain its legacy environment behavior. The project's
profile transport selects HTTP/2 directly: `GODEBUG=http2client=0` does not
replace that choice. A forward HTTP proxy and ordinary helper clients are not
browser protocol measurements. Keep JSON production-wire controls for both
layout choices and test HTTP/2 through Client.Do.

SDK daemon startup preserves `QUIC_GO_DISABLE_ECN`, `QUIC_GO_DISABLE_GSO`,
`QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING`, `QUIC_GO_LOG_LEVEL`,
`QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING` and `GODEBUG`; it removes only
`SSLKEYLOGFILE` (case-insensitively, including Windows). ECN/GSO switches limit
usable socket/kernel facilities; they do not supply browser defaults or enable
a feature excluded by JSON. They can change actual network observations, so
record them with OS/socket capabilities and keep them unset for an unmodified
browser comparison. Warning/log switches affect diagnostics. Tests on this
macOS host do not establish Linux GSO/ECN behavior.

TLS key logging requires an explicit API/CLI destination. The engine never
reads `SSLKEYLOGFILE`, on either client or server. Diagnostic redaction changes
only displayed strings and capture snapshots; credentials, query parameters,
request/response payloads and canonical URLs returned on success retain their
actual application values. A deliberately exported pcap/keylog allows reading
application secrets; proxy credentials sent in cleartext heads are masked.

Captured file identifiers are lower-case ASCII identifiers without `..`;
`profile.FilePath` owns the version/platform layout. Directory writes and reads
use an OS root handle. Implicit manual captures use a `manual_` namespace and
cannot select the default `local` or newest `chrome` family. Reported browser
majors are bounded to 1–4 ASCII digits. Explicit profile files and `--name` are
owner inputs, not visitor assertions; profile engine-major validation remains
mandatory after loading the file.


## Site-pool resource lifetime (A5)

`http.max_site_pools` limits the resident LRU, without changing its captured
value. A request pins each partition it uses through final response close;
background drainers own independent pins. Evicted partitions remain accounted
for until their last user finishes, then close and disappear. Permanent Close
also refuses new partition acquisition; active reads finish under their existing
request deadline, while detached drainers are canceled and waited for. Snapshot
bookkeeping and socket close/reap I/O use separate critical sections. These are
engine ownership/synchronization mechanisms, not new profile choices; all share
the pending unpublished engine1.

A response remains active through body completion, including HTTP/3 transports
whose internal RoundTrip count ends at headers. Only sites without chain/drainer
leases may enter idle-close I/O. The claim is made under the registry mutex; new
readers of that site wait outside the mutex until it finishes. Other sites can
proceed, and the resident site retains its existing session pool. An idle close
that finds a site leased is not dropped: the site keeps it, and its last release
closes the connections idle by then.

HTTPS-proxy discovery locking is synchronization, not a browser data choice.
Only a cold connection's negotiation/setup is serialized. The GotConn hook
composes with caller tracing and ends the lease before a response can block.
Observed H1 bypasses future discovery locking; every new socket still negotiates
ALPN normally. No captured ALPN, browser name/version, timing threshold or
concurrency default is hardcoded by this mechanism. New sites/Fresh have their
own observation state. Profile ALPN vectors and existing connection limits still
apply; no profile values or version metadata change for this fix.
