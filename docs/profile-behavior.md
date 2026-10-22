# Profile-owned network behavior

## Engine/profile compatibility (2.0.0)

The compiled engine version is **2.0.0**, independently of the browser build and
profile format **schema 4**. Every executable profile must declare the exact,
non-negative integer `engine_major: 2`. Engines reject profiles from both older
and newer majors, including files with no declaration. Schema, filename, browser
name, User-Agent and catalogue fallback cannot supply compatibility implicitly.
The check runs before request-related DNS, proxy, TCP, TLS or QUIC I/O.

```json
{"schema": 4, "engine_major": 2, "name": "my-browser"}
```

This illustrates metadata only; a complete profile still needs captured TLS/HTTP
data and the explicit `behavior` object. Browser values and selections stay in
JSON. Any coordinated change requiring shipped engine/fork runtime code increments
the project major exactly once, even a compatible fix. Existing primitives can be
configured by JSON without an engine bump. Versioned CLI, daemon and SDK identity
must agree; `engine/version.json` is the compiled authority. Release builds refuse
a different version stamp. Crossing to major 2 will also require Go module path
versioning.

`profile.Load` is the execution loader. `profile.Inspect` reads an archive offline
without declaring it compatible. `Save` and `Clone` preserve the original
`engine_major`, including absence; they never retag an old profile. Explicit
migration creates a candidate while preserving original capture provenance:

```go
old, err := profile.Inspect(originalJSON) // offline; handle err
candidate, err := old.Migrate("my-browser-engine-2") // handle err
migratedJSON, err := candidate.Save() // save to a separate destination
```

Preserve the original file. Migration is not browser equivalence acceptance;
repeat the relevant actual browser/wire checks before relying on its behavior.
The 15 shipped profiles and all backend catalogue policies have explicit engine-2
migration provenance; older captured browser builds are not new measurements.
A bare catalogue preset still supplies no browser headers.

For a new programmatically created Go profile, explicitly set
`EngineMajor: profile.Major(tlsforge.EngineMajor())`. Never use this assignment to
silently accept an imported file. `tlsforge.Version()` and `tlsforge.EngineMajor()`
report the compiled identity. Client constructors, transport adapters, the
registry and `Fresh` enforce it; client/profile clones own their major value.

Daemon protocol **3** reports `engine_major` and `version` on `hello`. Every
request and proxy `init` line must carry `engine_major: 2`; missing or mismatched
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

## Compatibility and boundaries

HTTP/3 gates request streams on the completion of its local control-stream
initialization. This is an engine ordering invariant, with no profile opt-out.
It queues local SETTINGS before request HEADERS, including 0-RTT and direct
request streams, without waiting for peer SETTINGS or an acknowledgement. The
SETTINGS values/order and priority/GREASE contents still come from the profile.

Schema 0-2 retains its historical family inference during migration. `Save` materializes `per_connection` and the complete effective policy into schema 4, without mutating the source object. The two JSON templates in `utls/behavior` preserve old default behavior; explicit schema 3 data takes precedence, even for a file called `chrome`. Bare transport-catalogue presets remain legacy backend presets and are not newly measured complete profiles.

Existing shipped TLS capture bytes, ordered settings, header values, machine data and original provenance are preserved. Added behavior sections materialize the pre-existing runtime policy, including the newer policy previously applied to older Chromium profiles; this is not fresh acceptance of Chrome 151-154.

Unknown keys, duplicate behavior keys, null or wrong types, invalid ranges and unsupported algorithm names are errors. Nonzero dynamic QPACK table support, H3 ALPS, ORIGIN/coalescing and cross-version profile negotiation remain unavailable; they must not be advertised through arbitrary data. Missing-API catalogue scenarios remain open.

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

## HTTP/3 QPACK string coding (engine 2)

The required `behavior` keys `h3.qpack.huffman_names` and
`h3.qpack.huffman_values` each select `always`, `shorter`, or `never`.
`shorter` uses Huffman only when its encoded bytes are strictly shorter; a tie
remains literal. Static-table references and field ordering are preserved.
These are data choices applied to actual request HEADERS, independent of the
profile name or User-Agent. No dynamic-table support is implied.

The Chrome155/macOS profile selects `shorter` for both strings. Other explicit
engine-2 migrations retain `always` until separately measured. The 15 original
engine-1 profile files remain in the private immutable r16 source archive.
Current macOS Chrome acceptance does not validate older builds or other OSes.

Engine 2.0.0 uses Go module/import path `github.com/Sec-CH-Lemon/tls-forge/v2`;
Node and Python packages are 2.0.0. Engine1 profiles cannot execute under engine2,
and engine2 profiles cannot execute under engine1. Schema4 and daemon protocol3
are unchanged; exact engine-major compatibility is still required.
