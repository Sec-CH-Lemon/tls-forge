# Profile behavior

Every executable profile is a JSON document for one selected browser and engine major. The current development format is **schema 4** with `engine_major: 1`; see [compatibility](../guides/profiles.md) before running a custom file. A bundled profile is the safest starting point because required fields, ordering, and provenance are already present.

## File layout

| Section | What it describes |
| --- | --- |
| `schema`, `engine_major`, `name`, `notes` | Format, exact execution gate, identifier, and provenance |
| `user_agent`, `client_hello` | Browser identity and captured TLS ClientHello structure |
| `per_connection` | Rules for values that change with a connection, such as extension ordering |
| `http1`, `http2`, `headers` | Wire layout, ordered settings, and request header templates |
| `client_hints`, `network_hints` | Browser and machine context for generated request headers |
| `behavior` | Engine policy choices and parameters for implemented mechanisms |

`behavior` is one **flat object** whose keys contain literal dots. For example, `"h2.retries"` is a single key inside `behavior`, not an `h2` object. The [generated field inventory](profile-fields.md) shows every key present in the bundled JSON files. Unknown policy keys, wrong types, unsupported choices, and invalid ranges are rejected. The policy registry in the pinned `utls/behavior` dependency defines allowed keys and bounds; the bundled profiles supply values.

## What the policy groups control

| Key prefix | Examples | Effect |
| --- | --- | --- |
| `cache.`, `cookie.` | `cache.entries`, `cookie.prefixes` | Response cache and cookie storage/selection rules |
| `headers.`, `http.` | `headers.navigation_order`, `http.max_content_codings` | Browser request templates, redirect/auth handling, content decoding, and request lifecycle |
| `h1.`, `h2.` | `h1.idle_reap`, `h2.retry_errors` | HTTP/1.1 and HTTP/2 framing, pooling, scheduling, and retries |
| `h3.`, `h3.qpack.` | `h3.settings`, `h3.qpack.encoder_strategy` | HTTP/3 control streams, priorities, GREASE, QPACK encoder/decoder behavior, and errors |
| `tls.`, `quic.`, `tcp.` | `tls.ech`, `quic.initial_layout`, `tcp.keepalive` | Supported handshake, QUIC packet/state, and host socket choices |
| `dns.`, `url.` | `dns.https_records`, `url.blocked_ports` | HTTPS-record discovery, upgrade timing, and URL policy |

These are selectable values for mechanisms the engine already implements. TLS authentication, parser integrity, fresh keys and randomness, actual I/O, and hard resource ceilings remain engine responsibilities. A profile cannot add a new protocol implementation or change the host kernel's TCP stack. Not every available key appears in every shipped file; the generated inventory is a record of shipped data rather than the full validation schema.

## Edit a candidate profile

From a source checkout, copy a complete profile and change only a supported value. This example changes the local response content-coding limit; it is a custom candidate and does not claim a Chrome match.

```bash title="Terminal"
cp profile/data/chrome_157/macos.json /tmp/my-chrome-profile.json
python3 - <<'PY'
import json
from pathlib import Path

path = Path('/tmp/my-chrome-profile.json')
data = json.loads(path.read_text())
data['name'] = 'my-chrome-profile'
data['behavior']['http.max_content_codings'] = 8
path.write_text(json.dumps(data, indent=2) + '\n')
PY
tls-forge fetch --profile /tmp/my-chrome-profile.json https://example.com/
```

The exact `engine_major` must remain valid for the running binary. Renaming or retagging an older profile does not establish compatibility. A new client loads a new snapshot; an existing client keeps its owned profile. Compare changed behavior against independent browser observations in the same scenario, including fresh and reused connections where relevant. Keep the original profile and raw evidence.

## HTTP/2 preface PING

The existing `h2.preface_ping_*` fields own idle/hung timers, first ID and failure policy. The engine prepares the PING decision before HEADERS I/O and writes it separately after HEADERS. A response read during that write cannot cancel an already due PING. DATA keeps its decision before its write. No new profile default or browser-name dispatch is involved. This mechanism fix remains within the same unpublished engine1 candidate; revalidate measured profiles against the actual source.

## HTTP/3 and QPACK

QPACK is implemented in the unreleased engine 1. The profile selects table capacity, encoder strategy and warmup, literal string coding, reference base, stream creation order, feedback, and error templates. The engine maintains actual dynamic table and stream state. Changing `h3.qpack.encoder_strategy` to `insert`, for example, requires a compatible `h3.qpack.encoder_table_bytes` and the relevant peer SETTINGS; it is not proof of Chrome's selection rule. Consult the [shipped fields](profile-fields.md) for concrete values and the historical engineering reference in `research/profile-behavior.md` for measurement provenance.

## Validation and provenance

Use `profile.Load` or a CLI `--profile` path to validate a candidate for execution. `profile.Inspect` reads an old file offline; `Save` and `Clone` preserve its declared major. An explicit `Migrate` creates a separately identified current-engine candidate but does not make it browser-equivalent. Preserve raw capture values as evidence while generating random, request-derived, and stateful fields from the current context. The [capture and compare guide](../guides/capture-compare.md) explains the measurement workflow.
