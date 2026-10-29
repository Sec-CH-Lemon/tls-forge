# Profiles

## Engine/profile compatibility (unreleased 1.0.0)

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
JSON. Engine/fork runtime changes share the next major after the latest actually
published stable release. The current anchor is v0.2.2; all work in the single
unpublished1.0.0 candidate stays major1 until publication. Internal historical
engine2..7 labels were never published releases. Existing primitives can be
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
candidate, err := old.Migrate("my-browser-engine-1") // handle err
migratedJSON, err := candidate.Save() // save to a separate destination
```

Preserve the original file. Migration is not browser equivalence acceptance;
repeat the relevant actual browser/wire checks before relying on its behavior.
The 15 shipped profiles and all backend catalogue policies have explicit engine-1
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



A profile is one browser build, described completely enough to impersonate it,
stored as JSON so it can be committed and reviewed.

```json
{
  "schema": 3,
  "behavior": { "tls.handshake_retries": 1, "http.body_read_bytes": 8192 },
  "name": "chrome_151",
  "user_agent": "Mozilla/5.0 (Macintosh; …) Chrome/151.0.0.0 Safari/537.36",
  "client_hello": "FgMBBvgBAAb0AwPdnWafT…",
  "per_connection": {
    "shuffles_extensions": true,
    "ech_payload_lengths": [128, 160, 192, 224]
  },
  "http1": {
    "header_order": ["Host", "Connection", "sec-ch-ua", "User-Agent", "Accept"],
    "headers": [
      {"name": "Connection", "value": "keep-alive"}
    ]
  },
  "http2": {
    "settings": [
      {"id": 1, "value": 65536},
      {"id": 2, "value": 0},
      {"id": 4, "value": 6291456},
      {"id": 6, "value": 262144}
    ],
    "connection_flow": 15663105,
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "header_priority": {"stream_id": 1, "exclusive": true, "depends_on": 0, "weight": 255}
  },
  "headers": [
    {"name": "sec-ch-ua", "value": "\"Chromium\";v=\"151\", …"},
    {"name": "sec-ch-ua-mobile", "value": "?0"},
    …
  ],
  "client_hints": [
    {"name": "sec-ch-ua-arch", "value": "\"arm\""},
    {"name": "sec-ch-ua-full-version-list", "value": "\"Google Chrome\";v=\"155.0.8059.80\", …"},
    …
  ],
  "notes": "captured 2026-08-15T09:12:44Z from Mozilla/5.0 …"
}
```

`client_hello` is a real ClientHello, base64'd, recorded off the wire. It is the
authoritative TLS field; the HTTP fields are measurements from the same browser
navigation. `http1.header_order` deliberately retains the exact spelling seen
on the wire: `sec-ch-ua` and `User-Agent` are different, measurable choices.
`http1.headers` contains only values that differ from the shared `headers`
block, such as HTTP/1.1-only `Connection`. `Host` remains first in the order but
its value is always derived from the request URL.

The `http1` object is optional for backward compatibility. A profile without it
uses the historical canonical HTTP/1.1 header spelling; its TLS and HTTP/2
fingerprints are unchanged. New captures include it whenever an HTTP/1.1
navigation was observed.

`per_connection` says what the browser draws afresh for every connection:
whether it shuffles its extensions, and the lengths the payload of its GREASE
`encrypted_client_hello` is drawn from, before the AEAD's 16-byte tag; with
none, the captured length is kept. `capture` says it of the browser it
measures: a browser that counts Chromium among its brands draws as Chromium
does, and one that gives no brands is judged by its user agent, on iOS never
Chromium's. A profile without `per_connection` is judged by its name and user
agent each time it is used, as profiles were before they said it.

`client_hints` are the values of the client hints the browser sends when a
server asks for them with `Accept-CH`, by name in lower case, as the browser
writes them: the user agent's beyond `sec-ch-ua`, `sec-ch-ua-mobile` and
`sec-ch-ua-platform`, which it sends unasked and which are in `headers`, and
the device's, the network's and the user's preferences. A hint the profile has
no value for is not sent, asked for or not. `capture` writes the user agent's
from what the browser gives JavaScript (`getHighEntropyValues()`), which is
what Chrome sends; the shipped `chrome_155_macos` has every one Chrome 155
sent there when asked, `rtt`, `downlink` and the viewport being what one
measurement gave, as Chrome estimates them anew. The names a profile may give
are `profile.ClientHintOrder` but those three, in the order Chrome sends them.

`schema` is the version of the format the profile was written in, 3 today. A
profile that names one is read strictly: a field the format does not have, at
any depth, is an error naming it, so a misspelt `heders` is found when the
profile is read rather than on the wire. Schema 1 is read as strictly, and has
no `client_hints`, which schema 2 added. A profile with a newer schema than
this tls-forge reads is refused, and says to upgrade. A profile with no
`schema` was written before the format had one and is read as it always was,
fields the format does not have passed over; it is written with the schema the
next time it is saved, as `capture --save` and `--install` do.

## Executable HTTP2 semantics (A6)

`Profile.Validate` is the common execution gate for Load, registry, catalogue,
Spec/adapters, New, Fresh and requests. CLI/daemon/SDK and pooled clients use
these paths. Inspect stays offline; Save/Clone preserve archives without
permission to execute. Accepted clients own deep snapshots of caller data.
Engine-major rejection remains the first independent gate.

HTTP2 SETTINGS remain an ordered array. The initial frame must fit 16384 bytes
(2730 records); IDs/values must fit uint16/uint32. INITIAL_WINDOW_SIZE is
0..2147483647, MAX_FRAME_SIZE 16384..16777215, and ENABLE_PUSH,
ENABLE_CONNECT_PROTOCOL, NO_RFC7540_PRIORITIES use 0/1. HEADER_TABLE_SIZE is at
most 1048576 and MAX_HEADER_LIST_SIZE at most 16777216: the protocol leaves both
open, and the transport sizes its HPACK decoder and its header-list limit by
them, so these are the engine's bounds on what a server can make a client keep
(HTTP/3's QPACK table has the same 1048576 in the behavior registry). Every
shipped and catalogue identity asks for 65536 and 262144 at most. Unknown IDs
retain their uint32 value. Repeated IDs are valid in the protocol, but this map-backed adapter
explicitly rejects their unsupported sequential representation; it never merges
them. Duplicate JSON keys, including Go-equivalent case/Unicode spellings, null
or non-integer numeric fields and out-of-range weights/IDs fail with field paths.

Client stream IDs are odd31-bit values; `stream_id:0` selects the existing
initial stream1. Standalone priorities need room for the request after their
final stream. Dependencies are31-bit and cannot refer to the same live stream. A fixed
client-stream dependency must precede the first request, so later requests
cannot become their own dependencies; nearest-weight derives live dependencies.
`header_priority.stream_id` is capture annotation; live request IDs come from
connection state. `connection_flow` is an increment to the initial65535-byte
connection window, in0..2147418112. Explicit zero sends no WINDOW_UPDATE;
INITIAL_WINDOW_SIZE zero likewise means a zero receive window, without fallback.
Legal extreme values are tested on a raw H2 peer that decodes original bytes.

The existing HTTP3 registry limits remain authoritative: GREASE payloads up to
4096 bytes and long SETTINGS vectors cannot block QUIC's run loop or Close.
The small setup prefix keeps its synchronous composition; any remainder is
written on a cancellable setup goroutine before request streams are released.
No browser profile values or version markers changed in A6. These are protocol
and resource controls, not a fresh browser-equivalence measurement.

## Capturing one

The current `chrome` alias resolves to `chrome_156_macos`, `chrome_156_linux` or
`chrome_156_windows` for the host platform. These schema4/engine1 profiles retain
exact native headed capture bytes and separate field provenance under
`profile/provenance/chrome_156/`. Unmeasured behavior remains inherited from155.
The [A8 acceptance report](remediation/2026-10-29/A8.ru.md) records per-platform
builds, hashes, native fixtures and bounded H3 evidence. It does not certify
every inherited timer or policy. Profiles151–154 remain historical captures.

```bash
tls-forge capture --save my-chrome.json
```

The command launches two independent browser processes, each with a fresh
throwaway profile directory. One makes a direct top-level navigation to the
local HTTP/1.1-only TLS listener; the other independently navigates to the
HTTP/2 listener. Starting both measurements cold prevents one navigation from
changing the other's `Sec-Fetch-*` context and records each protocol directly
instead of deriving one from the other. The command combines the observations,
prints a summary and writes the profile.

```bash
tls-forge capture --browser edge --save my-edge.json
tls-forge capture --browser /path/to/chrome --headless --save headless.json
tls-forge capture --json > raw-capture.json
```

The name is derived from the user-agent — `chrome_151` or `edge_151`, for
example — unless you pass `--name`. Every Chromium-based browser puts
`Chrome/` in its user-agent, so the ones with their own token are checked first;
otherwise they would all come out named `chrome`.

### Headless

`--headless` was measured to send the same TLS and HTTP structure: same JA4,
same HTTP/2 fingerprint and same header order. Chrome still identifies the mode
in its user-agent as `HeadlessChrome`, so a strict comparison against a headed
profile reports a `header_values` difference. It is not the default because the
browser being impersonated is a headed one. Use headless runs as an automated
structural drift signal, or capture a dedicated headless profile when a strict
headless match is the intended identity.

## Using one

```go
data, err := os.ReadFile("my-chrome.json")
p, err := profile.Load(data)

client, err := tlsforge.New(tlsforge.WithProfileValue(p))
```

Or register it under a name and refer to it like any other:

```go
profile.Register(p)
client, err := tlsforge.New(tlsforge.WithProfile(p.Name))
```

A registered profile wins over a shipped one with the same name — someone who
captures their own Chrome should get theirs.

A file in the local profile directory also deliberately wins by name. If that
file is invalid, resolution reports its path and parse error rather than
silently wearing a shipped or catalogue identity under the requested name.

## Name resolution

`WithProfile` resolves in this order:

1. profiles registered at runtime
2. profiles in this machine's user profile directory
3. profiles shipped in `profile/data/<version>/<platform>.json`
4. an exact name from the catalogue of [tls-client](https://github.com/igor-lemon/tls-client/tree/tls-forge), tls-forge's fork of bogdanfinn/tls-client
5. a **family name** — `chrome`, for example — meaning the newest measured member
   of that family

Rule 5 is why `WithProfile("chrome")` keeps meaning the current Chrome after the
next capture instead of pinning whichever one was current when the code was
written. The exact name is always available when you want to pin.

Measured profiles beat newer catalogue entries in that resolution, on purpose: a
catalogue entry for a later Chrome still carries no headers of its own, so
resolving `chrome` to it would trade a complete impersonation for a
handshake-only one, quietly, at the moment the catalogue moved ahead.

`tls-forge profiles` lists everything, measured first.

## What a profile does not carry

Per-request headers are stripped when a profile is built:

```
cookie          belongs to the jar; a captured one pins a dead session
host            derived from the URL
content-*       describe a body this request may not have
referer/origin  describe where the captured click came from, not this one
cache-control   present only because the capture navigation was a reload;
pragma          an ordinary visit sends neither
```

`sec-fetch-*` is deliberately kept: it describes the *kind* of request — a
document navigation — which is what a profile is for. For a subresource fetch,
override the values that differ and use a custom profile without fields the
browser would omit, such as `sec-fetch-user`.

## Capture candidates and policy provenance

`FromCapture(name, capture, basis)` requires exactly one complete executable
schema4 basis with explicit `per_connection` rules and matching engine major.
The old two-argument call returns an error. It does not select policy from a
name, User-Agent, brand, platform or catalogue preset. Only observed fields
replace basis data; missing fields remain inherited. TLS randoms, keys and
session state are rebuilt by the engine under the basis generation rules.

`capture --save` and `--install` use this same builder. `--policy-from` accepts
an explicit profile or file. The CLI default selects the newest shipped full
profile for the observed family/platform, and refuses if none exists.
`--provenance-dir` chooses a separate metadata destination; the default nested
provenance subtree is excluded from profile discovery. Keep provenance outside
`profile/data` when preparing shipped profiles. Provenance binds the exact
saved profile bytes by SHA-256, plus canonical JSON hashes of the basis and
capture, and distinguishes measured, inherited, generated/stateful and explicit
caller values. Browser mode comes from launch flags, not a rewritten UA.

UA persona hints are merged only when observed. Device/network/viewport and
preference observations stay in raw evidence; capture does not freeze them
into new defaults. An inherited value is not a new measurement. Repeated
browser/wire acceptance is required separately before promoting a candidate.

## Refusing a resumed capture

`FromCapture` refuses a capture taken over a resumed connection. Such a hello
carries `pre_shared_key`, so its JA4 is not the one a server sees on first
contact, and a profile built from it would match the browser about half the
time. The echo server does not issue session tickets by default, so this should
never happen — the check is there because the failure it prevents looks like
success.

The hello's own bytes decide: a `pre_shared_key` is a resumed connection's,
whether it parses or not, whatever the capture says. A capture that says
something of its hello, its JA4 and `session_resumed`, is held to it, and one
that says otherwise is refused as not one capture; one that says nothing is
read from the bytes alone.

A profile resumes all the same. `Spec` ends the spec of a hello that offers
`psk_key_exchange_modes` with the `pre_shared_key` slot a resumed hello has,
last, which utls fills only on a connection with a session to resume: the
first connection to a site is the capture, and the next one is the browser
coming back.

## Keeping profiles current

A browser update is when an impersonation silently stops being true. For a
strict check, compare against a headed browser:

```bash
tls-forge compare --profile chrome
```

An unattended `tls-forge compare --headless --profile chrome` still checks the
TLS, HTTP/1.1 and HTTP/2 structure, but may exit 3 solely because
`HeadlessChrome` differs from the headed profile's user-agent. Keep that check
informational unless the selected profile was itself captured headless.

It exits 3 when the fingerprints no longer match (`1` means the comparison
could not be completed). When they differ:

```bash
tls-forge capture --save profile/data
```

Headed, not `--headless`. A headless capture records `HeadlessChrome` as its
user-agent, and committing one here would make every library user impersonate
headless Chrome by default — which is a browser almost nobody browses with, and
so a signal rather than a disguise. The committed profiles are headed for
exactly this reason; capture a dedicated headless profile only when a headless
identity is the one you want.

Commit the new file. Nothing else needs changing: the family name resolves to
the newest measured profile, and the old one stays available for pinning.

The committed profiles are diffable JSON on purpose — an updated profile shows
up in review as the fields that changed, not as one very long line.


Schema 4 requires an explicit `behavior` object and makes profile identity
metadata independent of behavior selection. The example above is abbreviated;
start with a complete shipped profile when editing a browser identity. See
[Profile behavior](profile-behavior.md) for the strict field reference, supported
primitives, legacy migration and the difference between a data update and a new
engine capability. TCP capture does not measure QUIC or all session policies;
newly captured profiles state their inherited compatibility policy explicitly.

Raw `WithTransportOption(WithClientProfile(...))` overrides are refused before transport creation; use `WithProfile` or `WithProfileValue` with explicit `engine_major`.


The current engine1 candidate also requires explicit generated H3 SETTINGS
placement in executable profiles. See `h3.grease_setting_placement` in the
[behavior reference](profile-behavior.md#http3-generated-setting-placement-unreleased-engine1).
Old archives remain inspectable without adding that choice automatically.
