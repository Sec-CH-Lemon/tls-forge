# Profiles

A profile is one browser build, described completely enough to impersonate it,
stored as JSON so it can be committed and reviewed.

```json
{
  "name": "chrome_151",
  "user_agent": "Mozilla/5.0 (Macintosh; …) Chrome/151.0.0.0 Safari/537.36",
  "client_hello": "FgMBBvgBAAb0AwPdnWafT…",
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
  "notes": "captured 2026-08-15T09:12:44Z from Mozilla/5.0 …"
}
```

`client_hello` is a real ClientHello, base64'd, recorded off the wire. It is the
authoritative field; everything else was read from the same connection.

## Capturing one

```bash
tls-forge capture --save my-chrome.json
```

A browser opens with a throwaway profile directory, loads a page from a local
HTTPS server, reports what JavaScript can see, and shows the result. The command
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

## Name resolution

`WithProfile` resolves in this order:

1. profiles registered at runtime
2. profiles in this machine's user profile directory
3. profiles shipped in `profile/data/<version>/<platform>.json`
4. an exact name from the [tls-client](https://github.com/bogdanfinn/tls-client) catalogue
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
document navigation — which is what a profile is for. Override it for
subresource fetches.

## Refusing a resumed capture

`FromCapture` refuses a capture taken over a resumed connection. Such a hello
carries `pre_shared_key`, so its JA4 is not the one a server sees on first
contact, and a profile built from it would match the browser about half the
time. The echo server does not issue session tickets by default, so this should
never happen — the check is there because the failure it prevents looks like
success.

## Keeping profiles current

A browser update is when an impersonation silently stops being true. For a
strict check, compare against a headed browser:

```bash
tls-forge compare --profile chrome
```

An unattended `tls-forge compare --headless --profile chrome` still checks the
TLS and HTTP/2 structure, but may exit 3 solely because `HeadlessChrome` differs
from the headed profile's user-agent. Keep that check informational unless the
selected profile was itself captured headless.

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
