# What tls-forge reproduces, and how far that is checked

A request that "looks like Chrome" is a claim about many separate things: the
TLS handshake, the HTTP/2 connection preamble, the order and values of every
header, what happens on a redirect, which requests go out at all, and the
TCP/IP packets underneath. This page says, for each of them, whether tls-forge
reproduces the browser, how that is checked, and where it is known not to.
Only what is marked **checked** is promised.

Draft of 2026-10-16. The shipped profiles are `chrome_151` to `chrome_155`,
each captured on macOS, Linux and Windows; the measurements behind this page
were taken with Google Chrome 155.0.8059 on macOS, against local servers.

## How a behaviour becomes "checked"

1. It is measured from a real Chrome build, against a local server that records
   what arrived byte for byte (`tls-forge serve`, `tls-forge capture`).
2. The measurement is kept, either in a profile under `profile/data/` or as a
   fixture under `testdata/`.
3. A test holds tls-forge's own output to it, and `tls-forge compare` reports
   any difference against the browser installed on the machine it runs on.

A behaviour that has not been through these steps is not claimed, however
plausible it looks.

## The matrix

| Behaviour | Status | How it is checked, or what differs |
|---|---|---|
| ClientHello of a first connection: version, cipher suites, extension set, supported groups, key shares, signature algorithms, ALPN, ALPS, certificate compression, `trust_anchors`, JA4 | checked | `tls-forge compare`; profile and fingerprint tests against the Chrome 151 and 155 captures |
| Extension order shuffled on every connection | checked | `TestExtensionOrderIsShuffledLikeChrome`: six connections, more than one order; `compare` compares the extension set, since Chrome varies the order itself |
| GREASE values fresh on every connection, with Chrome's correlations (the group in `supported_groups` is the one in `key_share`; two different extension values) | not checked | measured to match on 2026-10-16 over nine connections; no test holds it |
| GREASE `encrypted_client_hello` payload length | differs | Chrome varies it per connection (144, 176, 208 or 240 bytes); tls-forge repeats the length of the capture |
| ClientHello of a resumed connection (`pre_shared_key` last) | checked | held to `testdata/chrome155-clienthello-resumed.bin` |
| 0-RTT early data, and using a session ticket once | not checked | |
| HTTP/2 SETTINGS, connection WINDOW_UPDATE, priority on HEADERS, pseudo-header order (the Akamai fingerprint) | checked | `tls-forge compare` |
| Header order and values of a top-level navigation (GET, no body), HTTP/2 and HTTP/1.1, including HTTP/1.1 spelling | checked | `tls-forge compare` |
| `cookie` on a navigation | differs | over HTTP/2 Chrome sends it before `priority`; tls-forge after |
| POST, form submissions, `fetch()` and XHR | differs | sent with a navigation's headers (`sec-fetch-*`, `accept`, `upgrade-insecure-requests`); `content-length`, `content-type` and `origin` sit in other places than Chrome's |
| CORS preflight for a cross-origin `fetch()` or XHR | not modelled | Chrome sends `OPTIONS` first, and nothing more when it is refused; tls-forge sends the request itself |
| Redirects | differs | tls-forge adds `Referer` with the redirecting URL and keeps the first hop's header order; Chrome sends no `Referer` after a direct navigation is redirected and moves its `sec-ch-ua` headers. tls-forge gives up after 10 redirects, Chrome after 20 |
| Client hints asked for with `Accept-CH` or `Critical-CH` | not modelled | the profile's headers are sent as they are, and a request is never retried for hints |
| HPACK representations, frame and TLS record boundaries | not checked | |
| Connections: one per try by default, one per URL with `--reuse-connection` | by design | neither is a browser's pool of connections per origin; this is a choice of the command line, not a claim |
| HTTP/3 and QUIC | not supported | an `Alt-Svc` that offers HTTP/3 is ignored; requests go over HTTP/2 or HTTP/1.1 |
| TCP/IP: TTL, window, options of the first packets | not controlled | they are this machine's operating system's, whatever the profile; the run header says so when the profile's platform is another (`tcp/ip`) |
| TLS to an HTTPS proxy | not a browser's | Go's own TLS; only the proxy provider sees it, never the site |
| JavaScript, subresources, cookies set by script | not done | tls-forge makes the requests it is asked for and runs nothing |

## Platforms

The shipped profiles cover macOS, Linux and Windows. A version named without a
platform, such as `chrome_155`, is this machine's capture; on a machine none of
the three describes, it is another platform's, and the run header says so.
Android and iOS browsers, Firefox and Safari can be measured with
`tls-forge capture --manual`; nothing about them ships.

## Checking a machine of your own

```bash
tls-forge compare
```

measures the Chrome installed here and the selected profile against the same
local server, and prints every difference it finds. A run with no differences
says so; the rows above marked "differs" or "not modelled" are not part of
what it compares.
