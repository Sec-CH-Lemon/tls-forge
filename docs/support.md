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
| ClientHello of a first connection: record layer, versions, session id length, cipher suites, compression methods, extension set, supported groups, key shares and the length of each key, signature algorithms, ALPN, ALPS, certificate compression, the IDs of `trust_anchors`, ECH's cipher suite and key, the contents of every extension that is the same on each connection, JA4 | checked | `tls-forge compare`; `TestEveryComparedTLSFieldCatchesAChange` changes a real Chrome hello once for each field compared and holds the comparison to finding it; `TestTheHelloHasChromesShapeColdAndResumed` holds a client's hellos to the Chrome 155 captures |
| Extension order shuffled on every connection | checked | `TestExtensionOrderIsShuffledLikeChrome`: six connections, more than one order; `compare` compares the extension set, since Chrome varies the order itself |
| GREASE values fresh on every connection, where Chrome puts them and with Chrome's correlations (first in every list it greases, two extensions first and last, the group in `supported_groups` the one in `key_share`, two different extension values) | checked | `tls-forge compare` compares where GREASE goes; `TestGREASEIsDrawnForEveryHelloWhereChromePutsIt` over sixteen hellos |
| GREASE `encrypted_client_hello` payload length drawn on every connection, from 144, 176, 208 and 240 bytes, each as likely; cipher suite, key and config id fresh too | checked | measured on Chrome 155 over 301 connections (`testdata/chrome155-ech.json`); `TestHelloAfterHelloDrawsItsOwnECH` over 256 hellos and `TestEveryConnectionDrawsItsECHLengthColdOrResumed` over cold and resumed connections. Only Chromium was measured: a profile of another browser keeps the length it was captured with |
| ClientHello of a resumed connection (`pre_shared_key` last, one identity, a 32-byte binder) | checked | held to `testdata/chrome155-clienthello-resumed.bin`, field by field |
| 0-RTT early data, and using a session ticket once | not checked | |
| HTTP/2 SETTINGS, connection WINDOW_UPDATE, PRIORITY frames, priority on HEADERS, pseudo-header order (the Akamai fingerprint) and the pseudo-headers' values but `:path` and `:authority` | checked | `tls-forge compare`; `TestCompareHTTP2` changes each field once and holds the comparison to finding it |
| Header order and values of a top-level navigation (GET, no body), HTTP/2 and HTTP/1.1, including HTTP/1.1 spelling and the request's method and version | checked | `tls-forge compare`; `TestCompareHTTP1` as `TestCompareHTTP2` |
| `cookie` on a navigation | differs | over HTTP/2 Chrome sends it before `priority`; tls-forge after |
| A navigation typed or from a page, a form's GET and POST, `fetch()` and an XHR to their own origin, and `fetch()` in no-cors mode, sent with `Request.Browser` or `fetch --request-kind`: each kind's headers, order and values, `Sec-Fetch-*`, `Origin`, `Referer` under every referrer policy, the HTTP/2 `HEADERS` weight, and the cookies SameSite and credentials let through | checked | measured on Chrome 155 over HTTP/2 and HTTP/1.1 (`testdata/chrome155-requests.json`); `TestABrowserContextSendsWhatChromeSent` sends 31 of its scenarios and holds every header, value but the user agent, priority, body and cookie to Chrome's |
| POST, form submissions, `fetch()` and XHR without `Request.Browser` | differs | sent with a navigation's headers, as tls-forge always has; give them a browser context |
| The order of several headers a script set on `fetch()` or an XHR | not modelled | Chrome's follows the hash table its renderer keeps them in, and changes with the set of names; one such header is placed exactly, several in the order given |
| `fetch()` and XHR on the connections a page opened | differs | they go out on connections of their own, with Chrome's HTTP/2 weight for them, 220, which the transport sets per connection pool; Chrome sends them on the page's |
| CORS for `fetch()` and an XHR in a browser context: the preflight a method or header asks for, its headers, nothing more when it is refused, its answer kept as long as `Access-Control-Max-Age` says for the session, and the check of the answer, credentials and all | checked | measured on Chrome 155: simple requests to the same site and another, preflights allowed, refused and cached, `X-Foo` asked about, credentials included, omitted and kept to the origin (`testdata/chrome155-requests.json`); `TestABrowserContextSendsWhatChromeSent` holds the whole sequence of each to Chrome's, and the CORS tests every rule of the check |
| CORS without a browser context | not modelled | tls-forge sends the request itself, with no preflight, as it always has |
| What a page reads of an answer CORS filters | differs | tls-forge returns every header and the body; a page sees only the headers CORS exposes, and nothing of a `no-cors` answer |
| Redirects, of a request with a browser context too | differs | tls-forge adds `Referer` with the redirecting URL and keeps the first hop's header order; Chrome sends no `Referer` after a direct navigation is redirected and moves its `sec-ch-ua` headers. tls-forge gives up after 10 redirects, Chrome after 20 |
| Client hints asked for with `Accept-CH` or `Critical-CH` | not modelled | the profile's headers are sent as they are, and a request is never retried for hints |
| Response bodies decoded from gzip, x-gzip, deflate (zlib or raw), br and zstd, in the reverse of the order applied; a coding Chrome does not know passed through; a zstd window over 8 MiB refused | checked | `TestABodyIsDecodedFromEveryCodingChromeAccepts` and the tests beside it, over HTTP/1.1 and HTTP/2, through the proxy, `fetch` and both SDKs |
| A saved session keeps each cookie's scope (its host's alone or its domain's), a session cookie without an expiry, and `SameSite`; a cookie lives at most 400 days | checked | `TestASessionComesBackWithEachCookiesScope` and the jar tests beside it |
| The text a page check reads with `--html-decoding browser`: the encoding Chrome decodes a document of its type in, by its byte order mark, its `Content-Type`, then in HTML an XML declaration and over it a `<meta>` before the page leaves its head and is a kilobyte in, in XML its declaration, in CSS an `@charset`, else UTF-8 for XML and JSON and windows-1252; XML read only to the first byte its encoding has nothing for | checked | measured on Chrome 155 with 174 bodies (`testdata/chrome155-decoding.json`); `TestBrowserDecodingIsChromes` reads each and holds the reading to Chrome's. `legacy`, the default, reads UTF-8 as UTF-8 whatever a page names |
| The encoding Chrome guesses for HTML, CSS and text that name none | not modelled | Chrome finds windows-1251 or GBK from the bytes; `--html-decoding browser` reads such a page as windows-1252, as Chrome reads undeclared UTF-8 |
| `SameSite` and partitioned cookies enforced when a request is sent | not modelled | `SameSite` is kept and written down; every cookie the jar holds for a URL goes to it |
| The frames before the first request and their flags, acknowledgements aside; the records the ClientHello came in | checked | `tls-forge compare` reads the frames the echo server keeps; `TestTheFirstRequestGoesOutInChromesFrames` holds them to `testdata/chrome155-http2-preamble.bin` |
| HPACK of the first request: each field indexed or not, its name from which table, each string Huffman-coded or not | checked | `tls-forge compare`; `TestTheFirstRequestGoesOutInChromesFrames` |
| HPACK of `:path` | differs | Chrome writes it without indexing, its name from the static table's first `:path`; tls-forge's transport indexes it, with the name of the second. `tls-forge compare` reports it |
| HPACK of later requests on a connection, against the dynamic table the first left | not checked | only a connection's first request is measured |
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
local server, and prints every difference it finds, after what it measured:
the browser's build, platform and mode, and the requests compared. A run with
no differences says so; the rows above marked "differs" or "not modelled" are
not part of what it compares, and `--json` carries the rule each field was
compared by.
