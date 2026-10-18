Raw ClientHello records captured from Google Chrome 151.0.7922.138 on macOS 26.6 (arm64),
by `tls-forge capture` against the local echo server. Used as a golden fixture:
its JA4 is t13d1516h2_8daaf6152771_806a8c22fdea, which tls.browserleaks.com
reported independently for the same browser.

`chrome155-clienthello.bin` and `chrome155-clienthello-resumed.bin` are two
connections of one launch of Google Chrome 155.0.8059.40 on macOS 27.0.1
(arm64), captured on 2026-10-15 against the local echo server with session
tickets on (`echo.WithSessionTickets(true)`). The first is the cold navigation,
JA4 t13d1517h2_8daaf6152771_cb7bf5808d99. The second is the connection Chrome
opened for the capture page's fetch() once it held a ticket: it resumes, with
JA4 t13d1518h2_8daaf6152771_e2d80978ab2e, and differs from the first by one
extension, pre_shared_key, last. Only the records are kept; what the page's
JavaScript reported about the machine is not.

`chrome155-http2-preamble.bin` is what Google Chrome 155.0.8059.80 on macOS
27.0 (arm64), headless, sent on a new HTTP/2 connection to the local echo
server from the end of its preface to the end of its first request's header
block, a navigation to `/?http1=done` on 2026-10-16: SETTINGS, WINDOW_UPDATE
and HEADERS with its priority, as the bytes went. Its user agent says
HeadlessChrome; nothing that compares it reads the value.

`chrome155-ech.json` is how Google Chrome 155.0.8059.80 on macOS 27.0 (arm64)
draws the length of the payload of its GREASE encrypted_client_hello
extension: two series on 2026-10-16, 301 connections in all, each launch with
a fresh user-data-dir at the local echo server. Every length was one of 144,
176, 208 and 240 bytes, as often as the others; the cipher suite and the
32-byte key never changed.

`chrome155-decoding.json` is how Google Chrome 155.0.8059.80 on macOS 27.0.1
(arm64), headless and in English, decoded 174 bodies on 2026-10-16: each
served over plain HTTP from a local server with the `Content-Type` given and
opened at the top level in a fresh profile with `--dump-dom`. Each case has
the body, the bytes of a word in it, and that word as Chrome decoded it; for
HTML, a script in the page wrote `document.characterSet` and the word's
`textContent` into the title. The cases are what `--html-decoding browser` is
held to: byte order marks, charsets in the `Content-Type`, `<meta>` and XML
declarations wherever Chrome stops looking for them, `@charset`, JSON, XML,
feeds, plain text and bodies with no type.

`chrome155-connections.json` is which connection Google Chrome 155.0.8059.80
on macOS 27.0.1 (arm64), headless and in English, sent each request on, for 22
scenarios over HTTP/2 and over HTTP/1.1, measured on 2026-10-17 and found the
same in a second run that day: a page, then its `fetch()` and XHR of each
credentials mode to its own origin, another origin of its site and another
site, in cors and no-cors mode, CORS preflights, a navigation, redirects to
another site, and connections the server ended after an answer. Each request
is kept as in `chrome155-requests.json`, with the connection it came on,
numbered from the page's in the order requests first came on them, and whether
that connection resumed a TLS session. Chrome took the local server's
certificate as a site's, by its key (`--ignore-certificate-errors-spki-list`),
and opened each page from another, two seconds after that one had loaded: it
closes its idle connections whenever its certificate verifier is told
something new, several times as it starts. Chrome kept the
requests that carried no credentials, every preflight among them, on
connections of their own, which resumed only TLS sessions of their own, and
over HTTP/2 sent a request with credentials to another name on the page's
connection.

`chrome155-requests.json` is what Google Chrome 155.0.8059.80 on macOS 27.0.1
(arm64), headless and in English, sent on 2026-10-16 and 2026-10-17 for 172
scenarios, over HTTP/2 and over HTTP/1.1: navigations typed and from pages
under each referrer policy, to and from `http://localhost`, forms posted and
sent by GET, `fetch()` and XHR of every mode and credentials, CORS
preflights allowed, refused and cached, SameSite cookies, redirects (of
every status, typed and from pages, through another site and back, to plain
HTTP, under a `Referrer-Policy` a redirect set, through CORS with preflights
again, to URLs with credentials, and the chain Chrome gives up on), the
client hints a server asked for with `Accept-CH` (every one, a few, emptied,
replaced, on a redirect, from forms, `fetch()` and XHR, and to other
origins) and said it needs with `Critical-CH`, and HTTP authentication with
the credentials in a URL (Basic, and Digest of every algorithm and `qop`
Chrome knows, with an opaque, a hashed username, a nonce out of date once,
later and every time, challenges it cannot read, several at once, NTLM and
Negotiate offered before it, and the realm's later pages). A local
server answered www.example.com and api.example.com (one site) and
www.example.net (another), mapped to 127.0.0.1, and localhost, and kept each
request's headers in order with their values, the priority of its HTTP/2
HEADERS frame, and its body. The pages that ran the scenarios are left out,
as are the port numbers.
