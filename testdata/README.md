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
