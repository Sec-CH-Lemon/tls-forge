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
