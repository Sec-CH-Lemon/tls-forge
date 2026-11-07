# Scope and limits

TLS Forge models selected browser **network** behaviour. A profile can control TLS ClientHello shape, HTTP/1.1 header casing and order, HTTP/2 settings and header order, supported HTTP/3 and QUIC choices, and selected request context and lifecycle rules. The exact covered fields depend on the profile, engine primitive and measured scenario.

## What it does not do

- It does not render HTML, run JavaScript, execute a service worker, solve a managed challenge or CAPTCHA, or reproduce a browser's DOM.
- It does not replace the host operating system's TCP/IP implementation. TCP options, routing, packet scheduling and platform network behaviour can differ.
- It does not make a request authorized by a server or remove the need to respect its access rules.
- A `User-Agent`, JA3 or JA4 match is not a complete browser match. A local `compare` success is limited to the fields and scenario it checks.
- A browser observation does not make a captured random key, ticket, stream ID, cookie or request-derived header a reusable constant.

## Read measurement claims narrowly

The development candidate includes measured and tested work on TLS, HTTP/1.1, HTTP/2, HTTP/3, DNS, proxy and lifecycle behaviour. Individual receipts record browser build, platform, network path and sample count. Historical checks for Chrome 155/macOS do not freshly prove Chrome 156, Linux, Windows, resumed sessions, HTTP/3, or every request context. The Chrome 157 profiles are captures of Google Chrome Stable on each platform; what a capture does not measure is the Chrome 156 profile's, carried over unchanged, not measured again. A passing unit test can establish an implementation property without establishing browser parity.

The maintained observation ledger is in the separate `net-fp-server` project. Historical reports and raw evidence moved out of this public documentation tree into the repository's `research/` archive; they retain their original scope. The [release status](release-status.md) distinguishes development work from published releases.

## Security-sensitive output

PCAPNG, TLS key logs, response bodies, cookies, proxy CA keys and raw captures may expose application data or decrypted traffic. Use the [diagnostic guide](../guides/diagnostics.md) to choose an output mode and retain those files according to your own data policy.
