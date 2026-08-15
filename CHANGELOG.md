# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

A note specific to this project: **a new profile is not a breaking change, but a
changed default profile can be.** `WithProfile("chrome")` resolves to the newest
measured Chrome, so adding a profile for a newer browser changes what that name
means. Pin the exact name — `WithProfile("chrome_151")` — when that matters.

## [Unreleased]

### Added

- Licensed under Apache-2.0, with `NOTICE` and a generated
  `THIRD-PARTY-NOTICES.txt`. The published binaries are statically linked, so
  every dependency travels inside them and its licence requires the copyright
  notice to travel too; `make notices` regenerates the file from what is
  actually linked.
- Installable with Homebrew from `Sec-CH-Lemon/homebrew-tap`, updated by the
  release workflow. Note that current Homebrew requires
  `brew trust --formula` for any tap outside its own repositories.
- Release assets are `.tar.gz` archives carrying the binary together with
  `LICENSE`, `NOTICE` and `THIRD-PARTY-NOTICES.txt`, rather than a bare binary
  beside loose licence files.
- Published to npm on a pushed `v*` tag. The binary reaches users as a
  platform-specific optional dependency — `@sec-ch-lemon/tls-forge-<platform>-<arch>`
  — so installing needs no Go, downloads nothing, and works under
  `npm ci --ignore-scripts`.
- A Dockerfile: Alpine plus the static binary, about 30 MB, running as a
  non-root user and carrying the licence notices. CI builds the image and runs
  the binary inside it, since nothing else in the repository would notice a
  Dockerfile that stopped working.
- `tls-forge capture` — launch the installed browser, measure what it sends, and
  write a reusable profile from it.
- `tls-forge compare` — measure the browser and the library against one local
  instrument and diff them, exiting 1 on a difference so it can gate a release.
- `tls-forge fetch`, `serve`, `daemon`, `profiles`.
- `fingerprint` — ClientHello parsing and local JA3, JA4, JA4_r and Akamai
  HTTP/2 fingerprints, plus a structural diff that names the field that differs.
- `echo` — a local HTTPS server that records the raw ClientHello, the HTTP/2
  preamble and the header order, and reports them back as JSON.
- `profile` — browser identities as committable JSON, synthesised from a
  capture; family-name resolution (`chrome` → newest measured Chrome).
- `daemon` — the JSON-lines protocol, and a Node client in `node/`.
- A measured Chrome 151 profile (macOS, arm64), verified against
  `tls.peet.ws`: JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`, HTTP/2
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`.

### Notes

- TLS extension order is shuffled per connection by default, as Chrome does.
  Turn it off with `WithFixedExtensionOrder` when impersonating a client that
  sends a stable order, such as Firefox or Safari.
- The echo server does not issue session tickets by default, so captures are
  always the cold handshake — a resumed connection carries `pre_shared_key` and
  therefore a different JA4.
