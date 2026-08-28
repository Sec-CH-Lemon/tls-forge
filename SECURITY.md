# Security Policy

## Supported versions

Security fixes are provided for the latest stable release of `tls-forge`.
Older releases may be affected by issues that have already been fixed and are
not supported. Until the first stable release is published, the repository's
default branch is the supported version.

| Version | Supported |
|---|---|
| Latest stable release | Yes |
| Default branch before the first release | Yes |
| Older releases and other branches | No |

When a fix requires a release, it will be published through the normal release
channels for the CLI, Go module, Node.js package, Python package, container
image, and Homebrew formula as applicable.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue,
discussion, pull request, or social media post.

Use GitHub's private vulnerability reporting form:

<https://github.com/Sec-CH-Lemon/tls-forge/security/advisories/new>

If that form is unavailable, open a public issue titled `Security contact
request` without technical details, logs, proof-of-concept code, credentials,
or other sensitive information. A maintainer will establish a private channel
for the report.

Include the following when possible:

- the affected component and version, commit, or release artifact;
- the operating system, architecture, and runtime versions involved;
- a description of the impact and the conditions required to reproduce it;
- minimal, deterministic reproduction steps or a proof of concept;
- whether secrets, cookies, proxy credentials, certificate authority keys, or
  other sensitive data may have been exposed;
- any suggested mitigation or fix;
- how you would like to be credited, or whether you prefer to remain anonymous.

Remove real credentials, session cookies, private keys, captured user traffic,
and third-party personal data from the report. Use test values and systems you
control whenever possible.

## What to expect

The maintainers aim to:

- acknowledge a complete report within three business days;
- provide an initial severity assessment within seven business days;
- send an update at least every fourteen days while remediation is in progress;
- coordinate a disclosure date after a fix is available.

These are response targets rather than guarantees. The time required to release
a fix depends on severity, complexity, affected platforms, and coordination
with upstream projects or package registries.

Validated vulnerabilities may be handled through a private GitHub Security
Advisory. The resolution may include a patched release, updated checksums and
packages, a changelog entry, an advisory, and a CVE when appropriate. Reporters
will be credited with their consent.

## Scope

Security reports are welcome for:

- the Go library, CLI, daemon, capture server, echo server, and intercepting
  proxy;
- the Node.js and Python SDKs and their bundled native executables;
- release artifacts, packaging scripts, and publication workflows;
- profile, cookie, proxy, certificate, and JSON Lines protocol handling;
- unsafe file permissions, path traversal, command injection, request
  smuggling, credential disclosure, sandbox escape, or unintended remote code
  execution;
- supply-chain issues that affect artifacts published by this project.

The following are generally not vulnerabilities:

- a website detecting, challenging, rate-limiting, or blocking `tls-forge`;
- a fingerprint differing after a browser or server changes its behaviour;
- inability to execute JavaScript, solve CAPTCHA or managed challenges, change
  IP reputation, or reproduce browser-only APIs;
- use of explicitly unsafe options, such as disabling certificate
  verification, when they behave as documented;
- issues that require attacking systems or traffic without authorisation.

If an apparent fingerprinting bug also causes memory corruption, credential
exposure, an authentication or trust-boundary failure, or another concrete
security impact, report the security impact privately.

## Network exposure model

The echo server and intercepting proxy are local development tools, not
internet-facing services. Their defaults bind to loopback. Neither protocol
authenticates incoming clients, and the proxy can make outbound requests and
mint certificates for any hostname on behalf of every client that can reach
it. The `serve` and `proxy` commands print a warning when their resolved listen
address is not loopback.

Using `echo.WithAddr`, `proxy.Options.Addr`, or `--addr` with `0.0.0.0`, `::`, a
LAN address, or a public address is an explicit expansion of the trust
boundary. Put such a listener behind an authenticated tunnel or firewall and
allow only intended clients. Do not expose it directly to the internet.

Resource limits reduce the effect of a bad peer but are not an authentication
boundary. Idle connections expire after 30 seconds, echo HTTP/1.1 requests are
limited to 100 headers with at most 8 KiB per line, proxy request bodies are
bounded.

## Safe research guidelines

Research must be performed against systems you own or are explicitly authorised
to test. Use the local capture and echo facilities where possible. Do not:

- access, modify, retain, or disclose another person's data;
- degrade service, perform denial-of-service testing, or generate excessive
  traffic;
- use social engineering, credential stuffing, or destructive payloads;
- bypass CAPTCHA, payment, authentication, or access-control mechanisms;
- leave persistence or continue testing after discovering sensitive data.

Stop testing and report immediately if an activity could affect other users or
production availability. This project does not currently operate a bug bounty
programme, and no payment should be assumed.

The maintainers will not initiate or support legal action for good-faith
research that follows this policy. This statement cannot authorise testing of
third-party systems or override their terms, policies, or applicable law.

## Disclosure

Please allow a reasonable remediation period before publishing details. The
maintainers will work with the reporter on a disclosure timeline and will not
ask for indefinite secrecy. Once users can obtain a fix, the advisory should
describe the affected versions, impact, mitigations, and upgrade path without
exposing unrelated sensitive data.
