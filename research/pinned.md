# The pinned gate

A release of tls-forge is held to Google Chrome as Google ships it: on each
platform the release workflow installs Google Chrome Stable from Google, the
build people are running that day, compares the profile with it, and goes
ahead only if they match. `go run ./internal/pinned` is the check. It is not
part of what ships.

The browser a runner image carries is no reference: it is whatever build the
image was made with, and an action that installs one often installs Chrome for
Testing, which turns on experiments real users do not have. The `browser` job
in `ci.yml` compares with it to show drift, and fails nothing. The pinned gate
installs Google Chrome itself, from Google, with the steps the behaviour job of
`drift.yml` uses
([`.github/actions/google-chrome`](../.github/actions/google-chrome/action.yml)),
and fails a release.

Nothing is archived. Google serves only its current builds, so the gate holds a
release to the Chrome of the day it runs. A release made after Chrome moved to
a new major stops at the gate until a profile of that major is measured, which
`drift.yml` proposes when it sees one. The bench holds the full version a page
asks for, `sec-ch-ua-full-version` and its list, to the profile's as well, so a
release passes when the profile was measured on the build Google serves then.

## What the check does

```bash
go run ./internal/pinned --browser PATH [--profile NAME] [--browser-arg ARG]... \
  [--out result.json] [--commit SHA] [--set DIGEST] \
  [--requests FILE] [--decoding FILE] [--scenario-timeout 45m]
```

In order, and stopping at the first that fails:

1. It reads the fixtures of what a page does, `--requests` and `--decoding`,
   `testdata/chrome155-requests.json` and `testdata/chrome155-decoding.json`
   unless said, and the profile, `--profile`, `chrome` unless said: the newest
   measured Chrome.
2. It asks the browser `--version`, and holds the answer to Google Chrome
   Stable of the major the profile's user agent says: Chrome for Testing,
   Chromium, another channel (a Beta says so after its version) or another
   major is refused, by name. On Windows, where `chrome.exe --version` starts
   the browser instead, it reads the product name and version the executable
   holds, with PowerShell.
3. It compares the profile with the browser, launched with a window and with
   the arguments `--browser-arg` gives, which are for the machine
   (`--no-sandbox` on a hosted runner), exactly as `tls-forge compare` does,
   and writes the result to `--out`: the version of Google Chrome it was held
   to, and what the result is for, the commit a release is built from
   (`--commit`, else `GITHUB_SHA`) and the identity of the release's set
   (`--set`, the SHA-256 of its `manifest.json`). A release takes a result only
   for its own commit and its own set.
4. It measures the browser on the bench in `internal/harness`, headless as the
   fixtures were measured, with the same arguments, every scenario of a page
   over HTTP/2 and over HTTP/1.1 and every page whose decoding is asked about,
   within `--scenario-timeout`, and holds it to the fixtures tls-forge is
   tested against: every request in order, its method, URL, body, HTTP/2
   priority, the names of its headers in order and spelling and their values,
   and what it made of each page. A value the machine decides (the user agent,
   the window, the memory, the network, the system's version and processor) is
   compared by its presence; estimator-generated RTT/downlink/ECT additionally
   must have canonical syntax, policy bounds/quantization and a declared ECT
   label. Availability comes from actual output of the JSON-selected generator,
   never invented captured values. One the build decides (`sec-ch-ua`, its platform,
   its full version and form factor) is held to the profile's, and each of
   either has to be one the profile has, or tls-forge would not send it. What
   differs goes to `--out` as `scenarios`, and the result does not pass.

It exits 0 only when every field compared matches, nothing is left unchecked
and the browser is what the fixtures say; 1 when anything does not hold,
saying what; 2 when it is not told where the browser is, or is given a commit
that is not 40 lower-case hex digits or a set that is not 64, before it
measures anything. A browser it cannot ask, or one that is not Google Chrome
of the profile's major, is a failure, never a reason to measure it anyway.

## In a release

The release workflow runs the check on each platform, after the release's set
is stored and before anything is published ([RELEASING.md](../RELEASING.md)):

1. `scripts/release-set.mjs gates` names the gates: macOS on arm64
   (`macos-15`), Linux on amd64 (`ubuntu-24.04`) and Windows on amd64
   (`windows-2025`).
2. `.github/actions/google-chrome` installs Google Chrome Stable from Google on
   the runner: the universal disk image on macOS, the `google-chrome-stable`
   package on Linux, the enterprise installer on Windows.
3. The check runs with `--commit` and `--set`, with `--no-sandbox` on Linux
   and Windows and under `xvfb-run` on Linux, and its result is kept in the
   tag's draft as `pinned-<platform>-<arch>.json`.
4. Each publishing job verifies the set with every gate result
   (`release-set.mjs gated`): each passed, for this commit and this set. A
   result for another commit or another set counts for nothing.

A result kept in the draft is not measured again when the release is run
again; a gate that failed is, with the Google Chrome Google serves then.

Run against Google Chrome 155.0.8059.80 on macOS, headless, the comparison
found the user agent alone, `HeadlessChrome`, which Chrome with a window does
not send: `:path` goes into HPACK as Chrome writes it, through tls-forge's fork
of fhttp ([support](support.md)). On the bench, the same Chrome is what both
fixtures say, every scenario and every page.

The fixtures were measured on macOS. Every profile of `chrome_155` has the
values of the client hints a server asks for, as Chrome sent them on its
platform (Linux's and Windows's on GitHub's runners), so Chrome on Linux or
Windows is held to its own platform's values in the scenarios that ask for
them.

## R26 release preparation (1 November2026)

The full strict run at b26bb10f retained all228H1/H2 scenarios and174decodings
on every platform. Cold TLS/H1/H2 matched on Linux/macOS/Windows. The scenario
gate found an outdated literal-only availability lookup after the estimator
migration, stale full-version hints and the previously documented Windows
NTLM/Negotiate boundary (see [support](support.md)). The release gate does not
apply the bench's platform exclusions. Those failures initially blocked the dry-run;
the auth comparison also needs a Windows reference rather than macOS bytes.

The updated availability check runs the actual declared estimator without
network I/O. Existing machine-dependent equality normalization remains; raw
values are kept. Added checks reject malformed, out-of-range, off-quantum or
undeclared ECT values. Missing generators, header order/count, method, body,
connection, build values and decoding differences keep failing. The original
`internal/harness/compare.go` is unchanged.

The result's `generated_network_hints` retains the selected noise/ECT policy,
the declared normalization, and original per-request header values, spelling
and order for every observed RTT/downlink/ECT field, including successful
checks. It does not infer RNG quality or equality of physical networks.

The optional fixture `observation_ms` maps scenario IDs to fixed observation
windows, bounded15–60s and never shorter than the original window. Only the
wait condition changes; all scene content, request capture and comparison stay
the same. The page must actually open before timing starts. The strict gate
measures the whole catalogue even with this metadata. The manual-only
[oracle workflow](../.github/workflows/release-oracle.yml) records two independent
Windows auth cohorts against the owned loopback peer, with exact source,
browser binary hash and OS version/build. Raw evidence is encrypted to the
supplied public certificate. No auth token normalization or automatic fixture
promotion is allowed. The original macOS fixture remains unchanged.

Windows auth calibration41332815788 accepted both independent cohorts on
source044c48f3, Google Chrome156.0.8078.80, Windows Server2025/10.0.26100.
Eight fresh profiles,16target requests: two per scenario/protocol/cohort.
Complete request arrays agree exactly. The Windows reference replaces only
the two auth scenarios;226common scenarios remain deeply equal to the original
macOS fixture, which is unchanged. All228request scenarios and174decodings
still run perOS. NTLM Type1 messages sent under NTLM/Negotiate are scoped environment-derived values,
compared in full, without a new normalization. This peer does not exercise
Type3 or completion of a real NTLM/Negotiate authentication exchange.

C4source98d669ef passed main30/30 but release root0 missed P1 after a fast
response. The original fixture is unchanged: official Chrome156 CreateHeaders
queues the decision before I/O, while fhttp checked after Flush. Controlled
real Client.Do raw-read-before-write-return reproduces missing P1 against
bd9be71. Local f88cd25 prepares the decision before I/O and retains the
separate PING after HEADERS; original150/400ms timers,5s deadline, record34,
P1/P2, GOAWAY and retry checks remain unchanged. Real Chrome156.80/macOS
retains the order in2cohorts x3launches after an explicit warm fetch then11s
idle on the same connection. First cold-socket closure is preserved separately;
it is not a persistent-connection PING measurement. Full fork/native acceptance
of the fix is required before release.

## The gate of another major, by hand (2026-11-07)

`capture.yml` with `gate: true` captures nothing: on each runner it installs
the browser the run asks for, Google Chrome Stable or, with `browser: 156`, the
pinned Chrome 156 installers of `verification/chrome156-installers.json`, and
holds the shipped profile of its major (`--profile chrome_<major>`, the
runner's platform) to it by `internal/pinned`, with the request fixture the
release takes for that platform. The result of each runner is the artifact
`gate-<OS>`, and a difference fails the job, as in the release. No evidence
certificate is needed: a gate keeps no raw capture.

Run 42423476026 held `chrome_156` to the installers pinned then
(156.0.8078.74, Linux .73), older than the build it says (156.0.8078.80,
Linux .79): no difference in the comparison, and on the bench only
`sec-ch-ua-full-version` and `-list`, wherever a request carries them. The
pin is the last builds of 156 since 2026-11-08: Google's update service
answers a `targetversionprefix` of `156.` with 156.0.8078.80 for macOS and
Windows, and its apt pool still holds 156.0.8078.79 for Linux. Windows is
asked for x64 (`arch` and `ap` `x64-stable`): asked without, the service gave
the 32-bit build, whose capture said `sec-ch-ua-wow64: ?1` (run 42463760501).
The same query of `156.0.8078.74` answers with the installers A8 pinned.
