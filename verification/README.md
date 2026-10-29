# Transport fork regression gates

The A6 gate is F09 stage1: a full-suite regression boundary with named old debt.
It does not close F09 stage2 or establish Chrome/RFC equivalence.

`fork-failures.json` pins all four source commits. Every known test/subtest has
its baseline evidence hash, cause/class, remaining obligation and repeat command.
A passing repetition does not remove that obligation. New failing names,
unrecognized diagnostic families or complete diagnostic transcripts, build failures, panic/timeout/race, incomplete
package execution and missing QUIC self integration reject the gate.

Run on macOS with `sandbox-exec`, from the owner root and an exact Git checkout:

```sh
python3 -m unittest discover -s scripts -p test_fork_gate.py
python3 scripts/fork_gate.py --fork fhttp --source /path/to/fhttp \
  --graph standalone --output /private/tmp/fhttp-standalone
python3 scripts/fork_gate.py --fork fhttp --source /path/to/fhttp \
  --graph production --output /private/tmp/fhttp-production
```

Repeat for `utls`, `tls-client`, `quic-go-utls`. Keep runs sequential on a shared
host. The fhttp root package runs alone, with at least45seconds between root
runs. Only `TestOmitHTTP2` is skipped, per the owner's fork contract; its
replacement obligation remains open. The tool records its end timestamp beside
the output directories. Do not run another fhttp root suite manually during it.

Both graphs use the exact root go.mod toolchain. Standalone retains the fork's
own module requirements. Production pins the module versions actually linked
into the owner's CLI/library. Its complete owner graph, linked subset and tested
fork graph are saved in module-graphs.json; test/tool-only additions are visible.
Making every latent `go list -m all` tool dependency direct would change lazy
graph pruning, rather than reproduce the product's dependency graph. No local
replace is used in the product or the test overlay.

The tool archives committed source (dirty checkout files are excluded), hydrates
dependencies, then runs all packages inside a verified loopback-only sandbox.
External-host tests run and fail visibly; their named environment exceptions
require unchanged-source reproduction. In particular, TestWeb cannot issue its
external registration POST. The macOS policy also denies sendfile in an old
file-copy fixture; the unconfined body-copy obligation is not measured by that
exception. Test JSONL/stderr, source archive, module graphs and result.json remain
in the output directory. Keep raw test evidence private as repository policy
requires; archive publication requires a separate review.

CI (`.github/workflows/forks.yml`) uses a separate runner per fork/graph and
runs on the macOS27 reference image (`xcode-27`). Its unchanged loopback-only policy
must pass both a real IPv4-mapped UDP loopback exchange and external IPv4/mapped
denial probes before any suite runs. Native macOS26 produced sendmsg EPERM for
these owned dual-stack loopback tests; the macOS15 positive preflight also
rejected the host before any suite ran. Both are preserved as unsupported
measurement environments, not added to the109 debt exceptions. The gate
runs on main/development only when `go.mod`, `go.sum`, `verification/` or
`scripts/fork_gate.py` change, or by hand; it cancels obsolete runs. Its raw
evidence stays on the runner by default, and its log has the gate's summary
line. An explicit diagnostic dispatch may select `forks`/`graphs` JSON lists
and supply `evidence-certificate` (base64 PEM public certificate). Only then
does it upload CMS-encrypted `fork-private-<fork>-<graph>` evidence, including
the original failed JSONL, source and module graphs. Keep the corresponding
private key and decrypted evidence private. Gate assertions, transcript
digests, exclusions and sandbox rules are unchanged. Exact fork commits and pseudo-versions
must be available remotely before these jobs can execute there. Locally sealed
module artifacts demonstrate installation without a replace; they do not prove
publication or remote CI.

See the [A6 report](../docs/remediation/2026-10-27/A6.ru.md) for the retained
before/after controls and acceptance limits.

Each observed known failure also pins a SHA-256 of its diagnostic transcript
for each module graph. Exact Go harness metadata is omitted; source-export
roots, loopback port numbers and matching resolver IPs in a sandbox-denied
DNS dial are normalized. DNS host, port 53, UDP and the denial reason stay
literal; changing any of them is rejected. Full diagnostic lines are
sorted with duplicates retained. Added, repeated or changed diagnostics reject
the gate even when the original failure pattern is still present. The private
source-pinned baselines and their hashes are listed in `fork-failures.json`. A
known failure without an observed transcript rejects the gate if it returns,
until its output is reviewed. This does not close any F09 obligation.

The control-frame flood fixture emits a supporting Framer trace with live
timestamps, object addresses and a scheduling-dependent number of repeated
PING events. Those timestamps/addresses and repeat multiplicities are not
assertion diagnostics. Distinct complete frame values remain in the digest;
`trace_counts` in the private result preserves every event count. Additional
core diagnostics, changed frame fields or unknown trace lines still reject
the gate. No raw Framer values are printed in its public summary.

Go Framer timestamps may omit fractional seconds when that fraction is zero.
Both timestamp forms use the same bounded normalization; malformed timestamps
and every distinct frame value remain part of the diagnostic comparison.

Only the clock prefix of the exact QUIC socket-buffer warning is normalized.
Its capacities, text, URL and multiplicity remain exact. A reviewed native26
transcript adds the observed768/7168/6144KiB warning to the existing ALPN-debt
case; the core assertion matches its previous digest. Other sizes, messages or
test failures still reject. No debt obligation is removed or added.

The official `xcode-27` hosted image is listed in GitHub runner-images. The
pinned actionlint1.7.12 registry predates that label; `.github/actionlint.yaml`
adds only this exact label. Unknown-label negative controls still reject.
