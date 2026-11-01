# URL verification

`FuzzCanonicalURL` checks canonicalization idempotence and the request URL's
scheme, authority and literal origin-form target, including an empty query and
fragment removal. It splits the already serialized delimiters rather than
asking Go `net/url.Parse` to accept WHATWG userinfo or hosts. It never filters
an accepted URL because another parser dislikes it.

`testdata/whatwg-url-components.json` is the independent reference: Node
24.16.0, Ada3.4.4 and two independent fresh Chrome156.0.8078.74 headless URL
constructor runs on macOS. The follow-up IDNA cohort expands the fixture to44
cases and rechecks every case in two fresh Chrome launches. It retains original inputs, serialized components,
encoded userinfo and independently decoded credential bytes. The historical
Chrome155 navigation/wire fixture remains separate and unchanged. The pinned
standard snapshot records provenance; the [living URL Standard](https://url.spec.whatwg.org/)
remains the normative reference.

Ordinary `go test` reads the fixture with no Node or Chrome dependency. Run the
reference implementations explicitly:

```sh
node scripts/check-url-oracle.mjs
node scripts/check-url-oracle.mjs --browser /path/to/google-chrome \
  --output /private/tmp/new-url-oracle-evidence
```

The script checks the exact Node/Ada versions and compares each constructor's
result to the fixture. It does not refresh expectations automatically. Browser
version/mode and each cohort are recorded in the new private output directory.
It evaluates a local data page with external name resolution disabled; this is
constructor evidence, not a navigation, HTTP authentication or browser parity
verdict.

The declared component normalization is limited to
`base_credentials_tracked_by_chain`: WHATWG's constructor retains base
userinfo; the redirect engine holds those credentials in chain/session state,
separately from the resolved request URL. The original values are retained.
New explicit userinfo is still compared byte for byte. Actual H1/H2 tests check
credentials only after a permitted401 challenge and their absence at another
origin, including another challenge with the same realm. Target/authority,
credential-origin and preemptive-auth compiling mutations must all fail these
wire tests.

Current representation limits are explicit: a malformed percent escape in a
path and blocked ports are refused, while the backtick host accepted by
`CanonicalURL` is refused later when the HTTP request is constructed. Tests
require those paths to fail before dial. The fixture retains WHATWG's result
rather than declaring its valid input invalid. Malformed percent escapes in
userinfo and queries remain accepted where the current request path supports
them.


The corrected fuzz property has already exposed a separate runtime IDNA defect:
`http:%800` is accepted on the first pass and serialized to a punycode host
that a second pass rejects. Node/Ada and two fresh Chrome constructors reject
the original input. Its minimized corpus and raw failures are preserved in
the private A7 evidence. The follow-up runtime fix validates the percent-decoded host as UTF-8 before
IDNA. The original/minimized inputs and raw-byte control now live in the real
fuzz corpus. Invalid hosts are refused before dial, including redirects; valid
Unicode/IDNA, ignored BOM/zero-width mappings, userinfo and query escapes retain
their expected behavior. No fuzz input filter or exception was added.

Fuzzing all packages is a separate finite run, on a clean checkout or a Git
archive export so unrelated temporary Go files do not become packages:

```sh
GOWORK=off python3 scripts/fuzz.py --list
GOWORK=off python3 scripts/fuzz.py \
  --package github.com/Sec-CH-Lemon/tls-forge/fingerprint \
  --target FuzzParseClientHello --seconds 30 \
  --output /private/tmp/new-clienthello-fuzz-evidence
```

Every discovered target receives30seconds, two workers, at most1second of
minimization, a Go timeout and an outer process timeout. Successful execution
requires a positive execution count. Summary, raw log, generated interesting
inputs and failing corpus stay in the private output directory. New failures
are retained and remain failures, never allowlisted or excluded from the
property. Finite runs do not prove absence of defects.

`.github/workflows/fuzz.yml` discovers the complete target matrix, runs it
weekly on the default branch or by manual dispatch, and separately compares
Node/Ada and two fresh real Google Chrome constructors. It uploads no raw
corpus/log artifact. Its local implementation checks do not establish a remote
CI run; unpublished module pins must first become available to its runner.
