# URL verification

`FuzzCanonicalURL` checks canonicalization idempotence and the request URL's
scheme, authority and literal origin-form target, including an empty query and
fragment removal. It splits the already serialized delimiters rather than
asking Go `net/url.Parse` to accept WHATWG userinfo or hosts. It never filters
an accepted URL because another parser dislikes it.

`testdata/whatwg-url-components.json` is the independent reference: Node
24.16.0, Ada3.4.4 and two independent fresh Chrome156.0.8078.74 headless URL
constructor runs on macOS. It retains original inputs, serialized components,
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
the private A7 evidence. This remains an open runtime finding; no input
filter, exception or changed expected value masks it in the fuzz target.
