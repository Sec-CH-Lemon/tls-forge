# Protocol fixtures

`response.json`, `response-text.json`, `response-error.json` and
`request.json` are three encoded `daemon.Response` values and one
`daemon.Request`, as they travel between the Go daemon and the Python and Node
clients. The responses pin both sides of the body contract — binary uses
`bodyEncoding: "base64"`, while ordinary text keeps the old shape with no
`bodyEncoding` field — and the shape every failure has: `error` set, the id
intact, and `headers` and `cookies` null. A session whose jar holds nothing
answers with `"cookies": []`.

The responses are what the daemon's own `handle` writes for a request, given
what the transport answered, rather than values written out by hand: a
hand-written fixture once pinned `[]` where the daemon sent `null`, and no
failure was pinned at all.

They exist because the protocol is implemented three times — the Go structs in
`daemon/daemon.go`, `python/tests/fake_daemon.py` and `node/test/fake-daemon.js`
— and the Python and Node suites run against their own fakes, never against the
real binary. Renaming a field in Go therefore passed `go test`, `node-test` and
`python-test` alike, and shipped a release where every Python caller silently
got `response.cookies == ()` on every request.

Each language asserts its own parser against these files, so a rename now breaks
all three at once. Regenerate deliberately, never to make a test pass:

    go test ./daemon/ -run TestProtocolFixture -update
