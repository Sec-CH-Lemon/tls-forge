# Protocol fixtures

`response.json` and `request.json` are one encoded `daemon.Response` and one
`daemon.Request`, byte for byte as they travel between the Go daemon and the
Python and Node clients.

They exist because the protocol is implemented three times — the Go structs in
`daemon/daemon.go`, `python/tests/fake_daemon.py` and `node/test/fake-daemon.js`
— and the Python and Node suites run against their own fakes, never against the
real binary. Renaming a field in Go therefore passed `go test`, `node-test` and
`python-test` alike, and shipped a release where every Python caller silently
got `response.cookies == ()` on every request.

Each language asserts its own parser against these files, so a rename now breaks
all three at once. Regenerate deliberately, never to make a test pass:

    go test ./daemon/ -run TestProtocolFixture -update
