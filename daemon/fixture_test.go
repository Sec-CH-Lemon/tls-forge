package daemon

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateFixtures = flag.Bool("update", false, "rewrite the protocol fixtures")

// The fixture values. Deliberately exercising every field, including the ones
// whose absence is meaningful, so that a rename or a retype of any of them
// changes the file.
func fixtureResponse() Response {
	return Response{
		ID:           7,
		Status:       200,
		URL:          "https://example.com/after-redirect",
		Body:         "AP7/gA==",
		BodyEncoding: BodyBase64,
		Headers: map[string][]string{
			"content-type": {"text/html; charset=utf-8"},
			"set-cookie":   {"a=1", "b=2"},
		},
		Cookies: []string{"a=1", "b=2"},
	}
}

// Text is a separate fixture because absence is part of the protocol: old
// readers must keep seeing the same response shape for ordinary UTF-8 bodies.
func fixtureTextResponse() Response {
	return Response{
		ID:     8,
		Status: 200,
		URL:    "https://example.com/text",
		Body:   "plain text — unchanged",
		Headers: map[string][]string{
			"content-type": {"text/plain; charset=utf-8"},
		},
		Cookies: []string{},
	}
}

func fixtureRequest() Request {
	return Request{
		ID:           7,
		Method:       "POST",
		URL:          "https://example.com/",
		Headers:      map[string]string{"accept": "*/*"},
		Order:        []string{"accept"},
		Body:         "AP7/gA==",
		BodyEncoding: BodyBase64,
		SetCookie:    []string{"a=1"},
	}
}

// TestProtocolFixture pins the wire format the Python and Node clients parse.
//
// Both of those suites run against hand-written fakes and never against the
// real binary, so nothing else in the repository compares what Go emits with
// what they expect. A rename of a response field used to pass every gate —
// `go test`, `make node-test`, `make python-test` — and ship a release in which
// Python callers silently received no cookies at all.
//
// The same two files are asserted against by python/tests/test_protocol.py and
// node/test/protocol.test.js, so one rename now breaks all three.
func TestProtocolFixture(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"response.json", fixtureResponse()},
		{"response-text.json", fixtureTextResponse()},
		{"request.json", fixtureRequest()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.MarshalIndent(tc.value, "", "  ")
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			encoded = append(encoded, '\n')

			path := filepath.Join("..", "testdata", "protocol", tc.name)
			if *updateFixtures {
				if err := os.WriteFile(path, encoded, 0o644); err != nil {
					t.Fatalf("writing the fixture: %v", err)
				}
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading the fixture: %v", err)
			}
			if string(encoded) != string(want) {
				t.Errorf("the wire format changed.\n got:\n%s\nwant:\n%s\n\n"+
					"If this is deliberate, update every implementation of the "+
					"protocol — python/src/tlsforge/_client.py and node/index.js — "+
					"and then regenerate with:\n"+
					"    go test ./daemon/ -run TestProtocolFixture -update",
					encoded, want)
			}
		})
	}
}

// TestProtocolFixtureRoundTrips checks the fixtures are what the Go decoder
// reads back, so they cannot drift into being merely a file this test writes.
func TestProtocolFixtureRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name         string
		id           uint64
		bodyEncoding string
	}{
		{"response.json", 7, BodyBase64},
		{"response-text.json", 8, ""},
	} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "protocol", tc.name))
		if err != nil {
			t.Fatalf("reading %s: %v", tc.name, err)
		}
		var got Response
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal %s: %v", tc.name, err)
		}
		if got.ID != tc.id || got.Status != 200 || got.BodyEncoding != tc.bodyEncoding {
			t.Errorf("decoded %s does not match the fixture: %+v", tc.name, got)
		}
	}

	data, err := os.ReadFile(filepath.Join("..", "testdata", "protocol", "request.json"))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.BodyEncoding != BodyBase64 || req.Method != "POST" {
		t.Errorf("decoded request does not match the fixture: %+v", req)
	}
}
