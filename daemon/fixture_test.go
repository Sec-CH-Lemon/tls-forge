package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/v4"
)

var updateFixtures = flag.Bool("update", false, "rewrite the protocol fixtures")

// The response fixtures are what handle makes of a request, given what the
// transport answered: the daemon's own path from an answer to a line, rather
// than a Response written out here. Hand-written ones pinned "cookies": [] for
// a session that held no cookies while the daemon sent null, and pinned no
// failure at all, so renaming the field every failure travels in passed every
// gate in all three languages.
//
// Every field is exercised, including the ones whose absence is meaningful,
// so that a rename or a retype of any of them changes a file.
func fixtureResponse() Response {
	return handle(context.Background(), `{"engine_major":4,"id":7,"url":"https://example.com/"}`, &fakeClient{response: &tlsforge.Response{
		Status: 200,
		URL:    "https://example.com/after-redirect",
		Body:   []byte{0x00, 0xfe, 0xff, 0x80},
		Header: map[string][]string{
			"content-type": {"text/html; charset=utf-8"},
			"set-cookie":   {"a=1", "b=2"},
		},
		Cookies: []string{"a=1", "b=2"},
	}})
}

// Text is a separate fixture because absence is part of the protocol: old
// readers must keep seeing the same response shape for ordinary UTF-8 bodies.
// Its jar holds nothing, which the client reports as no cookies at all.
func fixtureTextResponse() Response {
	return handle(context.Background(), `{"engine_major":4,"id":8,"url":"https://example.com/text"}`, &fakeClient{response: &tlsforge.Response{
		Status: 200,
		URL:    "https://example.com/text",
		Body:   []byte("plain text — unchanged"),
		Header: map[string][]string{
			"content-type": {"text/plain; charset=utf-8"},
		},
	}})
}

// A request the transport could not make: the shape every failure has.
func fixtureErrorResponse() Response {
	return handle(context.Background(), `{"engine_major":4,"id":9,"url":"https://example.com/"}`, &fakeClient{err: errors.New(
		`tlsforge: Get "https://example.com/": dial tcp 127.0.0.1:1: connect: connection refused`)})
}

// What a daemon answers hello with: its protocol and capabilities, and no
// connection. A daemon that predates control lines answers it as
// response-hello-old.json, a request with no url.
func fixtureHelloResponse() Response {
	return handle(context.Background(), `{"engine_major":4,"id":10,"control":"hello"}`, &fakeClient{})
}

func fixtureOldHelloResponse() Response {
	return Response{ID: 10, Error: "bad request: no url"}
}

func fixtureRequest() Request {
	return Request{EngineMajor: majorForTest(),
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
		{"response-error.json", fixtureErrorResponse()},
		{"response-hello.json", fixtureHelloResponse()},
		{"response-hello-old.json", fixtureOldHelloResponse()},
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
		status       int
		bodyEncoding string
		failed       bool
	}{
		{"response.json", 7, 200, BodyBase64, false},
		{"response-text.json", 8, 200, "", false},
		{"response-error.json", 9, 0, "", true},
	} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "protocol", tc.name))
		if err != nil {
			t.Fatalf("reading %s: %v", tc.name, err)
		}
		var got Response
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal %s: %v", tc.name, err)
		}
		if got.ID != tc.id || got.Status != tc.status || got.BodyEncoding != tc.bodyEncoding ||
			(got.Error != "") != tc.failed {
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
