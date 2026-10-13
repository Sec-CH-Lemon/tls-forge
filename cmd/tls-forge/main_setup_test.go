package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// TestMain takes the waiting out of the suite.
//
// A failed URL is retried three times by default, and the pauses between those
// tries are seconds that most of these tests spend on something they are not
// about. TestRetryBackoff checks the schedule itself, and the one test that
// cares that a pause happens at all puts it back.
//
// It also points the profile directory at one of its own. Every command now
// reports which profile it is wearing, and that reads the directory, so without
// this the suite would answer differently on a machine that has run
// `capture --install` — measured, when a leftover profile there turned a
// warning assertion in another file red.
//
// And it answers for the address services. Every fetch asks where it comes out,
// so without a stand-in the suite would put that question to services on the
// internet once per test, from wherever the tests happen to run. Over plain
// HTTP, so a fetch that does not pass --insecure is answered as well.
func TestMain(m *testing.M) {
	retryWait = func(int) time.Duration { return 0 }

	dir, err := os.MkdirTemp("", "tls-forge-profiles-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("TLSFORGE_PROFILES", dir)
	profile.Default.SetDir(dir)

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","country":"PL"}`))
	}))
	ipServices = []addressService{{URL: service.URL, read: readJSON}}

	code := m.Run()
	service.Close()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
