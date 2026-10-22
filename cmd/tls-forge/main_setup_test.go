package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/igor-lemon/fhttp/http2"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
)

// The variables a test sets for this binary started as the program: that it
// is to be the program, and where the address service it asks is.
const (
	asProgram       = "TLSFORGE_TEST_AS_PROGRAM"
	serviceVariable = "TLSFORGE_TEST_ADDRESS_SERVICE"
	sayFrames       = "TLSFORGE_TEST_SAY_FRAMES"
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
//
// And it is tls-forge itself when a test starts this binary to send it a
// signal (asProgram): with the suite's profile directory and address service,
// which the test that started it has, and nothing of the suite run.
func TestMain(m *testing.M) {
	retryWait = func(int) time.Duration { return 0 }
	// Cores enough for any test, and no cgroup quota under them: a machine
	// whose quota is under the four a list runs at warns on every list, and a
	// test that is about the count sets its own.
	numCPU = func() int { return 64 }
	cgroupRoot = filepath.Join(os.TempDir(), "tls-forge-test-no-cgroup", "absent")

	if os.Getenv(asProgram) == "1" {
		profile.Default.SetDir(os.Getenv("TLSFORGE_PROFILES"))
		ipServices = []addressService{{URL: os.Getenv(serviceVariable), read: readJSON}}
		if os.Getenv(sayFrames) == "1" {
			// Last, on standard error: whether the transport was ever told to say
			// what frames it reads.
			exit = func(code int) {
				fmt.Fprintf(os.Stderr, "frames %v\n", http2.VerboseLogs)
				os.Exit(code)
			}
		}
		main()
		return
	}
	// On for the whole suite, before any test opens a connection, which every
	// test that reads the frames out of a log needs: a test may not turn it on
	// once another's connections are reading it.
	wantFrames()

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
	_ = os.Setenv(serviceVariable, service.URL)

	code := m.Run()
	service.Close()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
