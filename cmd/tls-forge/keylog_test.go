package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// siteKeys are the secrets a site wrote of its connections, written to from
// the server's goroutines.
type siteKeys struct {
	mu   sync.Mutex
	text strings.Builder
}

func (k *siteKeys) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.text.Write(p)
}

func (k *siteKeys) lines() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return keyLines(k.text.String())
}

// keyLines are the lines of a key log, sorted.
func keyLines(text string) []string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if strings.TrimSpace(text) == "" {
		lines = nil
	}
	slices.Sort(lines)
	return lines
}

// keyedSite is a site over TLS and HTTP/2 that writes its own secrets to keys
// and answers each request with its number.
func keyedSite(t *testing.T, keys io.Writer) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "answer-%d", asked.Add(1))
	}))
	// At [::1] too: a SOCKS proxy is asked for it by localhost
	// (TestFetchKeepsTheHandshakeWithASOCKSProxyInACapture).
	atLocalhost(t, server)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{KeyLogWriter: keys}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &asked
}

func TestFetchWritesTheSecretsOfEveryConnectionToItsKeyLog(t *testing.T) {
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	dir := t.TempDir()
	path, log := filepath.Join(dir, "keys", "run.keys"), filepath.Join(dir, "run.json")
	code, stdout, stderr := exec(t, "fetch", "--fresh-connection", "--insecure", "--no-exit-lookup", "--keylog", path, "--log", log,
		"--repeat", "2", server.URL)
	if code != 0 || stdout != "answer-1answer-2" {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	// Each try on a connection of its own, the second resuming the first's
	// session: two handshakes, four secrets each, the site's own.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no key log: %v", err)
	}
	if got, want := keyLines(string(data)), keys.lines(); len(want) != 8 || !slices.Equal(got, want) {
		t.Errorf("the run wrote\n%s\nthe site\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the key log is %v, %v", info.Mode(), err)
		}
	}
	// The run says where they go, and its log does.
	if !strings.Contains(stderr, "  keylog      "+path+" · the TLS secrets of every connection") {
		t.Errorf("the run does not say where its secrets go:\n%s", stderr)
	}
	if run := recordsOf(logRecords(t, log), "run"); len(run) != 1 || run[0].get("keylog") != path {
		t.Errorf("the log's run record: %v", run)
	}
	// Added to, as browsers add to the file SSLKEYLOGFILE names.
	if code, _, stderr := exec(t, "fetch", "--fresh-connection", "--insecure", "--no-exit-lookup", "--keylog", path, server.URL); code != 0 {
		t.Fatalf("exit code = %d\n%s", code, stderr)
	}
	data, _ = os.ReadFile(path)
	if got, want := keyLines(string(data)), keys.lines(); len(want) != 12 || !slices.Equal(got, want) {
		t.Errorf("a second run left %d lines, the site wrote %d", len(got), len(want))
	}
	// A run that asks for none writes none, and says nothing of one.
	if code, _, stderr := exec(t, "fetch", "--fresh-connection", "--insecure", "--no-exit-lookup", server.URL); code != 0 ||
		strings.Contains(stderr, "keylog") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
}

func TestFetchWritesTheSecretsOfTheConnectionThatAsksWhereItComesOut(t *testing.T) {
	// The address service is asked over a connection of its own, before the
	// run, and its secrets go to the file with the site's.
	var keys siteKeys
	server, _ := keyedSite(t, &keys)
	service := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9"}`))
	}))
	service.TLS = &tls.Config{KeyLogWriter: &keys}
	service.StartTLS()
	t.Cleanup(service.Close)
	original := ipServices
	t.Cleanup(func() { ipServices = original })
	ipServices = []addressService{{URL: service.URL, read: readJSON}}

	path := filepath.Join(t.TempDir(), "run.keys")
	code, stdout, stderr := exec(t, "fetch", "--exit-lookup", "--exit-lookup", "--insecure", "--keylog", path, server.URL)
	if code != 0 || stdout != "answer-1" || !strings.Contains(stderr, "203.0.113.9") {
		t.Fatalf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no key log: %v", err)
	}
	if got, want := keyLines(string(data)), keys.lines(); len(want) != 8 || !slices.Equal(got, want) {
		t.Errorf("the run wrote\n%s\nthe site and the service\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFetchRefusesAKeyLogItCannotKeep(t *testing.T) {
	// Before anything is cleared, opened or asked: exit code 2.
	server, asked := keyedSite(t, io.Discard)
	dir := t.TempDir()
	path := filepath.Join(dir, "same")
	for _, tc := range []struct {
		name string
		args []string
		says string
	}{
		{"on a stream", []string{"--keylog", "-"}, "--keylog takes a file: TLS secrets go to no stream"},
		{"in the log's file", []string{"--keylog", path, "--log", path}, "--keylog"},
		{"a directory", []string{"--keylog", dir}, "--keylog"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := exec(t, append(append([]string{"fetch", "--insecure"}, tc.args...), server.URL)...)
			if code != 2 || !strings.Contains(stderr, tc.says) {
				t.Errorf("exit code = %d\n%s", code, stderr)
			}
		})
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused run made %s: %v", path, err)
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("a refused run asked %d times", got)
	}
}

func TestFetchKeyLogThatCannotBeWritten(t *testing.T) {
	server, asked := keyedSite(t, io.Discard)
	original := openKeyLogFile
	t.Cleanup(func() { openKeyLogFile = original })
	path := filepath.Join(t.TempDir(), "run.keys")

	// Said once, when the run is over, and the run made all the same.
	openKeyLogFile = func(string) (io.WriteCloser, error) { return unwritableLog{}, nil }
	code, stdout, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--keylog", path, server.URL)
	if code != 1 || stdout != "answer-1" ||
		!strings.Contains(stderr, "tlsforge: fetch: writing the key log "+path+": disk full") {
		t.Errorf("exit code = %d\n%s\n%s", code, stdout, stderr)
	}

	// Nor when it cannot be closed.
	openKeyLogFile = func(string) (io.WriteCloser, error) {
		return &closingBuffer{closeErr: errors.New("closed twice")}, nil
	}
	if code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--keylog", path, server.URL); code != 1 ||
		!strings.Contains(stderr, "writing the key log "+path+": closed twice") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}

	// Nor opened at all, which stops the run before it asks anybody anything.
	before := asked.Load()
	openKeyLogFile = func(string) (io.WriteCloser, error) { return nil, errors.New("no such device") }
	if code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--keylog", path, server.URL); code != 1 ||
		!strings.Contains(stderr, "tlsforge: fetch: no such device") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != before {
		t.Errorf("a run with no key log asked %d times", got-before)
	}
	openKeyLogFile = original

	// Nor its directory made.
	if runtime.GOOS == "windows" {
		return
	}
	notRoot(t)
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if code, _, stderr := exec(t, "fetch", "--insecure", "--no-exit-lookup", "--keylog",
		filepath.Join(locked, "keys", "run.keys"), server.URL); code != 1 || !strings.Contains(stderr, "permission denied") {
		t.Errorf("exit code = %d\n%s", code, stderr)
	}
	if got := asked.Load(); got != before {
		t.Errorf("a run with no key log asked %d times", got-before)
	}
}
