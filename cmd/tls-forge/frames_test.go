package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheTransportSaysWhatFramesItReadsOnlyIntoALogThatKeepsThem(t *testing.T) {
	// Turned on for good the moment it is, and read by every connection, so
	// it is asked of a program of its own, which says at the end whether it
	// was: only a run with a log kept at the trace level turns it on, before
	// it opens a connection, and nothing else makes the transport format a
	// line about a frame for nobody.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("page"))
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
		on   bool
	}{
		{"no log", []string{"fetch", server.URL}, false},
		{"a log kept with the requests", []string{"fetch", "-o", filepath.Join(dir, "out"), server.URL}, true},
		{"a log named", []string{"fetch", "--log", filepath.Join(dir, "named.log"), server.URL}, true},
		{"a log on standard error", []string{"fetch", "--log", "-", server.URL}, true},
		{"a log of what is not traced", []string{"fetch", "--log", filepath.Join(dir, "debug.log"), "--log-level",
			"debug", server.URL}, false},
		{"the daemon", []string{"daemon"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := program(t, tc.args...)
			cmd.Env = append(cmd.Env, sayFrames+"=1")
			cmd.Stdin = strings.NewReader("")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("starting: %v", err)
			}
			if status := ended(t, cmd, 30*time.Second); status.ExitStatus() != 0 {
				t.Fatalf("exit status %v\n%s", status, stderr.String())
			}
			lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
			if want := "frames " + map[bool]string{true: "true", false: "false"}[tc.on]; lines[len(lines)-1] != want {
				t.Errorf("ended with %q, want %q\n%s", lines[len(lines)-1], want, stderr.String())
			}
		})
	}
}
