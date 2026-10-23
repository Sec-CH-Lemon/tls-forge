package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v6/cookie"
)

// program is this test binary started as tls-forge, so that a signal sent to
// it meets the program's own handling of it rather than the test runner's.
func program(t *testing.T, args ...string) *osexec.Cmd {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("nothing sends SIGTERM on Windows")
	}
	cmd := osexec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), asProgram+"=1")
	return cmd
}

// ended waits for the program to end, within a bound, and is how it did.
func ended(t *testing.T, cmd *osexec.Cmd, within time.Duration) syscall.WaitStatus {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(within):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the program had not ended %v after it was told to", within)
	}
	return cmd.ProcessState.Sys().(syscall.WaitStatus)
}

// told sends the program SIGTERM.
func told(t *testing.T, cmd *osexec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling: %v", err)
	}
}

// reached waits for the server to say a path was reached.
func reached(t *testing.T, asked <-chan string, path string) {
	t.Helper()
	for deadline := time.After(10 * time.Second); ; {
		select {
		case got := <-asked:
			if got == path {
				return
			}
		case <-deadline:
			t.Fatalf("%s was never asked for", path)
		}
	}
}

// logged waits for the log to say something.
func logged(t *testing.T, path, text string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if data, _ := os.ReadFile(path); strings.Contains(string(data), text) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the log never said %q", text)
		}
	}
}

// hanging is a server that answers /fast at once, with a cookie, and holds
// /headers before its header fields and /body half way through its body, with
// a cookie of its own, until the test is over. Each says on asked when it is
// reached.
func hanging(t *testing.T) (*httptest.Server, <-chan string) {
	t.Helper()
	asked := make(chan string, 16)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fast":
			http.SetCookie(w, &http.Cookie{Name: "fast", Value: "1", Path: "/"})
			_, _ = fmt.Fprint(w, "fast")
			return
		case "/body":
			http.SetCookie(w, &http.Cookie{Name: "body", Value: "2", Path: "/"})
			w.Header().Set("content-length", "1000")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, strings.Repeat("x", 500))
			w.(http.Flusher).Flush()
		}
		asked <- r.URL.Path
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server, asked
}

func TestFetchStopsOnSIGTERMWithWhatItHas(t *testing.T) {
	// As at Ctrl-C: the request in flight is cancelled and said to be, no other
	// is made, and the run ends with its report, its session and the end of its
	// trace written.
	for _, tc := range []struct {
		name    string
		paths   []string
		held    string
		cookies []string
	}{
		{"waiting for the header fields", []string{"/headers"}, "/headers", nil},
		{"waiting for the body", []string{"/body"}, "/body", []string{"body"}},
		{"part way through a list", []string{"/fast", "/fast", "/headers", "/fast"}, "/headers", []string{"fast"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, asked := hanging(t)
			dir := t.TempDir()
			trace, report, session := filepath.Join(dir, "trace.json"), filepath.Join(dir, "report.json"),
				filepath.Join(dir, "session.json")
			log := filepath.Join(dir, "run.log")
			args := []string{"fetch", "--concurrency", "1", "--progress", "never", "--trace", trace,
				"--report=" + report, "--save-cookies", session, "--log", log}
			for _, path := range tc.paths {
				args = append(args, server.URL+path)
			}
			cmd := program(t, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("starting: %v", err)
			}
			reached(t, asked, tc.held)
			if tc.held == "/body" {
				// The cookie comes with the header fields, and is the session's
				// once the client has read them, which the log says.
				logged(t, log, "Set-Cookie: body=***")
			}
			told(t, cmd)
			if status := ended(t, cmd, 10*time.Second); status.ExitStatus() != 1 {
				t.Errorf("exit status %v\n%s", status, stderr.String())
			}

			if events := traceFile(t, trace); events[len(events)-1].Phase != phaseEnd {
				t.Errorf("the trace does not end the run: %+v", events[len(events)-1])
			}
			// A list stopped part of the way says how far it got.
			made := fmt.Sprintf("Requests %d of %d", slices.Index(tc.paths, tc.held)+1, len(tc.paths))
			if said := strings.Join(strings.Fields(stderr.String()), " "); len(tc.paths) > 1 && !strings.Contains(said, made) {
				t.Errorf("stderr does not say %q:\n%s", made, stderr.String())
			}
			doc := decoded(t, []byte(reportOf(t, report)))
			last := doc.Requests[len(doc.Requests)-1]
			if len(doc.Requests) != slices.Index(tc.paths, tc.held)+1 || !strings.HasSuffix(last.URL, tc.held) ||
				!strings.Contains(last.Error, "context canceled") {
				t.Errorf("the report has %d requests, the last %+v", len(doc.Requests), last)
			}
			var saved []string
			if data, err := os.ReadFile(session); err == nil {
				file, err := cookie.Load(data)
				if err != nil {
					t.Fatalf("the session: %v", err)
				}
				for _, c := range file.Sets[0].Cookies {
					saved = append(saved, c.Name)
				}
			}
			if !slices.Equal(saved, tc.cookies) {
				t.Errorf("the session holds %v, want %v", saved, tc.cookies)
			}
		})
	}
}

func TestASecondSignalEndsTheRunAtOnce(t *testing.T) {
	// The first asks for an orderly stop, which waits here on standard output:
	// nobody reads it, and the page does not fit in the pipe. The second ends
	// the run where it stands.
	served := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4<<20))
		close(served)
	}))
	t.Cleanup(server.Close)
	cmd := program(t, "fetch", server.URL)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("a pipe: %v", err)
	}
	t.Cleanup(func() { _ = stdout.Close() })
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}
	<-served
	time.Sleep(200 * time.Millisecond)
	told(t, cmd)
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the first signal ended a run it could not stop in order: %v", err)
	}
	told(t, cmd)
	if status := ended(t, cmd, 5*time.Second); !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Errorf("exit status %v, want ended by the second SIGTERM", status)
	}
}

func TestFetchWaitingForAListStopsOnSIGTERM(t *testing.T) {
	// Standard input is a pipe that stays open and says nothing.
	cmd := program(t, "fetch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("a pipe: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close() })
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}
	time.Sleep(time.Second)
	told(t, cmd)
	if status := ended(t, cmd, 5*time.Second); status.ExitStatus() != 1 ||
		!strings.Contains(stderr.String(), "tlsforge: context canceled") {
		t.Errorf("exit status %v\n%s", status, stderr.String())
	}
}

// daemonRunning is the daemon started as the program, once it has said what it
// is wearing, with its input and its output.
func daemonRunning(t *testing.T) (*osexec.Cmd, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	cmd := program(t, "daemon")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("a pipe: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close() })
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("a pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("a pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting: %v", err)
	}
	// What it is wearing is said once it is listening for signals: it reads
	// its flags only after main has asked for them.
	said := bufio.NewReader(stderr)
	for {
		line, err := said.ReadString('\n')
		if err != nil {
			t.Fatalf("the daemon said nothing of what it is wearing: %v", err)
		}
		if strings.Contains(line, "user-agent") {
			break
		}
	}
	go func() { _, _ = io.Copy(io.Discard, said) }()
	return cmd, stdin, bufio.NewReader(stdout)
}

func TestTheDaemonStopsOnSIGTERM(t *testing.T) {
	t.Run("waiting for a request", func(t *testing.T) {
		cmd, _, _ := daemonRunning(t)
		told(t, cmd)
		if status := ended(t, cmd, 5*time.Second); status.ExitStatus() != 0 {
			t.Errorf("exit status %v", status)
		}
	})
	t.Run("with a request in flight", func(t *testing.T) {
		// The request is cancelled, and answered with why before the daemon
		// ends, so that whoever asked is not left waiting for it.
		server, asked := hanging(t)
		cmd, stdin, stdout := daemonRunning(t)
		if _, err := fmt.Fprintf(stdin, `{"engine_major":6,"id":1,"url":%q}`+"\n", server.URL+"/headers"); err != nil {
			t.Fatalf("writing: %v", err)
		}
		reached(t, asked, "/headers")
		told(t, cmd)
		line, err := stdout.ReadString('\n')
		if err != nil {
			t.Fatalf("no answer: %v", err)
		}
		var answer struct {
			ID    int    `json:"id"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &answer); err != nil || answer.ID != 1 ||
			!strings.Contains(answer.Error, "context canceled") {
			t.Errorf("answered %q", line)
		}
		if status := ended(t, cmd, 5*time.Second); status.ExitStatus() != 0 {
			t.Errorf("exit status %v", status)
		}
	})
}
