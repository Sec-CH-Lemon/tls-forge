package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// secret is a password that must turn up in nothing a run writes down.
const secret = "s3cret-never-shown"

// countingTLS is a TLS server that counts what it is asked.
func countingTLS(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var asked atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		_, _ = fmt.Fprint(w, "the page")
	}))
	t.Cleanup(server.Close)
	return server, &asked
}

// hostOfURL is the host and port of a URL, as a CONNECT names it.
func hostOfURL(t *testing.T, raw string) string {
	t.Helper()
	return strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
}

func TestProxyEnvNamesTheProxy(t *testing.T) {
	// The URL comes from the variable, password and all, and goes nowhere
	// else: not the command line, which `ps` shows every user of the machine.
	server, asked := countingTLS(t)
	var heard []string
	proxy := startProxyHearing(t, func(int, []string) string { return "" })
	proxy.heard = func(fields []string) { heard = append(heard, fields...) }
	t.Setenv("RUN_PROXY", "http://alice:"+secret+"@"+proxy.addr)

	code, stdout, stderr := exec(t, "fetch", "-k", "--proxy-env", "RUN_PROXY", server.URL)
	if code != 0 || stdout != "the page" {
		t.Fatalf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
	if !slices.Contains(proxy.seen(), hostOfURL(t, server.URL)) || asked.Load() != 1 {
		t.Errorf("the request did not go through the proxy: %v", proxy.seen())
	}
	credentials := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+secret))
	if !slices.Contains(heard, credentials) {
		t.Errorf("the proxy was not told who was asking: %v", heard)
	}
	if strings.Contains(stderr, secret) {
		t.Errorf("stderr says the proxy's password:\n%s", stderr)
	}
}

func TestProxyEnvIsReadOnlyWhenNamed(t *testing.T) {
	// A variable that happens to be set sends a run nowhere it was not told.
	server, asked := countingTLS(t)
	proxy := startProxy(t)
	t.Setenv("TLSFORGE_PROXY", "http://"+proxy.addr)
	if code, stdout, stderr := exec(t, "fetch", "-k", server.URL); code != 0 || stdout != "the page" {
		t.Fatalf("exit code = %d, stdout = %q\n%s", code, stdout, stderr)
	}
	if seen := proxy.seen(); len(seen) != 0 || asked.Load() != 1 {
		t.Errorf("the run went through a proxy nobody named: %v", seen)
	}
}

func TestProxyEnvRefusals(t *testing.T) {
	t.Setenv("RUN_PROXY_EMPTY", "")
	t.Setenv("RUN_PROXY_SET", "http://alice:"+secret+"@127.0.0.1:1")
	server, asked := countingTLS(t)
	for _, command := range [][]string{
		{"fetch", "-k", "-o"},
		{"daemon"},
		{"proxy", "--addr", "127.0.0.1:0", "--ca-cert"},
	} {
		for _, tc := range []struct {
			args []string
			says string
		}{
			{[]string{"--proxy-env"}, "flag needs an argument: --proxy-env"},
			{[]string{"--proxy-env="}, "--proxy-env needs the name of an environment variable"},
			{[]string{"--proxy-env", "RUN_PROXY_NOT_SET"}, "--proxy-env RUN_PROXY_NOT_SET: there is no such environment variable"},
			{[]string{"--proxy-env", "RUN_PROXY_EMPTY"}, "--proxy-env RUN_PROXY_EMPTY: the variable is empty"},
			{[]string{"--proxy-env", "RUN_PROXY_SET", "--proxy", "http://127.0.0.1:2"},
				"--proxy and --proxy-env both name the proxy: give one of them"},
			{[]string{"--proxy", "http://127.0.0.1:2", "--proxy-env", "RUN_PROXY_SET"},
				"--proxy and --proxy-env both name the proxy: give one of them"},
		} {
			// Before anything is asked, made or written: the output directory
			// and the authority are not made, and the server is asked nothing.
			dir := t.TempDir()
			args := append(slices.Clone(command), tc.args...)
			switch command[0] {
			case "fetch":
				args = slices.Insert(args, 3, filepath.Join(dir, "out"))
				if !strings.HasSuffix(tc.args[len(tc.args)-1], "--proxy-env") {
					args = append(args, server.URL)
				}
			case "proxy":
				args = slices.Insert(args, 4, filepath.Join(dir, "ca.pem"))
			}
			code, _, stderr := exec(t, args...)
			if code != 2 || !strings.Contains(stderr, tc.says) || strings.Contains(stderr, secret) {
				t.Errorf("%q: exit code = %d, want 2 and %q\n%s", args, code, tc.says, stderr)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("%q made %v", args, entries)
			}
		}
	}
	if got := asked.Load(); got != 0 {
		t.Errorf("the server was asked %d times", got)
	}
}

// refusingProxy is a proxy that answers every CONNECT with 407, as one does to
// a password it does not know.
func refusingProxy(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				_, _ = fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			}()
		}
	}()
	return listener.Addr().String()
}

// nowhereSaid fails the test if the secret is in anything under dir, or in
// what the run said.
func nowhereSaid(t *testing.T, dir string, said ...string) {
	t.Helper()
	for i, text := range said {
		if strings.Contains(text, secret) {
			t.Errorf("stream %d says the password:\n%s", i, text)
		}
	}
	files := 0
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		files++
		data, err := os.ReadFile(path)
		if strings.Contains(string(data), secret) {
			t.Errorf("%s says the password", path)
		}
		return err
	})
	if err != nil || files == 0 {
		t.Fatalf("walking %s: %v, %d files", dir, err, files)
	}
}

func TestAProxysPasswordIsWrittenNowhere(t *testing.T) {
	server, _ := countingTLS(t)

	// One that will not parse is refused before the run, as a usage error,
	// without its password, and nothing is written.
	for _, proxy := range []string{"http://alice:" + secret + "@[bad", "alice:" + secret + "@proxy.test:8080"} {
		dir := t.TempDir()
		t.Setenv("RUN_PROXY", proxy)
		code, stdout, stderr := exec(t, "fetch", "-k", "--proxy-env", "RUN_PROXY",
			"--log", filepath.Join(dir, "run.jsonl"), "--trace", filepath.Join(dir, "trace.json"), server.URL)
		if code != 2 || !strings.Contains(stderr, "tlsforge: bad usage: --proxy-env RUN_PROXY: ") ||
			strings.Contains(stdout+stderr, secret) {
			t.Errorf("%s: exit code = %d, want 2 and the proxy refused without its password\n%s", proxy, code, stderr)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s: written: %v", proxy, entries)
		}
	}

	// One that turns the password away, for every request and the question
	// of where it comes out: the lines, every file kept of every request,
	// both reports, the log and the trace.
	dir := t.TempDir()
	t.Setenv("RUN_PROXY", "http://alice:"+secret+"@"+refusingProxy(t))
	code, stdout, stderr := exec(t, "fetch", "-k", "--proxy-env", "RUN_PROXY", "--json",
		"-o", filepath.Join(dir, "out"), "--log", filepath.Join(dir, "run.jsonl"),
		"--trace", filepath.Join(dir, "trace.json"), "--report="+filepath.Join(dir, "report"),
		"--report-format", "html,json", "--retry", "1", server.URL, server.URL+"/two")
	if code != 1 || !strings.Contains(stdout, "407") {
		t.Errorf("exit code = %d, want 1 and the proxy's refusal\n%s\n%s", code, stdout, stderr)
	}
	nowhereSaid(t, dir, stdout, stderr)
}
