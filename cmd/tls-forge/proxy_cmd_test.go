package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// proxyCommand is the proxy command, run until the test stops it.
type proxyCommand struct {
	addr   string
	out    *syncBuffer
	cancel context.CancelFunc
	done   chan int
	once   sync.Once
	code   int
}

// startProxyCommand runs the proxy command and returns once its whole banner is out.
//
// The banner goes on for a dozen lines after the address. A test that waited
// for the address alone and then looked at what the proxy said next took the
// rest of the banner for it: a quiet proxy failed one run in four under the
// race detector, having said nothing at all.
func startProxyCommand(t *testing.T, args ...string) *proxyCommand {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxyCommand{out: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() {
		p.done <- run(ctx, append([]string{"proxy", "--addr", "127.0.0.1:0"}, args...), p.out, p.out)
	}()
	t.Cleanup(func() { p.stop(t) })

	listening := regexp.MustCompile(`proxy listening on (\S+)`)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		select {
		case code := <-p.done:
			p.once.Do(func() { p.code = code })
			t.Fatalf("the proxy exited with %d before it was ready:\n%s", code, p.out.String())
		default:
		}
		said := p.out.String()
		if !strings.Contains(said, "Ctrl-C to stop.") {
			continue
		}
		found := listening.FindStringSubmatch(said)
		if found == nil {
			t.Fatalf("the banner ended without an address:\n%s", said)
		}
		p.addr = found[1]
		return p
	}
	t.Fatalf("the proxy never finished its banner:\n%s", p.out.String())
	return nil
}

// stop cancels the proxy and is how it exited. It waits a bounded time, so a
// proxy that ignores its context fails the test rather than wedging it.
func (p *proxyCommand) stop(t *testing.T) int {
	t.Helper()
	p.once.Do(func() {
		p.cancel()
		select {
		case p.code = <-p.done:
		case <-time.After(5 * time.Second):
			p.code = -1
			t.Error("the proxy did not stop when its context was cancelled")
		}
	})
	return p.code
}

// sendUnreadable sends the proxy something that is not a request and waits
// for it to hang up. The proxy hangs up only once it has decided what to say
// about it, so whatever it reports is reported by the time this returns.
func sendUnreadable(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "this is not a request\r\n\r\n"); err != nil {
		t.Fatalf("writing: %v", err)
	}
	// A reset is a hang-up too; only running out of time is not.
	if _, err := io.ReadAll(conn); err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("the proxy kept the connection open after a request it could not read")
		}
	}
}

func TestProxyCommandStopsWithItsContext(t *testing.T) {
	dir := t.TempDir()
	p := startProxyCommand(t, "--ca-cert", filepath.Join(dir, "ca.pem"), "--ca-key", filepath.Join(dir, "ca.key"))
	if code := p.stop(t); code != 0 {
		t.Errorf("exit code = %d", code)
	}

	// The warning about what the authority can do is not optional decoration.
	if !strings.Contains(p.out.String(), "impersonate any site") {
		t.Errorf("the authority's power was not explained:\n%s", p.out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Errorf("no authority was written: %v", err)
	}
}

func TestProxyReportsWhatItCannotRead(t *testing.T) {
	// Per-connection trouble is worth seeing by default: it is how a client
	// that speaks something else, or a proxy chain that mangles requests, is
	// found out.
	dir := t.TempDir()
	p := startProxyCommand(t, "--ca-cert", filepath.Join(dir, "ca.pem"), "--ca-key", filepath.Join(dir, "ca.key"))
	before := p.out.String()
	sendUnreadable(t, p.addr)

	said := strings.TrimPrefix(p.out.String(), before)
	if !strings.Contains(said, "proxy: reading a request") || !strings.Contains(said, "malformed") {
		t.Errorf("the proxy did not say what it could not read:\n%q", said)
	}
}

func TestProxyCommandErrors(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")

	// A file where a directory would have to go. `/no/such/root/…` was used
	// here and only fails where the root is unwritable: on Windows it resolves
	// against the current drive, the directory is created, the proxy starts,
	// and the command blocks until the test binary is killed.
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("in the way"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"proxy", "--ca-cert", filepath.Join(blocked, "ca.pem"),
			"--ca-key", filepath.Join(blocked, "ca.key")}, 1, "proxy: reading"},
		// Refused before the authority is made, as a usage error.
		{[]string{"proxy", "--ca-cert", cert, "--ca-key", key, "--profile", "netscape_4"}, 2,
			`unknown profile "netscape_4"`},
		{[]string{"proxy", "--ca-cert", cert, "--ca-key", key, "--proxy", "::not a proxy::"}, 2,
			"--proxy ::not a proxy:: is not a URL"},
		{[]string{"proxy", "--ca-cert", cert, "--ca-key", key, "--addr", "256.256.256.256:0"}, 1,
			"proxy: listen"},
	} {
		code, _, stderr := exec(t, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit code %d, stderr %q; want %d and %q", tc.args, code, stderr, tc.code, tc.want)
		}
		if tc.code == 2 {
			if _, err := os.Stat(cert); !os.IsNotExist(err) {
				t.Errorf("%v made the authority: %v", tc.args, err)
			}
		}
	}
}

func TestDefaultCAPaths(t *testing.T) {
	cert, key, err := defaultCAPaths()
	if err != nil {
		t.Fatalf("defaultCAPaths: %v", err)
	}
	// Under the user's config directory rather than the working directory, so
	// that a key this powerful is not committed by whoever runs the proxy inside
	// a repository.
	if !strings.Contains(cert, "tls-forge") || !strings.HasSuffix(cert, "ca.pem") {
		t.Errorf("certificate path = %q", cert)
	}
	if !strings.HasSuffix(key, "ca.key") {
		t.Errorf("key path = %q", key)
	}
	if filepath.Dir(cert) != filepath.Dir(key) {
		t.Error("the certificate and the key land in different directories")
	}
}

func TestProxyUsesTheConfigDirectoryByDefault(t *testing.T) {
	// Redirected at the environment so the test does not write an authority
	// into the real config directory.
	//
	// All three variables, because os.UserConfigDir reads a different one on
	// each platform: XDG_CONFIG_HOME then HOME on Linux, HOME on macOS, and
	// AppData on Windows. Setting only the first two left the Windows runner
	// writing a CA private key into the real user profile, which is what this
	// comment claims it does not do.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("AppData", home)

	// Derived the way the command derives it, rather than guessing each
	// platform's layout here, and checked to be inside the temporary directory
	// so that a variable missed on some future platform fails loudly instead of
	// quietly writing somewhere real.
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("no config directory: %v", err)
	}
	if !strings.HasPrefix(config, home) {
		t.Fatalf("config directory %s is outside %s; the redirection did not take", config, home)
	}

	p := startProxyCommand(t)
	if code := p.stop(t); code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if _, err := os.Stat(filepath.Join(config, "tls-forge", "ca.pem")); err != nil {
		t.Errorf("no authority under the config directory: %v", err)
	}
	if !strings.Contains(p.out.String(), filepath.Join(config, "tls-forge")) {
		t.Errorf("the banner does not name the authority under the config directory:\n%s", p.out.String())
	}
}

func TestProxyWithoutAConfigDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, _, err := defaultCAPaths(); err == nil {
		t.Skip("this platform finds a config directory without HOME")
	}
	if code, _, stderr := exec(t, "proxy", "--addr", "127.0.0.1:0"); code == 0 {
		t.Errorf("exit code = 0 without a config directory; stderr = %q", stderr)
	}
}

func TestProxyRejectsABadFlag(t *testing.T) {
	if code, _, _ := exec(t, "proxy", "--nonsense"); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestProxyCanBeQuiet(t *testing.T) {
	// Per-connection trouble is worth seeing by default and worth silencing on
	// a busy one, where every client that hangs up mid-request writes a line.
	// The same unreadable request TestProxyReportsWhatItCannotRead sees
	// reported: a connection that merely hangs up is reported by nobody, so it
	// could not tell a quiet proxy from a loud one.
	dir := t.TempDir()
	p := startProxyCommand(t, "--quiet", "--ca-cert", filepath.Join(dir, "ca.pem"), "--ca-key", filepath.Join(dir, "ca.key"))
	before := p.out.String()
	sendUnreadable(t, p.addr)
	if after := p.out.String(); after != before {
		t.Errorf("a quiet proxy reported a connection:\n%s", strings.TrimPrefix(after, before))
	}
}
