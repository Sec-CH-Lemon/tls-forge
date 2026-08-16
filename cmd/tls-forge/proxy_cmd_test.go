package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestProxyCommandStopsWithItsContext(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"proxy", "--addr", "127.0.0.1:0",
			"--ca-cert", filepath.Join(dir, "ca.pem"), "--ca-key", filepath.Join(dir, "ca.key")}, out, out)
	}()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if strings.Contains(out.String(), "proxy listening on") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not stop when its context was cancelled")
	}

	// The warning about what the authority can do is not optional decoration.
	if !strings.Contains(out.String(), "impersonate any site") {
		t.Errorf("the authority's power was not explained:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Errorf("no authority was written: %v", err)
	}
}

func TestProxyCommandQuiet(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"proxy", "--addr", "127.0.0.1:0", "--quiet",
			"--ca-cert", filepath.Join(dir, "ca.pem"), "--ca-key", filepath.Join(dir, "ca.key")}, out, out)
	}()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if strings.Contains(out.String(), "proxy listening on") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestProxyCommandErrors(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")

	for _, args := range [][]string{
		{"proxy", "--ca-cert", "/no/such/root/ca.pem", "--ca-key", "/no/such/root/ca.key"},
		{"proxy", "--ca-cert", cert, "--ca-key", key, "--profile", "netscape_4"},
		{"proxy", "--ca-cert", cert, "--ca-key", key, "--addr", "256.256.256.256:0"},
	} {
		if code, _, _ := exec(t, args...); code == 0 {
			t.Errorf("%v: exit code = 0, want non-zero", args)
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
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)

	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"proxy", "--addr", "127.0.0.1:0"}, out, out) }()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if strings.Contains(out.String(), "proxy listening on") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A connection the proxy cannot make sense of, so the reporting closure runs.
	addr := strings.TrimSpace(strings.SplitN(strings.SplitN(out.String(), "proxy listening on ", 2)[1], "\n", 2)[0])
	if conn, err := net.Dial("tcp", addr); err == nil {
		_, _ = io.WriteString(conn, "this is not a request\r\n\r\n")
		_ = conn.Close()
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if _, err := os.Stat(filepath.Join(home, "tls-forge", "ca.pem")); err != nil {
		if _, err2 := os.Stat(filepath.Join(home, "Library", "Application Support", "tls-forge", "ca.pem")); err2 != nil {
			t.Errorf("no authority under the config directory: %v / %v", err, err2)
		}
	}
	if !strings.Contains(out.String(), "not a request") && !strings.Contains(out.String(), "malformed") {
		t.Logf("proxy output:\n%s", out.String())
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
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"proxy", "--addr", "127.0.0.1:0", "--quiet",
			"--ca-cert", filepath.Join(dir, "ca.pem"),
			"--ca-key", filepath.Join(dir, "ca.key")}, out, out)
	}()

	listening := regexp.MustCompile(`proxy listening on (\S+)`)
	var addr string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if found := listening.FindStringSubmatch(out.String()); found != nil {
			addr = found[1]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		t.Fatalf("the proxy never started:\n%s", out.String())
	}

	// A connection that says nothing and hangs up: something for the proxy to
	// have an opinion about, which --quiet is asking it to keep.
	before := out.String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		cancel()
		t.Fatalf("dialling: %v", err)
	}
	_ = conn.Close()
	time.Sleep(200 * time.Millisecond)

	if after := out.String(); after != before {
		t.Errorf("a quiet proxy reported a connection:\n%s", strings.TrimPrefix(after, before))
	}
	cancel()
	<-done
}
