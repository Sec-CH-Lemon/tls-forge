package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Sec-CH-Lemon/tls-forge/internal/proctree"
)

// create is os.Create, which a test makes fail.
var create = os.Create

// Chrome is the Browser at Path, run as the fixtures were measured: headless,
// in English, each example.com and example.net name the bench serves taken to
// the loopback address, and its certificate taken on trust.
type Chrome struct {
	Path string
}

// flags are the browser's arguments for a profile in dir.
func flags(dir string) []string {
	return []string{
		"--headless=new",
		"--ignore-certificate-errors",
		"--host-resolver-rules=MAP *.example.com 127.0.0.1, MAP *.example.net 127.0.0.1",
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-default-apps",
		"--lang=en-US",
		"--accept-lang=en-US",
	}
}

// Open runs the browser at url until stop is called, or ctx is done, and
// either ends every process it started.
func (c Chrome) Open(ctx context.Context, url, dir string) (func(), error) {
	cmd := exec.CommandContext(ctx, c.Path, append(flags(dir), url)...)
	proctree.Own(cmd)
	cmd.Cancel = func() error { return proctree.Kill(cmd.Process) }
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("harness: launching %s: %w", c.Path, err)
	}
	return func() {
		_ = proctree.Kill(cmd.Process)
		_ = cmd.Wait()
	}, nil
}

// DumpDOM runs the browser at url with --dump-dom in a profile made for it,
// and is what it wrote. A browser that fails, or does not end before ctx does,
// dumped nothing to go by. What it writes goes to a file, not a pipe: a pipe
// would keep the dump waiting on whatever it started that holds it open.
func (c Chrome) DumpDOM(ctx context.Context, url string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "tls-forge-harness-")
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out, err := create(filepath.Join(dir, "dump.html"))
	if err != nil {
		return nil, fmt.Errorf("harness: %w", err)
	}
	defer func() { _ = out.Close() }()
	profile := filepath.Join(dir, "profile")
	cmd := exec.CommandContext(ctx, c.Path, append(flags(profile), "--dump-dom", url)...)
	proctree.Own(cmd)
	cmd.Cancel = func() error { return proctree.Kill(cmd.Process) }
	cmd.Stdout = out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("harness: launching %s: %w", c.Path, err)
	}
	err = cmd.Wait()
	// What it started may outlive it: a renderer still closing.
	_ = proctree.Kill(cmd.Process)
	if err != nil {
		return nil, fmt.Errorf("harness: %s --dump-dom %s: %w", c.Path, url, err)
	}
	return os.ReadFile(out.Name())
}
