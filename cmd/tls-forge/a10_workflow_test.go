package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

// Old measurements describe one browser across several requests. Select that
// ownership explicitly in their JSON fixture. Ordinary exec keeps the shipped
// per-request isolation and is covered independently by A10 controls.
func execWorkflow(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	args = append([]string(nil), args...)
	name, index := defaultProfileName(), -1
	for i, arg := range args {
		if (arg == "--profile" || arg == "-p") && i+1 < len(args) {
			name, index = args[i+1], i+1
		}
		if strings.HasPrefix(arg, "--profile=") {
			name, index = strings.TrimPrefix(arg, "--profile="), i
		}
	}
	p, err := profile.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	p.Behavior["http.instance_scope"] = json.RawMessage(`"client"`)
	p.Behavior["http.cache_scope"] = json.RawMessage(`"explicit-context"`)
	data, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "workflow.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if index >= 0 {
		if strings.HasPrefix(args[index], "--profile=") {
			args[index] = "--profile=" + path
		} else {
			args[index] = path
		}
	} else {
		args = append(args, "--profile", path)
	}
	return exec(t, args...)
}
