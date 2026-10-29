package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestCapturePolicyAndProvenanceReachSavedProfile(t *testing.T) {
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome_155_macos"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	saved, path, err := saveProfile(dir, "a8_candidate", measured, true, nil, "chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(captureProvenancePath(dir, path, saved, ""))
	if err != nil {
		t.Fatal(err)
	}
	var provenance profile.CaptureProvenance
	if err = json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.BasisName != "chrome_155_macos" || provenance.Fields["behavior.tls.close_notify"].Class != "inherited" {
		t.Fatal("provenance missing/invented")
	}
	registry := profile.NewRegistry()
	registry.SetDir(dir)
	for _, name := range registry.Names() {
		if strings.HasPrefix(name, "provenance") {
			t.Fatal("provenance became runnable profile")
		}
	}
	if _, err := profile.Load(data); err == nil {
		t.Fatal("metadata executable as profile")
	}
	// Metadata names stay confined to the selected profile root.
	other := t.TempDir()
	escape := t.TempDir()
	if err = os.Symlink(escape, filepath.Join(other, "provenance")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = saveProfile(other, "safe", measured, true, nil, "chrome_155_macos"); err == nil {
		t.Fatal("provenance escaped os.Root")
	}
	entries, err := os.ReadDir(escape)
	if err != nil || len(entries) != 0 {
		t.Fatal("escaped write")
	}
}

func TestCaptureJSONWithSaveKeepsOneDocumentAndExactProvenance(t *testing.T) {
	dir, metadata := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	code, stdout, stderr := exec(t, "capture", "--json", "--browser", browserStandIn(t), "--timeout", "30s", "--save", path, "--policy-from", "chrome_155_macos", "--provenance-dir", metadata)
	if code != 0 {
		t.Fatalf("capture: %d: %s", code, stderr)
	}
	var measured map[string]any
	if err := json.Unmarshal([]byte(stdout), &measured); err != nil {
		t.Fatal(err)
	}
	if measured["raw_client_hello"] == nil || !strings.Contains(stderr, "wrote profile") {
		t.Fatal("JSON/progress streams mixed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := profile.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(captureProvenancePath(path, path, saved, metadata))
	if err != nil {
		t.Fatal(err)
	}
	var provenance profile.CaptureProvenance
	if err := json.Unmarshal(raw, &provenance); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if provenance.ProfileSHA256 != hex.EncodeToString(sum[:]) || provenance.BrowserMode != "headed" {
		t.Fatal("provenance does not bind exact saved bytes/mode")
	}
}

func TestCaptureRejectsBadPolicyBeforeStartingBrowserOrListener(t *testing.T) {
	for _, args := range [][]string{
		{"--policy-from", "chrome_155_macos"}, {"--provenance-dir", t.TempDir()},
		{"--manual", "--save", t.TempDir(), "--policy-from", "missing_basis"},
	} {
		code, _, stderr := exec(t, append([]string{"capture"}, args...)...)
		if code == 0 || strings.Contains(stderr, "waiting for a browser") || strings.Contains(stderr, "opening a browser") {
			t.Fatalf("premeasurement gate: %v: %d %s", args, code, stderr)
		}
	}
	basis, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	basis.EngineMajor = profile.Major(0)
	data, err := basis.Save()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := exec(t, "capture", "--manual", "--save", t.TempDir(), "--policy-from", path)
	if code == 0 || !strings.Contains(stderr, "engine") || strings.Contains(stderr, "waiting for a browser") {
		t.Fatalf("old policy: %d %s", code, stderr)
	}
}
