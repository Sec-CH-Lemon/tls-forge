package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"io"
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

func TestCapturePreparesValidatedDataAndMetadataBeforeReplacingProfile(t *testing.T) {
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome_155_macos"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(measured)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"bad-hello", "invalid-h2", "invalid-extra", "invalid-setting", "metadata-parent-file", "metadata-open-race"} {
		t.Run(scenario, func(t *testing.T) {
			var c capture.Capture
			if err := json.Unmarshal(original, &c); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "candidate.json")
			previous := []byte("previous profile bytes")
			if err := os.WriteFile(path, previous, 0600); err != nil {
				t.Fatal(err)
			}
			settings := []setting(nil)
			metadata := ""
			switch scenario {
			case "bad-hello":
				c.RawClientHello = []byte{1}
			case "invalid-h2":
				c.HTTP2.Settings = append(c.HTTP2.Settings, c.HTTP2.Settings[0])
			case "invalid-extra":
				c.Navigator = &capture.Navigator{Extra: json.RawMessage("{")}
			case "invalid-setting":
				settings = []setting{{name: "sec-ch-ua-not-observed", value: "x"}}
			case "metadata-parent-file":
				metadata = filepath.Join(dir, "metadata")
				if err := os.WriteFile(metadata, []byte("file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "metadata-open-race":
				before := openProfileRoot
				openProfileRoot = func(string) (*os.Root, error) { return nil, os.ErrNotExist }
				defer func() { openProfileRoot = before }()
			}
			if _, _, err := saveProfile(path, "candidate", &c, true, settings, "chrome_155_macos", metadata); err == nil {
				t.Fatal("invalid capture/destination accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(previous) {
				t.Fatal("invalid input replaced existing profile")
			}
		})
	}
}

func TestCaptureMetadataWriteFailureIsReported(t *testing.T) {
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome_155_macos"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	metadata := t.TempDir()
	destination := filepath.Join(metadata, "candidate", "macos.json")
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := saveProfile(filepath.Join(dir, "profile.json"), "candidate", measured, true, nil, "chrome_155_macos", metadata); err == nil {
		t.Fatal("metadata replace error ignored")
	}
	info, err := os.Stat(destination)
	if err != nil || !info.IsDir() {
		t.Fatal("atomic metadata error changed destination")
	}
}

func TestCapturePolicyAndMetadataUnknownInputs(t *testing.T) {
	if _, err := capturePolicyBasis(nil, ""); err == nil {
		t.Fatal("nil capture selected implicit basis")
	}
	path := captureProvenancePath("candidate.json", "candidate.json", &profile.Profile{Name: "neutral", UserAgent: "unknown"}, t.TempDir())
	if !strings.HasSuffix(path, filepath.Join("neutral", "unknown.json")) {
		t.Fatalf("unknown platform path %s", path)
	}
}

func TestCaptureJSONWriteErrorAndLaunchModeProvenance(t *testing.T) {
	writer := &countingWriter{fail: errors.New("capture output refused")}
	if code := run(context.Background(), []string{"capture", "--json", "--browser", browserStandIn(t), "--timeout", "30s"}, writer, io.Discard); code != 1 {
		t.Fatalf("output error exit %d", code)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	code, _, stderr := exec(t, "capture", "--browser", browserStandIn(t), "--save", path, "--policy-from", "chrome_155_macos", "--browser-arg=--headless=new", "--timeout", "30s")
	if code != 0 {
		t.Fatalf("headless arg: %d %s", code, stderr)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(captureProvenancePath(path, path, p, ""))
	if err != nil {
		t.Fatal(err)
	}
	var provenance profile.CaptureProvenance
	if err := json.Unmarshal(metadata, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.BrowserMode != "headless (--browser-arg)" {
		t.Fatalf("mode %s", provenance.BrowserMode)
	}
}
