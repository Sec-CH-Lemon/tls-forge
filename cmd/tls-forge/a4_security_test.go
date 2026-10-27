package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/capture"
)

func TestCaptureRejectsVisitorPathComponents(t *testing.T) {
	for _, version := range []string{"../local", "155/../../local", "/tmp/local", "155\\local", "155_macos", "155.0", "12345", "１５５", "155 ", ""} {
		c := &capture.Capture{Navigator: &capture.Navigator{Brands: []capture.Brand{{Brand: "Brave", Version: version}}}}
		if got := profileNameFor(c); got != "brave" {
			t.Errorf("version %q became %q", version, got)
		}
	}
	for _, version := range []string{"0", "155", "9999"} {
		if _, got := browserFrom("Chrome/" + version + ".0"); got != version {
			t.Errorf("valid version %q became %q", version, got)
		}
	}
	for _, version := range []string{"../local", "/tmp/local", "12345", "155_foo", "155/../../local"} {
		if _, got := browserFrom("Chrome/" + version); got != "" {
			t.Errorf("UA version %q became %q", version, got)
		}
	}
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../local", "ok/../../local", "/tmp/local", "ok\\local", ".hidden", "two..dots", "UPPER", ""} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "nested", "nested", "profiles")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if _, _, err := saveProfile(dir, name, measured, true, nil); err == nil {
				t.Errorf("accepted unsafe name %q", name)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("unsafe name wrote %v", entries)
			}
		})
	}
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "safe")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := saveProfile(dir, "safe", measured, true, nil); err == nil {
		t.Error("followed a directory link outside profile root")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("wrote outside profile root: %v", entries)
	}
}

func TestCapturePathFailuresWriteNothing(t *testing.T) {
	if code, _, _ := exec(t, "capture", "--name", "../escape"); code != 2 {
		t.Errorf("unsafe explicit name: exit %d", code)
	}
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome"))
	if err != nil {
		t.Fatal(err)
	}
	version, platform := theVisitorsPlatform(t)
	if _, _, err := saveProfile(t.TempDir(), version+"_"+platform, measured, false, nil); err == nil {
		t.Error("implicitly shadowed shipped profile")
	}
	originalPath, originalOpen := capturedFilePath, openProfileRoot
	defer func() { capturedFilePath, openProfileRoot = originalPath, originalOpen }()
	capturedFilePath = func(string, string) (string, error) { return "", errors.New("invalid platform") }
	dir := t.TempDir()
	if _, _, err := saveProfile(dir, "safe", measured, true, nil); err == nil {
		t.Error("ignored invalid layout")
	}
	capturedFilePath = originalPath
	openProfileRoot = func(string) (*os.Root, error) { return nil, errors.New("directory disappeared") }
	if _, _, err := saveProfile(dir, "safe", measured, true, nil); err == nil {
		t.Error("ignored open failure")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failure wrote %v", entries)
	}
}
