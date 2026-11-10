package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestA12MachineHintsValidateTheirWireValues(t *testing.T) {
	for _, item := range []string{
		"device-memory=8", "sec-ch-device-memory=0.5", "device-memory=32",
		"dpr=2", "sec-ch-dpr=1.25", "dpr=0.001", "dpr=999999999999.999",
		"viewport-width=1280", "sec-ch-viewport-width=0", "sec-ch-viewport-height=999999999999999",
		"sec-ch-prefers-color-scheme=light", "sec-ch-prefers-color-scheme=dark",
		"sec-ch-prefers-reduced-motion=reduce", "sec-ch-prefers-reduced-motion=no-preference",
		"sec-ch-prefers-reduced-transparency=reduce", "sec-ch-prefers-reduced-transparency=no-preference",
	} {
		if got, err := settingsOf([]string{item}); err != nil || len(got) != 1 {
			t.Errorf("valid %q: %v, %v", item, got, err)
		}
	}
	for _, item := range []string{
		"device-memory=3", "device-memory=0", "device-memory=0.1", "device-memory=-8",
		"dpr=0", "dpr=-1", "dpr=+2", "dpr=NaN", "dpr=Inf", "dpr=1e1", "dpr=.5", "dpr=1.",
		"dpr=1.0000", "dpr=1000000000000", "dpr=1.2.3", "dpr=1.é", "dpr=", "dpr= 2", "dpr=2\r\nX: y",
		"viewport-width=", "viewport-width=-1", "viewport-width=1.5", "viewport-width=1000000000000000", "viewport-width=１",
		`sec-ch-prefers-color-scheme="light"`, "sec-ch-prefers-color-scheme=auto",
		"sec-ch-prefers-reduced-motion=none", "sec-ch-prefers-reduced-transparency=normal",
	} {
		if _, err := settingsOf([]string{item}); err == nil {
			t.Errorf("invalid %q accepted", item)
		}
	}
}

func TestA12CaptureRecordsEveryEditedAliasOrigin(t *testing.T) {
	measured, err := tlsforge.MeasureSelf(context.Background(), tlsforge.WithProfile("chrome_155_macos"))
	if err != nil {
		t.Fatal(err)
	}
	settings, err := settingsOf([]string{"dpr=1.25", "device-memory=4", "viewport-width=1366"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	saved, path, err := saveProfile(dir, "a12_persona", measured, true, settings, "chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(captureProvenancePath(dir, path, saved, ""))
	if err != nil {
		t.Fatal(err)
	}
	var provenance profile.CaptureProvenance
	if err := json.Unmarshal(metadata, &provenance); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if provenance.ProfileSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("provenance is not bound to the saved alias values")
	}
	want := map[string]string{"dpr": "1.25", "sec-ch-dpr": "1.25", "device-memory": "4", "sec-ch-device-memory": "4", "viewport-width": "1366", "sec-ch-viewport-width": "1366"}
	for _, field := range saved.ClientHints {
		if value, ok := want[field.Name]; ok {
			if field.Value != value || provenance.Fields["client_hints."+field.Name].Class != "user-provided" {
				t.Errorf("edited alias %v has origin%v", field, provenance.Fields["client_hints."+field.Name])
			}
			delete(want, field.Name)
		}
	}
	if len(want) != 0 || provenance.Fields["client_hints.sec-ch-ua-arch"].Class == "user-provided" {
		t.Fatalf("aliases missing%v, or unrelated origin overwritten", want)
	}
}

func TestA12MachineHintAliasesAreOneExplicitInput(t *testing.T) {
	for _, pair := range [][2]string{{"device-memory", "sec-ch-device-memory"}, {"dpr", "sec-ch-dpr"}, {"viewport-width", "sec-ch-viewport-width"}} {
		if _, err := settingsOf([]string{pair[0] + "=2", pair[1] + "=4"}); err == nil || !strings.Contains(err.Error(), "same value") {
			t.Errorf("contradictory %v: %v", pair, err)
		}
		settings, err := settingsOf([]string{pair[0] + "=2", pair[1] + "=2"})
		if err != nil {
			t.Fatal(err)
		}
		p, err := profile.Get("chrome_155_macos")
		if err != nil {
			t.Fatal(err)
		}
		before := p.Clone()
		if err := applySettings(p, settings[:1]); err != nil {
			t.Fatal(err)
		}
		for i, field := range p.ClientHints {
			if slices.Contains(pair[:], field.Name) {
				if field.Value != "2" {
					t.Errorf("alias %s kept %q", field.Name, field.Value)
				}
			} else if field != before.ClientHints[i] {
				t.Errorf("unrelated hint changed: %v", field)
			}
		}
		// One existing alias may be edited without inventing the other.
		p.ClientHints = []profile.Field{{Name: pair[1], Value: "4"}}
		if err := applySettings(p, settings[:1]); err != nil || len(p.ClientHints) != 1 || p.ClientHints[0].Name != pair[1] || p.ClientHints[0].Value != "2" {
			t.Fatalf("one supported alias: %v, %v", p.ClientHints, err)
		}
		p.ClientHints = nil
		if err := applySettings(p, settings[:1]); err == nil {
			t.Fatal("unsupported hint was invented")
		}
	}
}

func TestA12EveryMachineHintCanBeSavedAsAnExplicitChoice(t *testing.T) {
	p, err := profile.Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, value := range machineValues(p) {
		values[value[0]] = value[1]
	}
	if len(values) != len(machineFields) {
		t.Fatalf("only %d of %d supported machine fields inventoried", len(values), len(machineFields))
	}
	for _, field := range machineFields {
		settings, err := settingsOf([]string{fmt.Sprintf("%s=%s", field, values[field])})
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		copy := p.Clone()
		if err := applySettings(copy, settings); err != nil {
			t.Fatal(err)
		}
		raw, err := copy.Save()
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := profile.Load(raw)
		if err != nil || loaded.Name != p.Name || len(machineValues(loaded)) != len(machineFields) {
			t.Fatalf("saved %s: %v", field, err)
		}
	}
}
