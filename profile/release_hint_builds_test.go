package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type hintBuildChange struct {
	Name   string `json:"name"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type hintBuildDerivation struct {
	Path       string            `json:"path"`
	BeforeFile string            `json:"before_file"`
	BeforeSHA  string            `json:"before_sha256"`
	AfterSHA   string            `json:"after_sha256"`
	Changes    []hintBuildChange `json:"changes"`
	Witness    struct {
		BrowserBuild string `json:"browser_build"`
		Samples      int    `json:"samples_each"`
	} `json:"witness"`
}

func hintBuildDerivations() ([]hintBuildDerivation, error) {
	raw, err := os.ReadFile("provenance/release-hint-builds.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Schema int                   `json:"schema"`
		Major  int                   `json:"engine_major"`
		Rows   []hintBuildDerivation `json:"derivations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != 1 || doc.Major != 1 || len(doc.Rows) == 0 {
		return nil, fmt.Errorf("invalid hint-build derivation inventory")
	}
	return doc.Rows, nil
}

// A later data refresh unwinds to exact preserved bytes before the immutable
// A13 provenance checks run. Future refreshes append records; old hashes stay.
func unwindHintBuildDerivations(raw []byte) ([]byte, error) {
	rows, err := hintBuildDerivations()
	if err != nil {
		return nil, err
	}
	for step := 0; step <= len(rows); step++ {
		matched := false
		for _, row := range rows {
			if a13SHA(raw) != row.AfterSHA {
				continue
			}
			before, err := undoHintBuildDerivation(raw, row)
			if err != nil {
				return nil, err
			}
			raw, matched = before, true
			break
		}
		if !matched {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("cyclic hint-build provenance")
}

func undoHintBuildDerivation(raw []byte, row hintBuildDerivation) ([]byte, error) {
	if a13SHA(raw) != row.AfterSHA || len(row.Changes) != 2 || filepath.ToSlash(filepath.Dir(row.BeforeFile)) != "provenance/release-hint-builds" {
		return nil, fmt.Errorf("invalid hint-build source or change scope")
	}
	before, err := os.ReadFile(row.BeforeFile)
	if err != nil {
		return nil, err
	}
	if a13SHA(before) != row.BeforeSHA {
		return nil, fmt.Errorf("hint-build before bytes differ")
	}
	old, err := Load(before)
	if err != nil {
		return nil, err
	}
	current, err := Load(raw)
	if err != nil {
		return nil, err
	}
	copy := current.Clone()
	changes := map[string]hintBuildChange{}
	for _, change := range row.Changes {
		if change.Name != "sec-ch-ua-full-version" && change.Name != "sec-ch-ua-full-version-list" || changes[change.Name].Name != "" || change.Before == change.After {
			return nil, fmt.Errorf("undeclared hint-build field")
		}
		changes[change.Name] = change
		oldCount, newCount := 0, 0
		for _, hint := range old.ClientHints {
			if hint.Name == change.Name && hint.Value == change.Before {
				oldCount++
			}
		}
		for i, hint := range copy.ClientHints {
			if hint.Name == change.Name && hint.Value == change.After {
				newCount++
				copy.ClientHints[i].Value = change.Before
			}
		}
		if oldCount != 1 || newCount != 1 {
			return nil, fmt.Errorf("hint-build field does not match its record")
		}
	}
	version := changes["sec-ch-ua-full-version"]
	oldBuild, err := strconv.Unquote(version.Before)
	if err != nil || oldBuild == "" || version.After != strconv.Quote(row.Witness.BrowserBuild) || row.Witness.Samples < 2 {
		return nil, fmt.Errorf("hint-build witness does not match the full version")
	}
	list := changes["sec-ch-ua-full-version-list"]
	if list.After != strings.ReplaceAll(list.Before, oldBuild, row.Witness.BrowserBuild) {
		return nil, fmt.Errorf("hint-build changed brand data or ordering")
	}
	copy.Notes = old.Notes
	if !reflect.DeepEqual(copy, old) {
		return nil, fmt.Errorf("hint-build changed another profile field")
	}
	return before, nil
}

func TestReleaseHintBuildsPreserveEveryEarlierProvenanceLayer(t *testing.T) {
	rows, err := hintBuildDerivations()
	if err != nil {
		t.Fatal(err)
	}
	network, err := networkDerivations()
	if err != nil {
		t.Fatal(err)
	}
	latest, known := map[string]hintBuildDerivation{}, map[string]bool{}
	for path, row := range network {
		known[path+":"+row.AfterSHA] = true
	}
	for _, row := range rows {
		if !known[row.Path+":"+row.BeforeSHA] {
			t.Fatal("foreign before anchor", row.Path)
		}
		known[row.Path+":"+row.AfterSHA], latest[row.Path] = true, row
	}
	if len(latest) != 6 {
		t.Fatal("incomplete base/close-notify build refresh")
	}
	for path, row := range latest {
		raw, err := unwindPolicyAdditions(chainBytes(t, path))
		if err != nil {
			t.Fatal(path, err)
		}
		if a13SHA(raw) != row.AfterSHA {
			t.Fatal("current bytes differ from measured refresh", path)
		}
		before, err := unwindHintBuildDerivations(raw)
		if err != nil || a13SHA(before) != network[path].AfterSHA {
			t.Fatal("historical layers changed", path, err)
		}
		current, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		current.UserAgent += " foreign"
		bad, err := current.Save()
		if err != nil {
			t.Fatal(err)
		}
		changed := row
		changed.AfterSHA = a13SHA(bad)
		if _, err := undoHintBuildDerivation(bad, changed); err == nil {
			t.Fatal("refreshed hash hid an unrelated browser change")
		}
	}
}
