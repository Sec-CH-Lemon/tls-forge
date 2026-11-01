package profile

import (
	"strings"
	"testing"
)

func TestA13RawHelloNeverInfersExecutionOrderFromMetadata(t *testing.T) {
	for _, schema := range []int{0, 1, 2, 3, 4} {
		p := mustGet(t, "chrome_155_macos").Clone()
		p.Schema = schema
		p.PerConnection = nil
		p.Name = "chrome_source"
		chrome := p.ShufflesExtensions()
		p.Name = "neutral_source"
		neutral := p.ShufflesExtensions()
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "per_connection") {
			t.Errorf("schema%d raw order accepted (metadata shuffle%v/%v): %v", schema, chrome, neutral, err)
		}
		saved, err := p.Save()
		if err != nil {
			t.Fatal(err)
		}
		inspected, err := Inspect(saved)
		if err != nil {
			t.Fatal(err)
		}
		if inspected.PerConnection != nil {
			t.Errorf("schema%d Save invented generation rule", schema)
		}
		if _, err := Load(saved); err == nil {
			t.Errorf("schema%d Save bypassed order requirement", schema)
		}
	}
}

func TestA13RawMigrationUsesSourceGenerationNotDestinationMetadata(t *testing.T) {
	for _, tc := range []struct {
		source, destination string
		shuffle             bool
	}{{"chrome_archived", "neutral_candidate", true}, {"neutral_archived", "chrome_candidate", false}} {
		p := mustGet(t, "chrome_155_macos").Clone()
		p.EngineMajor = Major(0)
		p.Schema = 0
		p.Name = tc.source
		p.UserAgent = ""
		p.Behavior = nil
		p.PerConnection = nil
		m, err := p.Migrate(tc.destination)
		if err != nil {
			t.Fatal(err)
		}
		if m.PerConnection == nil || m.PerConnection.ShufflesExtensions != tc.shuffle {
			t.Fatal("destination changed generation", tc, m.PerConnection)
		}
		if p.PerConnection != nil || p.Behavior != nil || *p.EngineMajor != 0 {
			t.Fatal("source archive mutated")
		}
	}
}
