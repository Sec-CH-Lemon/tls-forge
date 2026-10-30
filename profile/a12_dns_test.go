package profile

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestA12DNSQueryChoicesSurviveSaveLoadCloneAndExplicitMigration(t *testing.T) {
	p, err := Get("chrome_156_macos")
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "renamed-dns-persona"
	p.Behavior["dns.https_query_recursion_desired"] = json.RawMessage("false")
	p.Behavior["dns.https_query_udp_payload_bytes"] = json.RawMessage("1232")
	p.Behavior["dns.https_query_timeout_ms"] = json.RawMessage("47")
	raw, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	clone := loaded.Clone()
	clone.Behavior["dns.https_query_timeout_ms"] = json.RawMessage("81")
	if loaded.Behavior.Uint("dns.https_query_timeout_ms") != 47 || clone.Behavior.Uint("dns.https_query_timeout_ms") != 81 || loaded.Behavior.Flag("dns.https_query_recursion_desired") || loaded.Behavior.Uint("dns.https_query_udp_payload_bytes") != 1232 {
		t.Fatal("DNS choices lost or aliased")
	}
	var old map[string]json.RawMessage
	if err = json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	var behavior map[string]json.RawMessage
	if err = json.Unmarshal(old["behavior"], &behavior); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dns.https_query_recursion_desired", "dns.https_query_udp_payload_bytes", "dns.https_query_timeout_ms"} {
		delete(behavior, key)
	}
	old["behavior"], err = json.Marshal(behavior)
	if err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := Inspect(archiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Load(archiveBytes); err == nil {
		t.Fatal("old executable profile silently acquired DNS choices")
	}
	saved, err := archive.Save()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(saved, []byte("dns.https_query_timeout_ms")) {
		t.Fatal("offline Save filled a new runtime choice")
	}
	if archive.Clone().Behavior.Has("dns.https_query_timeout_ms") {
		t.Fatal("Clone filled a new runtime choice")
	}
	migrated, err := archive.Migrate("explicit-dns-migration")
	if err != nil {
		t.Fatal(err)
	}
	if !migrated.Behavior.Has("dns.https_query_timeout_ms") || archive.Behavior.Has("dns.https_query_timeout_ms") {
		t.Fatal("migration mutated source or did not add explicit data")
	}
}
