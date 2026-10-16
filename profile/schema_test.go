package profile

import (
	"bytes"
	"io/fs"
	"testing"
)

func TestEveryShippedProfileIsReadAndWornAsItShips(t *testing.T) {
	// Each in the current schema, read strictly; built into a handshake and a
	// client without its bytes changing; and saved back as it ships, so that
	// the files are what Save writes.
	paths, err := fs.Glob(embedded, "data/*/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("shipped profiles: %v, %v", paths, err)
	}
	for _, path := range paths {
		data, err := embedded.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		before := bytes.Clone(data)
		p, err := Load(data)
		if err != nil || p.Schema != Schema {
			t.Fatalf("%s: schema %d, %v", path, p.Schema, err)
		}
		hello := bytes.Clone(p.ClientHello)
		if _, err := p.Spec(); err != nil {
			t.Errorf("%s: Spec: %v", path, err)
		}
		if _, err := p.ClientProfile(); err != nil {
			t.Errorf("%s: ClientProfile: %v", path, err)
		}
		saved, err := p.Save()
		if err != nil || !bytes.Equal(saved, data) {
			t.Errorf("%s is not what Save writes of it (%v)", path, err)
		}
		if !bytes.Equal(data, before) || !bytes.Equal(p.ClientHello, hello) {
			t.Errorf("%s: reading or wearing it changed it", path)
		}
	}
}
