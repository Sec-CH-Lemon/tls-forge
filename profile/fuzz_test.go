package profile

import (
	"encoding/json"
	"os"
	"testing"
)

// A profile is a file, and files arrive from places their reader did not
// choose: a repository, a colleague, a release asset. Load decodes JSON and
// base64 out of one and hands the result to a TLS stack, so it gets the same
// treatment as the wire parser.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"engine_major":2,"name":"x","client_hello":"AAAA","header_order":["a"]}`))
	f.Add([]byte(`{"engine_major":2,"name":"x","client_hello":"!!!!"}`))
	p, err := Get("chrome_156_macos")
	if err != nil {
		f.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/catalogue-tls-export.json")
	if err != nil {
		f.Fatal(err)
	}
	var exported struct {
		Specs map[string]*TLSSpec `json:"specs"`
	}
	if err := json.Unmarshal(fixture, &exported); err != nil {
		f.Fatal(err)
	}
	p.ClientHello = nil
	p.PerConnection = nil
	p.TLSSpec = exported.Specs["chrome_133"]
	data, err := p.Save()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Load(data)
		if err != nil {
			return
		}
		if p == nil {
			t.Fatal("neither a profile nor an error")
		}
		_, _ = p.ClientProfile()
	})
}
