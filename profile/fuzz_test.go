package profile

import "testing"

// A profile is a file, and files arrive from places their reader did not
// choose: a repository, a colleague, a release asset. Load decodes JSON and
// base64 out of one and hands the result to a TLS stack, so it gets the same
// treatment as the wire parser.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"name":"x","client_hello":"AAAA","header_order":["a"]}`))
	f.Add([]byte(`{"name":"x","client_hello":"!!!!"}`))
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
