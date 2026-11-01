package profile

import "testing"

func TestBareBaseCannotKeepAnUnselectedQUICFactory(t *testing.T) {
	p := mustGet(t, "chrome_155_macos").Clone()
	p.Name = "explicit_adapter"
	p.Base = "firefox_148"
	p.ClientHello = nil
	p.PerConnection = nil
	p.TLSSpec = nil
	p.HTTP2 = HTTP2{}
	// The child owns a complete adapter policy; only TCP TLS/H2 comes from base.
	if p.RuntimeBehavior().Text("quic.tls_source") != "tcp-adapter" {
		t.Fatal("bad fixture")
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	cp, err := p.ClientProfile()
	if err != nil {
		t.Fatal(err)
	}
	if cp.GetQUICClientHelloSpec() != nil {
		t.Fatal("inherited independent factory survived explicit tcp-adapter selection")
	}
}
