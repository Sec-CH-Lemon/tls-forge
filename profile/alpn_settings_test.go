package profile

import (
	"encoding/binary"
	"github.com/Sec-CH-Lemon/tls-forge/v7/fingerprint"
	tls "github.com/igor-lemon/utls"
	"io"
	"slices"
	"testing"
)

func TestForcedHTTP1DoesNotOfferHTTP2Settings(t *testing.T) {
	p, err := Get("chrome_155_macos")
	if err != nil {
		t.Fatal(err)
	}
	for _, forced := range []bool{false, true} {
		cp, err := p.ClientProfile()
		if err != nil {
			t.Fatal(err)
		}
		c := tls.UClient(nil, &tls.Config{ServerName: "example.com", OmitEmptyPsk: true}, cp.GetClientHelloId(), false, forced, true)
		if err := c.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		hello, err := fingerprint.ParseClientHello(append([]byte{22, 3, 1, byte(len(c.HandshakeState.Hello.Raw) >> 8), byte(len(c.HandshakeState.Hello.Raw))}, c.HandshakeState.Hello.Raw...))
		if err != nil {
			t.Fatal(err)
		}
		var types []uint16
		for _, e := range hello.Extensions {
			types = append(types, e.Type)
		}
		if has := slices.Contains(types, fingerprint.ExtALPS); has == forced {
			t.Errorf("forced=%v,ALPS offered=%v", forced, has)
		}
	}
}

func TestSettingsFollowTheFinalALPNList(t *testing.T) {
	alpn := &tls.ALPNExtension{AlpnProtocols: []string{"h2", "h3"}}
	old := &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "h3", "unused"}}
	modern := &tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2", "h3", "unused"}}
	other := &tls.GenericExtension{Id: 1234, Data: []byte{1}}
	spec := settingsForALPN(tls.ClientHelloSpec{Extensions: []tls.TLSExtension{other, old, modern, alpn}})
	if spec.Extensions[0] != other {
		t.Fatal("unrelated extension replaced")
	}
	for i, code := range []uint16{17513, 17613} {
		e := spec.Extensions[i+1]
		for _, ps := range [][]string{{"h2", "h3"}, {"http/1.1"}, {"h3"}, {"h2", "h3"}} {
			alpn.AlpnProtocols = ps
			buf := make([]byte, e.Len())
			n, err := e.Read(buf)
			if err != io.EOF || n != len(buf) {
				t.Fatalf("%v,%d", err, n)
			}
			if ps[0] == "http/1.1" {
				if n != 0 {
					t.Fatal("settings without an offered protocol")
				}
				continue
			}
			if binary.BigEndian.Uint16(buf) != code {
				t.Fatal("wrong ALPS codepoint")
			}
			var names []string
			for j := 6; j < len(buf); {
				size := int(buf[j])
				j++
				names = append(names, string(buf[j:j+size]))
				j += size
			}
			if !slices.Equal(names, ps) {
				t.Fatalf("%q,want %q", names, ps)
			}
			if _, err := e.Read(buf[:len(buf)-1]); err != io.ErrShortBuffer {
				t.Fatal("short buffer accepted")
			}
		}
	}
	spec = settingsForALPN(tls.ClientHelloSpec{Extensions: []tls.TLSExtension{old}})
	if n, err := spec.Extensions[0].Read(nil); n != 0 || err != io.EOF {
		t.Fatal("ALPS with no ALPN")
	}
}
