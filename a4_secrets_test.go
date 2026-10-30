package tlsforge

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestURLAPIsDoNotExposeSecretsOnFailure(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	for _, raw := range []string{"https://u:never-keep@[broken/?access_token=never-keep", "https://u:never-keep@example.test:bad/?access_token=never-keep"} {
		_, canonical := CanonicalURL(raw)
		_, own := OwnPage(raw)
		_, cookies := client.CookiesFor(raw)
		for _, err := range []error{client.Validate(&Request{URL: raw}), canonical, own, cookies} {
			if err == nil || strings.Contains(err.Error(), "never-keep") {
				t.Errorf("unsafe API error: %v", err)
			}
		}
	}
}

// A URL the URL Standard reads with a password, however it is spelt, has
// none in what the URL APIs say of it: one slash or three after the scheme,
// none, backslashes, capitals, a tab in the password or the scheme. Port
// 6000 is one Chrome sends nothing to, so each is refused and quoted.
func TestAPasswordInAnySpellingOfAURLIsSaidNowhere(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	said := func(t *testing.T, what string) {
		t.Helper()
		for _, part := range []string{"zq7", "x9w"} {
			if strings.Contains(what, part) {
				t.Errorf("the password said: %s", what)
			}
		}
	}
	for _, raw := range []string{
		"https:/u:zq7x9w@example.test:6000/",
		"https:///u:zq7x9w@example.test:6000/",
		"https:u:zq7x9w@example.test:6000/",
		`https:\\u:zq7x9w@example.test:6000/`,
		"HTTPS:/u:zq7x9w@example.test:6000/",
		"https://u:zq7\tx9w@example.test:6000/",
		"ht\ntps:/u:zq7x9w@example.test:6000/",
		"wss:/u:zq7x9w@example.test/",
	} {
		t.Run(raw, func(t *testing.T) {
			_, canonical := CanonicalURL(raw)
			_, sent := client.Do(&Request{URL: raw})
			for _, err := range []error{client.Validate(&Request{URL: raw}), sent, canonical} {
				if err == nil {
					t.Fatalf("%q was not refused", raw)
				}
				said(t, err.Error())
			}
			own, err := OwnPage(raw)
			said(t, fmt.Sprint(own, err))
			cookies, err := client.CookiesFor(raw)
			said(t, fmt.Sprint(cookies, err))
		})
	}
	// a page's URL that does not read
	err = client.Validate(&Request{URL: "https://example.test/", Browser: &BrowserContext{Kind: KindFetch, Initiator: "https:/u:zq7x9w@[bad/"}})
	if err == nil {
		t.Fatal("an initiator that does not read was taken")
	}
	said(t, err.Error())
}

func TestProfileQUICLayoutOverridesAmbientScrambling(t *testing.T) {
	p := quicProfile(t, map[string]string{"quic.initial_layout": `"scramble"`,
		"quic.chaos_first_frame_min": "", "quic.chaos_first_frame_spread": "", "quic.chaos_crypto_splits_min": "",
		"quic.chaos_crypto_splits_max": "", "quic.chaos_pings_min": "", "quic.chaos_pings_max": ""})
	// This is a technical layout witness, not a new browser observation.
	// Keep SNI in the first packet while its deferred bytes follow the final
	// packet. Otherwise both cuts can fit in that final packet and the
	// transport's control-frame shuffle can restore contiguous wire order.
	p.Behavior["quic.shuffle_extensions"] = json.RawMessage("false")
	p.PerConnection.ShufflesExtensions = false
	p.ClientHello = earlySNIFixture(t, p.ClientHello)
	for _, setting := range []string{"false", "true"} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv("QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING", setting)
			sent, _ := firstFlight(t, p, 100*time.Millisecond)
			if len(sent) == 0 {
				t.Fatal("no Initial")
			}
			if root := os.Getenv("TLSFORGE_A4_EVIDENCE"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(map[string]any{"setting": setting, "datagrams": sent, "policy": p.Behavior})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("quic-%s-%d.json", setting, time.Now().UnixNano())), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Scrambling skips SNI/ECH ranges and later fills them. The first
			// packet need not contain multiple frames; the fixed input has a suffix.
			bytesSeen := map[uint64]byte{}
			var highest uint64
			skipped, filled := false, false
			for _, datagram := range sent {
				for len(datagram) > 7 && datagram[0]&0xf0 == 0xc0 {
					packet, rest := openInitial(t, datagram, dcidOf(sent[0]))
					datagram = rest
					for _, frame := range packet.frames {
						if frame.typ != 0x06 {
							continue
						}
						fresh := false
						for i, b := range frame.data {
							at := frame.offset + uint64(i)
							if _, ok := bytesSeen[at]; !ok {
								fresh = true
							}
							bytesSeen[at] = b
						}
						if fresh && frame.offset > highest {
							skipped = true
						}
						if fresh && frame.offset < highest {
							filled = true
						}
						highest = max(highest, frame.offset+uint64(len(frame.data)))
					}
				}
			}
			if !skipped || !filled {
				t.Fatalf("JSON scramble disabled by ambient %s: skipped=%v filled=%v", setting, skipped, filled)
			}
			if len(bytesSeen) < 4 || bytesSeen[0] != 1 {
				t.Fatal("not a complete ClientHello header")
			}
			length := uint64(bytesSeen[1])<<16 | uint64(bytesSeen[2])<<8 | uint64(bytesSeen[3])
			for at := uint64(0); at < 4+length; at++ {
				if _, ok := bytesSeen[at]; !ok {
					t.Fatalf("scrambled ClientHello missing byte %d", at)
				}
			}

		})
	}
}

func TestProfileHTTP2IgnoresAutomaticTransportEnvironment(t *testing.T) {
	t.Setenv("GODEBUG", "http2client=0")
	t.Setenv("SSLKEYLOGFILE", filepath.Join(t.TempDir(), "missing", "keys"))
	measured, err := MeasureSelf(context.Background(), WithProfile("chrome"))
	if err != nil || measured.HTTP2 == nil {
		t.Fatalf("profile transport overridden by ambient configuration: %+v %v", measured, err)
	}
}

// earlySNIFixture moves the complete SNI extension before the other extensions,
// preserving the captured values and all vector lengths. Runtime still derives
// the hostname, randoms, key shares and ECH for the current connection.
func earlySNIFixture(t *testing.T, raw []byte) []byte {
	t.Helper()
	out := append([]byte(nil), raw...)
	if len(out) < 44 || out[0] != 22 || out[5] != 1 {
		t.Fatal("not a ClientHello record")
	}
	pos := 43
	pos += 1 + int(out[pos])
	if pos+2 > len(out) {
		t.Fatal("missing cipher suites")
	}
	pos += 2 + int(binary.BigEndian.Uint16(out[pos:]))
	if pos >= len(out) {
		t.Fatal("missing compression methods")
	}
	pos += 1 + int(out[pos])
	if pos+2 > len(out) {
		t.Fatal("missing extensions")
	}
	end := pos + 2 + int(binary.BigEndian.Uint16(out[pos:]))
	pos += 2
	if end != len(out) {
		t.Fatal("truncated ClientHello extensions")
	}
	first := pos
	for pos+4 <= end {
		size := 4 + int(binary.BigEndian.Uint16(out[pos+2:]))
		if pos+size > end {
			t.Fatal("truncated extension")
		}
		if binary.BigEndian.Uint16(out[pos:]) == 0 {
			extension := append([]byte(nil), out[pos:pos+size]...)
			copy(out[first+size:pos+size], out[first:pos])
			copy(out[first:], extension)
			return out
		}
		pos += size
	}
	t.Fatal("no SNI in layout fixture")
	return nil
}
