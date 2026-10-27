package tlsforge

import (
	"context"
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

func TestProfileQUICLayoutOverridesAmbientScrambling(t *testing.T) {
	p := quicProfile(t, map[string]string{"quic.initial_layout": `"scramble"`,
		"quic.chaos_first_frame_min": "", "quic.chaos_first_frame_spread": "", "quic.chaos_crypto_splits_min": "",
		"quic.chaos_crypto_splits_max": "", "quic.chaos_pings_min": "", "quic.chaos_pings_max": ""})
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
			// packet need not contain multiple frames: extension order is random.
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
