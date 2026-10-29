package tlsforge

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func TestCaptureBasisPolicyReachesActualTLSClose(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, alert := range []bool{false, true} {
			name := "h1"
			if h2 {
				name = "h2"
			}
			if alert {
				name += "-alert"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				basis, err := profile.Get("chrome_155_macos")
				if err != nil {
					t.Fatal(err)
				}
				value, _ := json.Marshal(alert)
				basis.Behavior["tls.close_notify"] = value
				// A real saved/loaded JSON basis, not an opaque transport override.
				raw, err := basis.Save()
				if err != nil {
					t.Fatal(err)
				}
				basis, err = profile.Load(raw)
				if err != nil {
					t.Fatal(err)
				}
				observed := &capture.Capture{RawClientHello: basis.ClientHello, HTTP2: &capture.HTTP2{WindowUpdate: basis.HTTP2.ConnectionFlow, PseudoHeaderOrder: []string{"m", "a", "s", "p"}}}
				for _, setting := range basis.HTTP2.Settings {
					observed.HTTP2.Settings = append(observed.HTTP2.Settings, capture.Setting{ID: setting.ID, Value: setting.Value})
				}
				observed.HTTP2.Headers = []capture.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "localhost"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}
				for _, field := range basis.Headers {
					observed.HTTP2.Headers = append(observed.HTTP2.Headers, capture.HeaderField{Name: field.Name, Value: field.Value})
				}
				observed.HTTP2.HeaderPriority = &capture.Priority{StreamID: 1, Exclusive: true, Weight: 255}
				built, err := profile.FromCapture("neutral_capture", observed, basis)
				if err != nil {
					t.Fatal(err)
				}
				built.UserAgent = "Metadata without a browser identity"
				data, err := built.Save()
				if err != nil {
					t.Fatal(err)
				}
				built, err = profile.Load(data)
				if err != nil {
					t.Fatal(err)
				}
				site := newLifecycleServer(t, h2, nil)
				client := newTestClient(t, WithProfileValue(built))
				tap := &seeingTap{}
				get(t, client, site.URL, tap)
				time.Sleep(100 * time.Millisecond)
				connections, _ := tap.seen()
				if len(connections) != 1 {
					t.Fatalf("connections %d", len(connections))
				}
				before, _ := connections[0].what()
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if !site.closedWithin(2 * time.Second) {
					t.Fatal("connection not closed")
				}
				after, _ := connections[0].what()
				if (len(after) > len(before)) != alert {
					t.Fatalf("TLS close policy lost: alert=%v added_bytes=%d", alert, len(after)-len(before))
				}
			})
		}
	}
}
