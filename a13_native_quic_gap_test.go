package tlsforge

import (
	"encoding/json"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	tc "github.com/igor-lemon/tls-client"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestA13NativeQUICJSONInitialSize(t *testing.T) {
	for _, size := range []int{1250, 1300} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			p, err := profile.Get("firefox_148")
			if err != nil {
				t.Fatal(err)
			}
			if p.RuntimeBehavior().Flag("quic.enabled") {
				t.Fatal("not native branch")
			}
			var data map[string]json.RawMessage
			if err = json.Unmarshal([]byte(`{"quic.config":"explicit", "quic.enabled":false,
 "quic.versions":[1], "quic.dedicated_socket":false, "quic.source_cid_bytes":4,
 "quic.initial_dcid_bytes":8, "quic.stream_receive_window":524288,
 "quic.max_stream_receive_window":6291456, "quic.connection_receive_window":786432,
 "quic.max_connection_receive_window":15728640, "quic.incoming_bidi_streams":0,
 "quic.incoming_uni_streams":100, "quic.idle_timeout_ms":30000,
 "quic.keep_alive_ms":10000, "quic.initial_packet_bytes":1280,
 "quic.datagrams":true, "quic.max_udp_payload":1452, "quic.active_cid_limit":4,
 "quic.ack_timer_ms":25, "quic.max_ack_delay_ms":26,
 "quic.max_datagram_frame":16383}`), &data); err != nil {
				t.Fatal(err)
			}
			for key, value := range data {
				p.Behavior[key] = value
			}
			p.Behavior["quic.initial_packet_bytes"] = json.RawMessage(fmt.Sprint(size))
			if size == 1300 {
				p.Behavior["quic.source_cid_bytes"] = json.RawMessage("8")
			}
			raw, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), fmt.Sprint(size))
			if base := os.Getenv("TLSFORGE_A13_CATALOGUE_EVIDENCE"); base != "" {
				out = filepath.Join(base, "native", fmt.Sprint(size))
			}
			if err = os.MkdirAll(out, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(out, "profile.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			p, err = profile.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			port, heard := silentSite(t)
			client := newTestClient(t, WithProfileValue(p), WithTransportOption(tc.WithProtocolRacing()))
			if got := came(t, client, "https://127.0.0.1:"+port+"/"); got != "HTTP/2.0" {
				t.Fatal(got)
			}
			time.Sleep(100 * time.Millisecond)
			packets, at := heard.heard()
			if len(packets) == 0 {
				t.Fatal("no QUIC first flight")
			}
			for i, packet := range packets {
				if err = os.WriteFile(filepath.Join(out, fmt.Sprintf("%d.bin", i)), packet, 0600); err != nil {
					t.Fatal(err)
				}
			}
			info, _ := json.Marshal(map[string]any{"requested": size, "native": true, "datagrams": len(packets), "first_bytes": len(packets[0]), "at": at})
			if err = os.WriteFile(filepath.Join(out, "observed.json"), info, 0600); err != nil {
				t.Fatal(err)
			}
			atCID := 6 + int(packets[0][5])
			wantCID := 4
			if size == 1300 {
				wantCID = 8
			}
			if int(packets[0][atCID]) != wantCID {
				t.Errorf("source CID bytes=%d want%d", packets[0][atCID], wantCID)
			}
			if len(packets[0]) != size {
				t.Errorf("JSON quic.initial_packet_bytes=%d ignored; actual first datagram=%d", size, len(packets[0]))
			}
		})
	}
}
