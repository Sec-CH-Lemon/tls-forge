package tlsforge

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	tc "github.com/igor-lemon/tls-client"
)

func TestA13CatalogueJSONChangesHTTP3Wire(t *testing.T) {
	p, err := profile.Get("firefox_148")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"original", "renamed", "settings-order", "settings-value", "pseudo-order", "declared-grease"} {
		t.Run(variant, func(t *testing.T) {
			raw, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			var data map[string]any
			if err = json.Unmarshal(raw, &data); err != nil {
				t.Fatal(err)
			}
			behavior := data["behavior"].(map[string]any)
			settings := behavior["h3.settings"].([]any)
			switch variant {
			case "renamed":
				data["name"] = "neutral-catalogue"
				data["user_agent"] = "Independent metadata"
			case "settings-order":
				settings[0], settings[1] = settings[1], settings[0]
			case "settings-value":
				settings[0].(map[string]any)["value"] = float64(4096)
			case "pseudo-order":
				behavior["h3.pseudo_header_order"] = []string{":path", ":authority", ":method", ":scheme"}
			case "declared-grease":
				behavior["h3.settings"] = append(settings, map[string]any{"id": 33, "value": 17})
			}
			raw, err = json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			q, err := profile.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			url, wire := a13CatalogueH3Peer(t)
			client := newTestClient(t, WithProfileValue(q), WithTimeout(6*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			res, err := client.Get(url)
			if err != nil || string(res.Body) != "ok" {
				t.Fatalf("response %+v %v", res, err)
			}
			got := <-wire
			cp, err := q.ClientProfile()
			if err != nil {
				t.Fatal(err)
			}
			var order []uint64
			values := map[uint64]uint64{}
			for _, s := range got.Settings {
				order = append(order, s.ID)
				values[s.ID] = s.Value
			}
			if !slices.Equal(order, cp.GetHttp3SettingsOrder()) || !reflect.DeepEqual(values, cp.GetHttp3Settings()) {
				t.Fatalf("JSON setting mutation missing: %v %v", order, values)
			}
			var pseudo []string
			for _, h := range got.Headers {
				if len(h.Name) > 0 && h.Name[0] == ':' {
					pseudo = append(pseudo, h.Name)
				}
			}
			if !slices.Equal(pseudo, cp.GetHttp3PseudoHeaderOrder()) {
				t.Fatal("JSON pseudo order ignored", pseudo)
			}
		})
	}
}
