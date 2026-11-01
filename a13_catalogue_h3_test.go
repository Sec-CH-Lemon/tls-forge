package tlsforge

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tc "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	"github.com/quic-go/qpack"
)

func TestA13CatalogueHTTP3Production(t *testing.T) {
	path := os.Getenv("TLSFORGE_A13_CATALOGUE_INPUT")
	if path == "" {
		path = "profile/catalogue.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err = json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Entries) != 83 {
		t.Fatal("catalogue denominator", len(inv.Entries))
	}
	names := make([]string, 0, 83)
	for n := range inv.Entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p, err := profile.Load(inv.Entries[name])
			if err != nil {
				t.Fatal(err)
			}
			url, seen := a13CatalogueH3Peer(t)
			client := newTestClient(t, WithProfileValue(p), WithTimeout(6*time.Second), WithTransportOption(tc.WithProtocolRacing()))
			for i := range 3 {
				if i == 2 {
					client.CloseIdleConnections()
				}
				res, err := client.Get(url)
				if err != nil || string(res.Body) != "ok" {
					t.Fatalf("H3 response %d %+v %v", i, res, err)
				}
				var got a13H3Observed
				select {
				case got = <-seen:
				case <-time.After(time.Second):
					t.Fatal("missing original peer observation")
				}
				if got.Connection != i/2 || got.Stream != int64(i%2)*4 {
					t.Fatalf("lifecycle %d conn%d stream%d", i, got.Connection, got.Stream)
				}
				cp, err := p.ClientProfile()
				if err != nil {
					t.Fatal(err)
				}
				expected := cp.GetHttp3Settings()
				if expected == nil {
					expected = map[uint64]uint64{6: 10 << 20, 51: 1}
				}
				actual := map[uint64]uint64{}
				greaseCount := 0
				var actualOrder []uint64
				for _, s := range got.Settings {
					if _, ok := expected[s.ID]; !ok && p.RuntimeBehavior().Flag("h3.grease_settings") && s.ID >= 0x21 && (s.ID-0x21)%0x1f == 0 {
						pol := p.RuntimeBehavior()
						n := (s.ID - 33) / 31
						if n < pol.Uint("h3.grease_setting_n_min") || n > pol.Uint("h3.grease_setting_n_max") || s.Value > math.MaxUint32 || pol.Flag("h3.grease_setting_nonzero") && s.Value == 0 {
							t.Fatal("invalid GREASE settings draw", s)
						}
						greaseCount++
						continue
					}
					if _, duplicate := actual[s.ID]; duplicate {
						t.Fatal("duplicate settings", got.Settings)
					}
					actual[s.ID] = s.Value
					actualOrder = append(actualOrder, s.ID)
				}
				if p.RuntimeBehavior().Flag("h3.grease_settings") && greaseCount != 1 {
					t.Fatal("missing/extra generated GREASE settings", greaseCount)
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("SETTINGS changed: %v want%v", actual, expected)
				}
				if order := cp.GetHttp3SettingsOrder(); len(order) > 0 && !slices.Equal(actualOrder, order) {
					t.Fatalf("SETTINGS order %v want%v", actualOrder, order)
				}
				order := cp.GetHttp3PseudoHeaderOrder()
				if len(order) == 0 {
					order = []string{":method", ":authority", ":scheme", ":path"}
				}
				var names []string
				for _, h := range got.Headers {
					if strings.HasPrefix(h.Name, ":") {
						names = append(names, h.Name)
					}
				}
				if !slices.Equal(names, order) {
					t.Fatalf("pseudo order %v want%v", names, order)
				}
				relative := filepath.Join(name, "h3", fmt.Sprintf("%d.json", i))
				if base := os.Getenv("TLSFORGE_A13_CATALOGUE_BEFORE"); base != "" {
					raw, err := os.ReadFile(filepath.Join(base, relative))
					if os.IsNotExist(err) && a13BeforeH3WasUnavailable(t, name) {
						// This alias still has all three after wire assertions. It has
						// no paired successful before-H3; the original failure is retained.
					} else if err != nil {
						t.Fatal(err)
					} else {
						var old a13H3Observed
						if err = json.Unmarshal(raw, &old); err != nil {
							t.Fatal(err)
						}
						if old.Resumed != got.Resumed || old.Connection != got.Connection || old.Stream != got.Stream {
							t.Fatal("H3 lifecycle changed")
						}

						stableSettings := func(seen a13H3Observed) (map[uint64]uint64, []uint64) {
							out := map[uint64]uint64{}
							var order []uint64
							draws := 0
							for _, v := range seen.Settings {
								if _, declared := expected[v.ID]; !declared && p.RuntimeBehavior().Flag("h3.grease_settings") && v.ID >= 33 && (v.ID-33)%31 == 0 {
									n := (v.ID - 33) / 31
									pol := p.RuntimeBehavior()
									if n < pol.Uint("h3.grease_setting_n_min") || n > pol.Uint("h3.grease_setting_n_max") || v.Value > math.MaxUint32 || pol.Flag("h3.grease_setting_nonzero") && v.Value == 0 {
										t.Fatal("before GREASE violates declared rule", v)
									}
									draws++
									continue
								}
								if _, duplicate := out[v.ID]; duplicate {
									t.Fatal("duplicate before SETTINGS")
								}
								out[v.ID] = v.Value
								order = append(order, v.ID)
							}
							if p.RuntimeBehavior().Flag("h3.grease_settings") && draws != 1 {
								t.Fatal("before generated GREASE count", draws)
							}
							return out, order
						}
						beforeValues, beforeOrder := stableSettings(old)
						if !reflect.DeepEqual(beforeValues, actual) {
							t.Fatalf("before/after SETTINGS values changed: %v / %v", beforeValues, actual)
						}
						// The old nil/default map had no declared order. Its new6,51
						// order is an explicit documented choice, not hidden normalization.
						if p.RuntimeBehavior().Flag("quic.enabled") || len(profiles.MappedTLSClients[name].GetHttp3SettingsOrder()) > 0 {
							if !slices.Equal(beforeOrder, actualOrder) {
								t.Fatalf("declared SETTINGS order changed: %v / %v", beforeOrder, actualOrder)
							}
						}
						clean := func(h []qpack.HeaderField) []qpack.HeaderField {
							h = slices.Clone(h)
							for i := range h {
								if h[i].Name == ":authority" {
									h[i].Value = "owned-peer:port"
								}
							}
							return h
						}
						if !reflect.DeepEqual(clean(old.Headers), clean(got.Headers)) {
							t.Fatalf("request headers changed: %+v want%+v", got.Headers, old.Headers)
						}
					}
				}
				if dir := os.Getenv("TLSFORGE_A13_CATALOGUE_EVIDENCE"); dir != "" {
					target := filepath.Join(dir, relative)
					if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
						t.Fatal(err)
					}
					raw, err := json.MarshalIndent(got, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(target, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

// A missing successful baseline is allowed only for the exact frozen set of
// prior placeholder-factory failures, checked again against that source API.
func a13BeforeH3WasUnavailable(t *testing.T, name string) bool {
	t.Helper()
	raw, err := os.ReadFile("profile/testdata/catalogue-h3-before-unavailable.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Aliases []string `json:"aliases"`
	}
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Aliases) != 15 {
		t.Fatal("original unavailable denominator changed")
	}
	if !slices.Contains(record.Aliases, name) {
		return false
	}
	original := profiles.MappedTLSClients[name].GetClientHelloId()
	if original.SpecFactory == nil {
		t.Fatal("frozen original placeholder changed")
	}
	if _, err = original.ToSpec(); err == nil || err.Error() != "please implement this method" {
		t.Fatal("original placeholder failure changed", err)
	}
	return true
}
