package profile

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/igor-lemon/tls-client/profiles"
)

func TestCatalogueHas83CompleteIndependentDataEntries(t *testing.T) {
	entries, err := catalogueEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 83 || len(entries) != len(profiles.MappedTLSClients) {
		t.Fatal("catalogue denominator", len(entries))
	}
	for name, old := range profiles.MappedTLSClients {
		t.Run(name, func(t *testing.T) {
			p, err := catalogueProfile(name)
			if err != nil {
				t.Fatal(err)
			}
			if !p.Catalogue() || p.Base != "" || p.TLSSpec == nil || len(p.ClientHello) != 0 || len(p.Headers) != 0 {
				t.Fatal("not a materialized handshake-only entry")
			}
			cp, err := p.ClientProfile()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cp.GetSettings(), old.GetSettings()) || !slices.Equal(cp.GetSettingsOrder(), old.GetSettingsOrder()) || cp.GetConnectionFlow() != old.GetConnectionFlow() || !slices.Equal(cp.GetPseudoHeaderOrder(), old.GetPseudoHeaderOrder()) || !reflect.DeepEqual(cp.GetPriorities(), old.GetPriorities()) && (len(cp.GetPriorities()) != 0 || len(old.GetPriorities()) != 0) {
				t.Fatal("H2 descriptor values changed")
			}
			priority := old.GetHeaderPriority()
			if priority == nil {
				got := cp.GetHeaderPriority()
				if got == nil || got.Weight != 255 || !got.Exclusive || got.StreamDep != 0 {
					t.Fatal("effective nil priority not explicit")
				}
			} else if !reflect.DeepEqual(cp.GetHeaderPriority(), priority) {
				t.Fatal("priority changed")
			}
			raw, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			q, err := Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			if q.Catalogue() || !p.Clone().Catalogue() {
				t.Fatal("catalogue provenance was forged/lost")
			}
			a, _ := json.Marshal(p)
			b, _ := json.Marshal(q)
			if string(a) != string(b) {
				t.Fatal("roundtrip changed data")
			}
			clone := p.Clone()
			clone.Behavior["h3.settings"][0] = '!'
			if clone.Behavior["h3.settings"][0] == p.Behavior["h3.settings"][0] {
				t.Fatal("shared H3 policy data")
			}

		})
	}
}
func TestCatalogueRejectsAmbiguousInventoryAndEntry(t *testing.T) {
	old := catalogueTemplate
	t.Cleanup(func() { catalogueTemplate = old })
	p := mustGet(t, "chrome_155_macos")
	raw, _ := p.Save()
	for _, data := range [][]byte{[]byte(`{"entries":{},"entries":{}}`), []byte(`{"entries":{"chrome_133":null}}`), []byte(`{"entries":{}} {}`)} {
		catalogueTemplate = data
		if _, err := catalogueProfile("chrome_133"); err == nil {
			t.Fatal("accepted bad inventory", string(data))
		}
	}
	catalogueTemplate = []byte(`{"entries":{"different":` + string(raw) + `}}`)
	if _, err := catalogueProfile("different"); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatal(err)
	}
}
func TestProductionProfileCodeHasNoGoPresetLookup(t *testing.T) {
	names, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if !strings.HasSuffix(n.Name(), ".go") || strings.HasSuffix(n.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(n.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "MappedTLSClients") || strings.Contains(string(b), "UTLSIdToSpec") {
			t.Fatal("compiled preset authority remains", n.Name())
		}
	}
}
func TestCatalogueRejectsIndirectionBeforeRecursion(t *testing.T) {
	old := catalogueTemplate
	t.Cleanup(func() { catalogueTemplate = old })
	for _, entry := range []string{`{"base":"cycle"}`, `"not an object"`} {
		catalogueTemplate = []byte(`{"entries":{"cycle":` + entry + `}}`)
		if _, err := catalogueProfile("cycle"); err == nil {
			t.Fatal("accepted invalid catalogue shape")
		}
	}
}

func TestBareCatalogueAdapterReportsInvalidHandshake(t *testing.T) {
	base := mustGet(t, "chrome_155_macos").Clone()
	base.Name = "invalid-wire"
	base.ClientHello = []byte{1, 2, 3}
	data, err := base.Save()
	if err != nil {
		t.Fatal(err)
	}
	old := catalogueTemplate
	t.Cleanup(func() { catalogueTemplate = old })
	catalogueTemplate = []byte(`{"entries":{"invalid-wire":` + string(data) + `}}`)
	facade := mustGet(t, "chrome_155_macos").Clone()
	facade.ClientHello = nil
	facade.PerConnection = nil
	facade.HTTP2 = HTTP2{}
	facade.Base = "invalid-wire"
	if _, err := facade.ClientProfile(); err == nil {
		t.Fatal("invalid handshake accepted")
	}
}

func TestCatalogueHTTP3EffectiveDescriptorMatchesFrozenExport(t *testing.T) {
	raw, err := os.ReadFile("testdata/catalogue-http3-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Entries map[string]struct {
			Settings map[uint64]uint64 `json:"settings"`
			Order    []uint64          `json:"order"`
			Pseudo   []string          `json:"pseudo"`
			Priority uint32            `json:"priority"`
			Grease   bool              `json:"grease"`
		} `json:"entries"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Entries) != 83 {
		t.Fatal("frozen HTTP3 denominator changed")
	}
	for name, want := range fixture.Entries {
		t.Run(name, func(t *testing.T) {
			p, err := catalogueProfile(name)
			if err != nil {
				t.Fatal(err)
			}
			cp, err := p.ClientProfile()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cp.GetHttp3Settings(), want.Settings) || !slices.Equal(cp.GetHttp3SettingsOrder(), want.Order) || !slices.Equal(cp.GetHttp3PseudoHeaderOrder(), want.Pseudo) || cp.GetHttp3PriorityParam() != want.Priority || cp.GetHttp3SendGreaseFrames() != want.Grease {
				t.Fatal("H3 effective descriptor changed")
			}
		})
	}
}

func TestHTTP3SettingDataCannotInventZeroChoices(t *testing.T) {
	for _, raw := range []string{`[{"id":51,"value":null}]`, `[{"id":51}]`, `[{"value":0}]`, `[{"id":51,"id":6,"value":0}]`, `[{"id":51,"Value":0}]`, `[{"id":51,"value":0,"extra":1}]`, `[null]`, `[{"id":null,"value":0}]`, `[{"id":51,"value":0.0}]`, `[{"id":51,"value":"0"}]`} {
		p := mustGet(t, "chrome_155_macos").Clone()
		p.Behavior["h3.settings"] = json.RawMessage(raw)
		if err := p.Validate(); err == nil {
			t.Fatal("ambiguous programmatic setting accepted", raw)
		}
		bytes, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Load(bytes); err == nil {
			t.Fatal("ambiguous loaded setting accepted", raw)
		}
	}
}
