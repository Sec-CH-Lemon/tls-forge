package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func estimatedProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Get("chrome_156_linux")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func networkScenario() map[string]harness.MeasuredScenario {
	r := harness.Request{Method: "GET", URL: "https://example.test/", Headers: [][2]string{
		{"rtt", "100"}, {"downlink", "1.45"}, {"ect", "4g"}, {"accept", "*/*"},
	}}
	return map[string]harness.MeasuredScenario{"network": {H2: []harness.Request{r}, H1: []harness.Request{r}}}
}

func TestDeclaredNetworkGeneratorSuppliesRealComparisonValues(t *testing.T) {
	for _, name := range []string{"chrome_156_linux", "chrome_156_macos", "chrome_156_windows"} {
		p, err := profile.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		p.Name = "renamed-profile"
		got := networkScenario()
		if diff := harness.Compare(got, got, valuesOf(p)); len(diff) != 6 {
			t.Fatalf("old literal-only oracle did not reproduce missing generated fields: %v", diff)
		}
		values, err := comparisonValues(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"rtt", "downlink", "ect"} {
			if value, ok := values[field]; !ok || !validEstimatedHint(p.NetworkHints.Policy, field, value) {
				t.Fatalf("%s generator output %s=%q", name, field, value)
			}
		}
		if diff := harness.Compare(got, got, values); len(diff) != 0 {
			t.Fatalf("generated values not recognized: %v", diff)
		}
		if diff := estimatedHintDifferences(p, got); len(diff) != 0 {
			t.Fatal(diff)
		}
		record := estimatedHintSamples(p, got)
		if len(record.Samples) != 2 || record.Samples[0].Headers[1][1] != "1.45" || record.Samples[1].Protocol != "h1" || record.Normalization == "" {
			t.Fatalf("original normalized values lost: %+v", record)
		}
		if empty := estimatedHintSamples(p, map[string]harness.MeasuredScenario{"x": scenario}); len(empty.Samples) != 0 {
			t.Fatal("invented network samples")
		}
	}
}

func TestMissingDisabledAndInvalidNetworkGeneratorsStillFail(t *testing.T) {
	got := networkScenario()
	for _, change := range []func(*profile.Profile){
		func(p *profile.Profile) { p.NetworkHints = nil },
		func(p *profile.Profile) { p.NetworkHints = &profile.NetworkHintsPolicy{Mode: "literal"} },
	} {
		p := estimatedProfile(t)
		change(p)
		values, err := comparisonValues(p)
		if err != nil || len(harness.Compare(got, got, values)) != 6 || estimatedHintDifferences(p, got) != nil || estimatedHintSamples(p, got) != nil {
			t.Fatalf("absent generator admitted: %v %v", values, err)
		}
	}
	for _, change := range []func(*profile.Profile){
		func(p *profile.Profile) { p.NetworkHints.Policy = nil },
		func(p *profile.Profile) { p.Behavior["headers.network_hints"] = json.RawMessage(`"none"`) },
		func(p *profile.Profile) { p.NetworkHints.Policy.Noise.RTTQuantumMS = 0 },
	} {
		p := estimatedProfile(t)
		change(p)
		if _, err := comparisonValues(p); err == nil {
			t.Fatal("invalid generator admitted")
		}
	}
}

func TestEstimatedHintValuesKeepSyntaxBoundsAndQuantization(t *testing.T) {
	p := estimatedProfile(t)
	for _, tc := range []struct{ name, value string }{
		{"rtt", "-1"}, {"rtt", "01"}, {"rtt", "+50"}, {"rtt", "25"}, {"rtt", "3050"}, {"rtt", "1e3"},
		{"rtt", "999999999999999999999999"}, {"downlink", "NaN"}, {"downlink", "Inf"}, {"downlink", "-1"},
		{"downlink", "-0"}, {"downlink", "1e0"}, {"downlink", "1.450"}, {"downlink", "1.01"},
		{"downlink", "10.05"}, {"downlink", "x"}, {"ect", "5g"}, {"ect", "offline"}, {"ect", "unknown"},
	} {
		if validEstimatedHint(p.NetworkHints.Policy, tc.name, tc.value) {
			t.Errorf("invalid %s=%q accepted", tc.name, tc.value)
		}
	}
	for _, tc := range []struct{ name, value string }{
		{"rtt", "0"}, {"rtt", "3000"}, {"downlink", "0"}, {"downlink", "10"},
		{"downlink", "1.45"}, {"ect", "slow-2g"}, {"ect", "4g"}, {"accept", "*/*"},
	} {
		if !validEstimatedHint(p.NetworkHints.Policy, tc.name, tc.value) {
			t.Errorf("valid %s=%q rejected", tc.name, tc.value)
		}
	}
	got := networkScenario()
	for _, r := range [][]harness.Request{got["network"].H1, got["network"].H2} {
		r[0].Headers[0][1] = "25"
	}
	if diff := estimatedHintDifferences(p, got); len(diff) != 2 || !strings.Contains(diff[0], "over h2, request 1: rtt=\"25\"") || !strings.Contains(diff[1], "over h1") {
		t.Fatalf("invalid actual browser values not rejected: %v", diff)
	}
	// Bounds and vocabulary come from JSON policy, including cap-before-round.
	n := &p.NetworkHints.Policy.Noise
	n.RTTCapMS, n.RTTQuantumMS = 125, 50
	n.DownlinkCapKbps, n.DownlinkQuantumKbps = 125, 50
	p.NetworkHints.Policy.ECT = p.NetworkHints.Policy.ECT[:1]
	n.MissingECT = "3g"
	if !validEstimatedHint(p.NetworkHints.Policy, "rtt", "150") || validEstimatedHint(p.NetworkHints.Policy, "rtt", "200") ||
		!validEstimatedHint(p.NetworkHints.Policy, "downlink", "0.15") || validEstimatedHint(p.NetworkHints.Policy, "downlink", "0.2") ||
		!validEstimatedHint(p.NetworkHints.Policy, "ect", "3g") || validEstimatedHint(p.NetworkHints.Policy, "ect", "4g") {
		t.Fatal("renderer policy changes ignored")
	}
}

func TestPinnedRejectsInvalidGeneratorBeforeBrowserIO(t *testing.T) {
	b := laidOut(t)
	var asked tlsforge.MeasureOptions
	seams(t, "Google Chrome "+stableOf(t), matching(&asked))
	p := estimatedProfile(t)
	p.NetworkHints.Policy = nil
	profileOf = func(string) (*profile.Profile, error) { return p, nil }
	if _, err := hold(context.Background(), options{profile: "chrome", requests: b.requests, decoding: b.decoding}); err == nil || asked.Browser != "" {
		t.Fatalf("invalid generator reached comparison: %v %v", asked, err)
	}
	// Network-dependent changes pass; header removal, order, build and body
	// changes still go through the unchanged complete harness comparison.
	p = estimatedProfile(t)
	values, err := comparisonValues(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*harness.Request){
		func(r *harness.Request) { r.Headers = r.Headers[1:] },
		func(r *harness.Request) { r.Headers[0], r.Headers[1] = r.Headers[1], r.Headers[0] },
		func(r *harness.Request) { r.Body = "changed" },
	} {
		want, got := networkScenario(), networkScenario()
		r := got["network"].H2[0]
		change(&r)
		s := got["network"]
		s.H2[0] = r
		got["network"] = s
		if diff := harness.Compare(want, got, values); len(diff) == 0 {
			t.Fatal("non-environment difference hidden")
		}
	}
}

func TestGeneratedComparisonFieldsReachActualClientDo(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			p := estimatedProfile(t)
			p.Name = "validator-wire-profile"
			if !enabled {
				p.NetworkHints = nil
				p.Behavior["headers.network_hints"] = json.RawMessage(`"none"`)
			}
			// Exercise the serialized profile contract, not just a Go object.
			raw, err := p.Save()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := profile.Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var seen []http.Header
			var protocols []string
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, r.Header.Clone())
				protocols = append(protocols, r.Proto)
				mu.Unlock()
				w.Header().Set("Cache-Control", "no-store")
				if r.URL.Path == "/start" {
					w.Header().Set("Accept-CH", "rtt, downlink, ect, sec-ch-ua-full-version, sec-ch-ua-full-version-list")
					w.Header().Set("Location", "/end")
					w.WriteHeader(http.StatusFound)
					return
				}
				_, _ = w.Write([]byte("okay"))
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			client, err := tlsforge.New(tlsforge.WithProfileValue(loaded), tlsforge.WithInsecureSkipVerify())
			if err != nil {
				server.Close()
				t.Fatal(err)
			}
			response, err := client.Get(server.URL + "/start")
			client.Close()
			server.Close()
			if err != nil || response.Status != http.StatusOK || string(response.Body) != "okay" {
				t.Fatalf("actual Do: %v %v", response, err)
			}
			mu.Lock()
			if len(seen) != 2 {
				t.Fatalf("redirect chain requests: %d", len(seen))
			}
			wantProto := "HTTP/1.1"
			if h2 {
				wantProto = "HTTP/2.0"
			}
			for _, proto := range protocols {
				if proto != wantProto {
					t.Fatalf("negotiated %s, want %s", proto, wantProto)
				}
			}
			for _, name := range []string{"rtt", "downlink", "ect"} {
				if seen[0].Get(name) != "" || (seen[1].Get(name) != "") != enabled {
					t.Fatalf("JSON availability %s, enabled=%v: %v", name, enabled, seen)
				}
				if enabled && !validEstimatedHint(loaded.NetworkHints.Policy, name, seen[1].Get(name)) {
					t.Fatalf("production value violates renderer: %s=%q", name, seen[1].Get(name))
				}
			}
			for _, name := range []string{"sec-ch-ua-full-version", "sec-ch-ua-full-version-list"} {
				if got, want := seen[1].Get(name), valuesOf(loaded)[name]; got != want || got == "" {
					t.Fatalf("JSON build hint did not reach Do: %s=%q want %q", name, got, want)
				}
			}
			mu.Unlock()
		}
	}
}
