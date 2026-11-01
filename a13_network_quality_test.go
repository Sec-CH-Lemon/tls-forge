package tlsforge

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/networkquality"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	fhttp "github.com/igor-lemon/fhttp"
	tc "github.com/igor-lemon/tls-client"
)

func a13EstimatedProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, e := profile.Get("chrome_156_macos")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("networkquality/testdata/chromium156-nqe-source-candidate.json")
	if e != nil {
		t.Fatal(e)
	}
	var pol networkquality.Policy
	if e := json.Unmarshal(raw, &pol); e != nil {
		t.Fatal(e)
	}
	for i := range pol.Seeds {
		pol.Seeds[i].HTTP = networkquality.Metric{}
		pol.Seeds[i].Transport = networkquality.Metric{}
		pol.Seeds[i].Downlink = networkquality.Metric{}
	}
	pol.Cache.Enabled = false
	pol.Cache.ReadAfterBootstrap = false
	pol.Compute.IntervalMS = 0
	pol.Compute.SparseRTTCapMS = 0
	pol.Compute.TransportLower = 0
	pol.Compute.UseEnd = false
	pol.Throughput.MinInflight = 1
	pol.Throughput.MinTransferBytes = 1
	pol.Throughput.HangingCWNDBytes = 0
	pol.Publication.LatencyDifference = 0
	pol.Publication.BandwidthDifference = 0
	pol.Publication.Ratio = 1
	pol.Noise.SaltMin = 1
	pol.Noise.SaltMax = 1
	pol.Noise.Buckets = 1
	pol.Noise.Base = 1
	pol.Noise.RTTQuantumMS = 10
	pol.ExcludePrivate = false
	pol.Socket.AllowPrivate = true
	p.NetworkHints = &profile.NetworkHintsPolicy{Mode: "estimated", Policy: &pol}
	p.Headers = []profile.Field(Header(p.Headers).without("rtt", "downlink", "ect"))
	p.ClientHints = []profile.Field(Header(p.ClientHints).without("rtt", "downlink", "ect"))
	p.Behavior["http.instance_scope"] = json.RawMessage(`"client"`)
	return p
}

func TestA13TypedNetworkResetRejectsOldInFlightObservations(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			answer := func(header fhttp.Header, path string) string {
				header.Set("Accept-CH", "rtt")
				header.Set("Cache-Control", "no-store")
				if path == "/held" {
					close(started)
					<-release
				} else {
					time.Sleep(40 * time.Millisecond)
				}
				return "observed"
			}
			p := a13EstimatedProfile(t)
			for i := range p.NetworkHints.Policy.Metrics {
				if p.NetworkHints.Policy.Metrics[i].Name == "http" {
					p.NetworkHints.Policy.Metrics[i].Percentile = 100
				}
			}
			first := NetworkContext{Type: "wifi", ID: "first", Generation: 1}
			opts := []Option{WithProfileValue(a13SavedEstimatedProfile(t, p)), WithNetworkContext(first), WithInsecureSkipVerify()}
			var origin string
			if protocol == "h3" {
				u, tcp, _ := h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { io.WriteString(w, answer(w.Header(), r.URL.Path)) }))
				origin = u
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
				defer func() {
					if tcp.Load() != 0 {
						t.Error("H3 fell back to TCP")
					}
				}()
			} else {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, answer(fhttp.Header(w.Header()), r.URL.Path))
				})
				origin = "https://www.example.com"
				opts = append(opts, s.dialing())
			}
			c, e := New(opts...)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if _, e = c.Get(origin + "/prime"); e != nil {
				t.Fatal(e)
			}
			oldDone := make(chan error, 1)
			go func() { _, e := c.Get(origin + "/held"); oldDone <- e }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("old request did not reach peer")
			}
			second := NetworkContext{Type: "ethernet", ID: "second", Generation: 2}
			if _, e = c.Do(&Request{URL: origin + "/reset", Network: &second}); e != nil {
				t.Fatal(e)
			}
			before, _ := c.network.state.Snapshot()
			if !before.HTTP.Available {
				t.Fatal("new epoch had no actual observation")
			}
			time.Sleep(100 * time.Millisecond)
			releaseOnce.Do(func() { close(release) })
			if e = <-oldDone; e != nil {
				t.Fatal(e)
			}
			after, _ := c.network.state.Snapshot()
			if before.HTTP != after.HTTP {
				t.Fatal("old epoch polluted new network HTTP history", before, after)
			}
		})
	}
}

func TestA13ConcurrentJSONPoliciesKeepTheirOwnWireHints(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			answer := func(header fhttp.Header, request fhttp.Header) string {
				header.Set("Accept-CH", "rtt")
				header.Set("Cache-Control", "no-store")
				header.Set("Observed-Rtt", request.Get("Rtt"))
				time.Sleep(60 * time.Millisecond)
				return "observed"
			}
			var origin string
			opts := []Option{WithInsecureSkipVerify()}
			if protocol == "h3" {
				u, tcp, _ := h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { io.WriteString(w, answer(w.Header(), r.Header)) }))
				origin = u
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
				defer func() {
					if tcp.Load() != 0 {
						t.Error("H3 fell back to TCP")
					}
				}()
			} else {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, answer(fhttp.Header(w.Header()), fhttp.Header(r.Header)))
				})
				origin = "https://www.example.com"
				opts = append(opts, s.dialing())
			}
			var clients []*Client
			for i, quantum := range []int64{7, 97} {
				p := a13EstimatedProfile(t)
				p.Name = fmt.Sprintf("independent-policy-%d", i)
				p.NetworkHints.Policy.Noise.RTTQuantumMS = quantum
				c, e := New(append(append([]Option(nil), opts...), WithProfileValue(a13SavedEstimatedProfile(t, p)))...)
				if e != nil {
					t.Fatal(e)
				}
				clients = append(clients, c)
				defer c.Close()
			}
			if clients[0].network.state == clients[1].network.state {
				t.Fatal("clients share estimator")
			}
			var wg sync.WaitGroup
			for i, c := range clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					quantum := float64([]int64{7, 97}[i])
					for step := range 5 {
						q, _ := c.network.state.Snapshot()
						expected := ""
						if step > 0 {
							if !q.HTTP.Available {
								t.Error("prior request not measured")
								return
							}
							expected = strconv.FormatInt(int64(math.Round(float64(q.HTTP.Value)/quantum)*quantum), 10)
						}
						r, e := c.Get(origin + "/concurrent")
						if e != nil {
							t.Error(e)
							return
						}
						if got := r.Header["observed-rtt"]; len(got) != 1 || got[0] != expected {
							t.Error("concurrent JSON policy crossed browser-instance boundary", i, step, got, expected)
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestA13NetworkObservationsReachClientDoOnAllProtocols(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			var mu sync.Mutex
			var seen []map[string]string
			answer := func(header fhttp.Header, request fhttp.Header, proto string) string {
				mu.Lock()
				seen = append(seen, map[string]string{"rtt": request.Get("Rtt"), "downlink": request.Get("Downlink"), "ect": request.Get("Ect"), "proto": proto})
				mu.Unlock()
				header.Set("Accept-CH", "rtt, downlink, ect")
				header.Set("Cache-Control", "no-store")
				time.Sleep(60 * time.Millisecond)
				return strings.Repeat("response-", 1024)
			}
			opts := []Option{WithProfileValue(a13EstimatedProfile(t)), WithInsecureSkipVerify()}
			var origin string
			if protocol == "h3" {
				u, tcp, _ := h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) {
					io.WriteString(w, answer(w.Header(), r.Header, r.Proto))
				}))
				origin = u
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
				defer func() {
					if tcp.Load() != 0 {
						t.Error("H3 fell back to TCP")
					}
				}()
			} else {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, answer(fhttp.Header(w.Header()), fhttp.Header(r.Header), r.Proto))
				})
				origin = "https://www.example.com"
				opts = append(opts, s.dialing())
			}
			c, e := New(opts...)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			for i := range 2 {
				res, e := c.Get(fmt.Sprintf("%s/observation%d", origin, i))
				if e != nil || len(res.Body) != 9*1024 {
					t.Fatal("production request", res, e)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 2 {
				t.Fatal("request count", len(seen))
			}
			if seen[0]["rtt"] != "" {
				t.Fatal("hint without origin opt-in", seen)
			}
			rtt, e := strconv.Atoi(seen[1]["rtt"])
			if e != nil || rtt < 40 {
				t.Fatal("no measured HTTP RTT", seen, e)
			}
			q, _ := c.network.state.Snapshot()
			if !q.HTTP.Available || q.HTTP.Value < 40 || !q.Downlink.Available || q.Downlink.Value <= 0 {
				t.Fatal("actual receive/completion observations absent", q)
			}
			if seen[1]["ect"] == "" || seen[1]["downlink"] == "" {
				t.Fatal("inconsistent generated hints", seen)
			}
		})
	}
}

func TestA13EstimatedContextsValidateAndFreshIsIndependent(t *testing.T) {
	p := a13EstimatedProfile(t)
	c, e := New(WithProfileValue(p))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	fresh, e := c.Fresh()
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	if fresh.network == c.network || fresh.network.state == c.network.state {
		t.Fatal("Fresh shares estimator state")
	}
	for _, input := range []*NetworkContext{{Type: "forged"}, {Type: "wifi", Generation: 1 << 53}, {Type: "wifi", Signal: new(int)}} {
		if input.Validate() == nil {
			continue
		}
		if _, e := c.Do(&Request{URL: "https://must-not-resolve.invalid", Network: input}); e == nil {
			t.Fatal("invalid input reached request")
		}
	}
	p.NetworkHints.Policy.Environment.Missing = "reject"
	missing, e := New(WithProfileValue(p))
	if e != nil {
		t.Fatal(e)
	}
	defer missing.Close()
	if _, e := missing.Get("https://must-not-resolve.invalid"); e == nil || !strings.Contains(e.Error(), "requires actual network context") {
		t.Fatal(e)
	}
	literalProfile := p.Clone()
	literalProfile.NetworkHints = &profile.NetworkHintsPolicy{Mode: "literal"}
	literalProfile.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`)
	literal, e := New(WithProfileValue(literalProfile))
	if e != nil {
		t.Fatal(e)
	}
	defer literal.Close()
	if _, e := literal.Do(&Request{URL: "https://must-not-resolve.invalid", Network: &NetworkContext{Type: "wifi"}}); e == nil || !strings.Contains(e.Error(), "estimated") {
		t.Fatal(e)
	}
}

func a13SavedEstimatedProfile(t *testing.T, p *profile.Profile) *profile.Profile {
	t.Helper()
	raw, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/profile.json"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := profile.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestA13JSONQuantizationAndRenameReachProductionHeaders(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			answer := func(header fhttp.Header, request fhttp.Header) string {
				header.Set("Accept-CH", "rtt, downlink, ect")
				header.Set("Cache-Control", "no-store")
				time.Sleep(120 * time.Millisecond)
				return request.Get("Rtt")
			}
			var origin string
			opts := []Option{WithInsecureSkipVerify()}
			if protocol == "h3" {
				origin, _, _ = h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { io.WriteString(w, answer(w.Header(), r.Header)) }))
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
			} else {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, answer(fhttp.Header(w.Header()), fhttp.Header(r.Header)))
				})
				origin = "https://www.example.com"
				opts = append(opts, s.dialing())
			}
			for _, quantum := range []int64{10, 100} {
				p := a13EstimatedProfile(t)
				p.Name = "independent_policy"
				p.NetworkHints.Policy.Noise.RTTQuantumMS = quantum
				p.UserAgent = "a13-virtual-persona"
				for i := range p.Headers {
					if strings.EqualFold(p.Headers[i].Name, "user-agent") {
						p.Headers[i].Value = p.UserAgent
					}
				}
				p = a13SavedEstimatedProfile(t, p)
				c, err := New(append(opts, WithProfileValue(p))...)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Get(origin + "/prime"); err != nil {
					c.Close()
					t.Fatal(err)
				}
				quality, _ := c.network.state.Snapshot()
				expected := int64(math.Round(float64(quality.HTTP.Value)/float64(quantum))) * quantum
				res, err := c.Get(origin + "/target")
				c.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(res.Body) != strconv.FormatInt(expected, 10) {
					t.Fatal("JSON-only quantization or renamed/changed-UA profile lost", protocol, quantum, string(res.Body), expected, quality)
				}
			}
		})
	}
}

func TestA13CachedAndRevalidatedResponsesDoNotFabricateHTTPObservations(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var requests atomic.Int64
			server := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Accept-CH", "rtt")
				w.Header().Set("ETag", `"v1"`)
				if r.URL.Path == "/fresh" {
					w.Header().Set("Cache-Control", "max-age=600")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				if r.Header.Get("If-None-Match") != "" {
					if r.Header.Get("If-None-Match") != `"v1"` {
						t.Error("wrong validator")
					}
					time.Sleep(220 * time.Millisecond)
					w.WriteHeader(304)
					return
				}
				time.Sleep(40 * time.Millisecond)
				io.WriteString(w, "cached entity")
			})
			p := a13EstimatedProfile(t)
			p.NetworkHints.Policy.Throughput.MinInflight = 5
			for i := range p.NetworkHints.Policy.Metrics {
				if p.NetworkHints.Policy.Metrics[i].Name == "http" {
					p.NetworkHints.Policy.Metrics[i].Percentile = 100
				}
			}
			c, err := New(WithProfileValue(a13SavedEstimatedProfile(t, p)), WithInsecureSkipVerify(), server.dialing())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for _, path := range []string{"/fresh", "/validated"} {
				beforeRequests := requests.Load()
				first, err := c.Get("https://www.example.com" + path)
				if err != nil {
					t.Fatal(err)
				}
				before, _ := c.network.state.Snapshot()
				second, err := c.Get("https://www.example.com" + path)
				if err != nil {
					t.Fatal(err)
				}
				after, _ := c.network.state.Snapshot()
				if string(first.Body) != "cached entity" || string(second.Body) != "cached entity" || second.Status != 200 {
					t.Fatal("cache contract changed", first, second)
				}
				if before.HTTP != after.HTTP {
					t.Fatal("cache/revalidation generated HTTP RTT", path, before, after)
				}
				want := int64(1)
				if path == "/validated" {
					want = 2
				}
				if requests.Load()-beforeRequests != want {
					t.Fatal("actual network requests", path, requests.Load()-beforeRequests, want)
				}
			}
		})
	}
}

func TestA13CriticalRestartAndFreshInstancesKeepDynamicHints(t *testing.T) {
	for _, protocol := range []string{"h1", "h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			var mu sync.Mutex
			var hints []string
			answer := func(header fhttp.Header, request fhttp.Header) string {
				mu.Lock()
				hints = append(hints, request.Get("Rtt"))
				mu.Unlock()
				header.Set("Accept-CH", "rtt")
				header.Set("Critical-CH", "rtt")
				header.Set("Cache-Control", "no-store")
				time.Sleep(40 * time.Millisecond)
				return "okay"
			}
			var origin string
			opts := []Option{WithInsecureSkipVerify()}
			if protocol == "h3" {
				origin, _, _ = h3Origin(t, fhttp.HandlerFunc(func(w fhttp.ResponseWriter, r *fhttp.Request) { io.WriteString(w, answer(w.Header(), r.Header)) }))
				opts = append(opts, WithTransportOption(tc.WithProtocolRacing()))
			} else {
				s := newRecorder(t, protocol, func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, answer(fhttp.Header(w.Header()), fhttp.Header(r.Header)))
				})
				origin = "https://www.example.com"
				opts = append(opts, s.dialing())
			}
			// Opaque dial options are rejected in request scope; use independent Fresh
			// instances to check that instance lifetime never becomes process lifetime.
			p := a13SavedEstimatedProfile(t, a13EstimatedProfile(t))
			c, err := New(append(opts, WithProfileValue(p))...)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for i := range 2 {
				current := c
				if i == 1 {
					current, err = c.Fresh()
					if err != nil {
						t.Fatal(err)
					}
					defer current.Close()
				}
				res, err := current.Get(origin + "/critical")
				if err != nil || string(res.Body) != "okay" {
					t.Fatal(res, err)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(hints) != 4 || hints[0] != "" || hints[2] != "" {
				t.Fatal("origin opt-in leaked between browser instances", hints)
			}
			for _, i := range []int{1, 3} {
				value, err := strconv.Atoi(hints[i])
				if err != nil || value < 20 {
					t.Fatal("critical restart used frozen/missing RTT", hints)
				}
			}
		})
	}
}

func TestA13DefaultDoOwnsNetworkStateAndOriginOptIn(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var mu sync.Mutex
			var hints []string
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				hints = append(hints, r.Header.Get("Rtt"))
				mu.Unlock()
				w.Header().Set("Accept-CH", "rtt")
				w.Header().Set("Critical-CH", "rtt")
				w.Header().Set("Cache-Control", "no-store")
				time.Sleep(40 * time.Millisecond)
				io.WriteString(w, "okay")
			}))
			server.EnableHTTP2 = protocol == "h2"
			server.StartTLS()
			defer server.Close()
			p := a13EstimatedProfile(t)
			p.Behavior["http.instance_scope"] = json.RawMessage(`"request"`)
			c, err := New(WithProfileValue(a13SavedEstimatedProfile(t, p)), WithInsecureSkipVerify())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for range 2 {
				res, err := c.Get(server.URL + "/critical")
				if err != nil || string(res.Body) != "okay" {
					t.Fatal(res, err)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(hints) != 4 || hints[0] != "" || hints[2] != "" {
				t.Fatal("separate Do calls inherited origin opt-in", hints)
			}
			for _, i := range []int{1, 3} {
				n, err := strconv.Atoi(hints[i])
				if err != nil || n < 20 {
					t.Fatal("logical request did not retain its own RTT", hints)
				}
			}
			q, _ := c.network.state.Snapshot()
			if q.HTTP.Available || q.Downlink.Available {
				t.Fatal("prototype retained a child browser's observations", q)
			}
		})
	}
}

func TestA13JSONHeaderDeliveryPreservesSourceNextStepContract(t *testing.T) {
	for _, delivery := range []string{"headers", "next-step"} {
		t.Run(delivery, func(t *testing.T) {
			p := a13EstimatedProfile(t)
			p.NetworkHints.Policy.Compute.HeaderDelivery = delivery
			if delivery == "next-step" {
				p.NetworkHints.Policy.Compute.TransactionStart = "next-step"
			}
			c, err := New(WithProfileValue(a13SavedEstimatedProfile(t, p)))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			now := time.Now()
			record := &networkRecord{owner: c.network, id: 1, method: "GET", meta: networkquality.RequestMeta{Created: now, Method: "GET", Public: true}, start: c.network.state.CaptureStart(), sent: now, headers: now.Add(120 * time.Millisecond)}
			record.finish(false)
			before, _ := c.network.state.Snapshot()
			if before.HTTP.Available != (delivery == "headers") || record.started != (delivery == "headers") {
				t.Fatal("header/transaction delivered before selected phase", delivery, before, record.started)
			}
			record.activity(1)
			after, _ := c.network.state.Snapshot()
			if !after.HTTP.Available || after.HTTP.Value != 120 || !record.started {
				t.Fatal("next positive read did not flush original header observation", delivery, after)
			}
			record.complete()
			record.headers = now.Add(600 * time.Millisecond)
			record.activity(1)
			final, _ := c.network.state.Snapshot()
			if final.HTTP != after.HTTP {
				t.Fatal("header observation replayed", after, final)
			}
		})
	}
}
