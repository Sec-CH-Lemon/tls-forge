package tlsforge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/networkquality"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
)

func TestNetworkMetadataProviderErrorsAndExplicitFallback(t *testing.T) {
	p := a13EstimatedProfile(t).NetworkHints.Policy.Environment
	failure := errors.New("metadata unavailable")
	if _, e := networkContextFromRoute(p, func([]string) (networkRoute, error) { return networkRoute{}, failure }, net.InterfaceByIndex); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	p.Identity = "route-interface-addresses"
	route := func([]string) (networkRoute, error) { return networkRoute{index: 1, kind: "ethernet"}, nil }
	if _, e := networkContextFromRoute(p, route, func(int) (*net.Interface, error) { return nil, failure }); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	if _, e := networkContextFromRoute(p, route, func(int) (*net.Interface, error) { return nil, nil }); e == nil {
		t.Fatal("missing physical interface accepted")
	}
	p.Source = "system"
	p.Missing = "reject"
	system := func(networkquality.EnvironmentPolicy) (NetworkContext, error) { return NetworkContext{}, failure }
	if _, e := networkInputFrom(p, nil, system); !errors.Is(e, failure) {
		t.Fatal("mandatory metadata error hidden", e)
	}
	p.Missing = "fallback"
	p.Fallback = NetworkContext{Type: "unknown", Signal: new(int)}
	value, e := networkInputFrom(p, nil, system)
	if e != nil || value.Type != "unknown" {
		t.Fatal(value, e)
	}
	*value.Signal = 3
	if *p.Fallback.Signal != 0 {
		t.Fatal("fallback aliases profile")
	}
}

func TestNetworkInputsFailBeforeRequestAndPreserveState(t *testing.T) {
	p := a13EstimatedProfile(t)
	for _, option := range []Option{WithHeaders(Header{{Name: "rtt", Value: "100"}}), WithNetworkContext(NetworkContext{Type: "made-up"})} {
		if c, e := New(WithProfileValue(p), option); e == nil {
			c.Close()
			t.Fatal("invalid network input constructed client")
		}
	}
	literal := p.Clone()
	literal.NetworkHints = &profile.NetworkHintsPolicy{Mode: "literal"}
	literal.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`)
	if c, e := New(WithProfileValue(literal), WithNetworkContext(NetworkContext{Type: "wifi"})); e == nil {
		c.Close()
		t.Fatal("literal profile ignored requested metadata")
	}
	bad := p.Clone()
	bad.NetworkHints.Policy.Algorithm = "made-up"
	if _, e := newNetworkObserver(bad, nil); e == nil {
		t.Fatal("invalid estimator accepted")
	}
	if _, e := newNetworkObserver(p, &NetworkContext{Type: "made-up"}); e == nil {
		t.Fatal("invalid constructor input accepted")
	}
	c, e := New(WithProfileValue(p))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Do(&Request{URL: "https://must-not-resolve.invalid/", Header: Header{{Name: "downlink", Value: "1.45"}}}); e == nil {
		t.Fatal("literal request bypassed estimated profile")
	}
	before, _ := c.network.state.Snapshot()
	if e = c.prepareNetworkFrom(nil, func(networkquality.EnvironmentPolicy, *NetworkContext) (NetworkContext, error) {
		return NetworkContext{}, io.ErrUnexpectedEOF
	}); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal("provider error lost", e)
	}
	if e = c.prepareNetworkFrom(nil, func(networkquality.EnvironmentPolicy, *NetworkContext) (NetworkContext, error) {
		return NetworkContext{Type: "unexpected-provider-class"}, nil
	}); e == nil {
		t.Fatal("provider bypassed context validation")
	}
	after, _ := c.network.state.Snapshot()
	if before != after {
		t.Fatal("rejected metadata changed network state")
	}
	if c.network.publicPeer(nil) || c.network.publicPeer(networkTestAddr("not-an-endpoint")) {
		t.Fatal("missing/malformed peer treated as public")
	}
	c.network.transport(false).HTTP2RTT(&net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 443}, 15*time.Millisecond)
}

func TestNetworkValidationMatchesDoWithoutSamplingOrChangingState(t *testing.T) {
	p := a13EstimatedProfile(t)
	c, e := New(WithProfileValue(p), WithNetworkContext(NetworkContext{Type: "wifi"}))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	before, _ := c.network.state.Snapshot()
	for _, req := range []*Request{{URL: "https://must-not-resolve.invalid/", Network: &NetworkContext{Type: "invalid"}}, {URL: "https://must-not-resolve.invalid/", Header: Header{{Name: "rtt", Value: "100"}}}} {
		if c.Validate(req) == nil {
			t.Fatal("Validate accepted input Do rejects")
		}
	}
	if e = c.Validate(&Request{URL: "https://must-not-resolve.invalid/"}); e != nil {
		t.Fatal(e)
	}
	after, _ := c.network.state.Snapshot()
	if before != after {
		t.Fatal("offline validation mutated estimator")
	}
	literal := p.Clone()
	literal.NetworkHints = &profile.NetworkHintsPolicy{Mode: "literal"}
	literal.Behavior["headers.network_hints"] = json.RawMessage(`"literal"`)
	l, e := New(WithProfileValue(literal))
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if l.Validate(&Request{URL: "https://must-not-resolve.invalid/", Network: &NetworkContext{Type: "wifi"}}) == nil {
		t.Fatal("literal validation ignored metadata")
	}
	if l.prepareNetwork(&NetworkContext{Type: "wifi"}) == nil {
		t.Fatal("literal request preparation ignored metadata")
	}
}

func TestNetworkMetadataFailureStopsDoBeforeOriginIO(t *testing.T) {
	p := a13EstimatedProfile(t)
	p.NetworkHints.Policy.Environment.Source = "system"
	c, e := New(WithProfileValue(p))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.network.input = func(networkquality.EnvironmentPolicy, *NetworkContext) (NetworkContext, error) {
		return NetworkContext{}, io.ErrUnexpectedEOF
	}
	if _, e = c.Get("https://must-not-resolve.invalid/"); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal("metadata failure did not stop request", e)
	}
}

func TestNetworkJSONStartPhaseControlsPublishedNavigationEstimate(t *testing.T) {
	for _, phase := range []string{"request", "headers"} {
		t.Run(phase, func(t *testing.T) {
			p := a13EstimatedProfile(t)
			p.NetworkHints.Policy.Compute.TransactionStart = phase
			p.NetworkHints.Policy.Compute.Navigation = true
			for i := range p.NetworkHints.Policy.Sources {
				if p.NetworkHints.Policy.Sources[i].Name == "h2-ping" {
					p.NetworkHints.Policy.Sources[i].Recompute = false
				}
			}
			c, e := New(WithProfileValue(a13SavedEstimatedProfile(t, p)))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.network.state.ObserveEndToEnd(123 * time.Millisecond)
			before, _ := c.network.state.Snapshot()
			if before.HTTP.Available {
				t.Fatal("unpublished observation computed before selected phase")
			}
			req, _ := fhttp.NewRequest("GET", "https://example.com/", nil)
			ch := &chain{client: c, browser: &browserRequest{kind: KindNavigation}}
			_, e = c.networkRoundTrip(ch, req, networkTestTrip(func(*fhttp.Request) (*fhttp.Response, error) {
				q, _ := c.network.state.Snapshot()
				if q.HTTP.Available != (phase == "request") {
					t.Error("navigation estimate published at wrong phase", phase, q)
				}
				return &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Cache-Control": {"no-store"}}, Body: fhttp.NoBody}, nil
			}))
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

type networkTestAddr string

func (a networkTestAddr) Network() string { return "test" }
func (a networkTestAddr) String() string  { return string(a) }

func TestNetworkRawReadAndKernelSampleRemainSeparate(t *testing.T) {
	p := a13EstimatedProfile(t)
	p.NetworkHints.Policy.Socket.TCPSource = "kernel-tcp-info"
	owner, e := newNetworkObserver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	observed := owner.wrapTCP(near).(*networkConn)
	go func() { _, _ = far.Write([]byte("bytes")) }()
	b := make([]byte, 5)
	n, e := observed.readWithRTT(b, func(actual net.Conn) (time.Duration, bool) {
		if actual != near {
			t.Error("kernel query used a different connection")
		}
		return 7 * time.Millisecond, true
	})
	if n != 5 || e != nil || string(b) != "bytes" {
		t.Fatal(n, e, string(b))
	}
	q, _ := owner.state.Snapshot()
	if !q.Transport.Available || q.Transport.Value != 7 || owner.state.CaptureStart().ReceivedBytes != 5 {
		t.Fatal("kernel sample and receive bytes conflated", q)
	}
}

type networkTestTrip func(*fhttp.Request) (*fhttp.Response, error)

func (f networkTestTrip) RoundTrip(r *fhttp.Request) (*fhttp.Response, error) { return f(r) }

type networkOwnedBody struct {
	io.ReadCloser
	released int
}

func (b *networkOwnedBody) ResponseBodyReleased() { b.released++ }

func TestNetworkTraceOwnershipAndProxyEventsDoNotInventSamples(t *testing.T) {
	p := a13EstimatedProfile(t)
	c, e := New(WithProfileValue(p))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	request, _ := fhttp.NewRequest("GET", "https://example.com/", nil)
	ch := &chain{client: c}
	_, e = c.networkRoundTrip(ch, request, networkTestTrip(func(r *fhttp.Request) (*fhttp.Response, error) {
		trace := httptrace.ContextClientTrace(r.Context())
		trace.DNSDone(httptrace.DNSDoneInfo{Addrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}})
		trace.WriteHeadersStart("CONNECT")
		trace.GotResponseHeaders("CONNECT", 200)
		trace.GotResponseBodyBytes("CONNECT", 5)
		trace.GotResponseBodyDone("CONNECT")
		trace.GotConn(httptrace.GotConnInfo{})
		return nil, io.ErrUnexpectedEOF
	}))
	if e == nil {
		t.Fatal("transport error hidden")
	}
	q, _ := c.network.state.Snapshot()
	if q.HTTP.Available {
		t.Fatal("proxy response generated origin RTT", q)
	}
	record := &networkRecord{owner: c.network}
	record.activity(0)
	body := io.NopCloser(strings.NewReader("kept"))
	if observedCacheBody(request, body) != body {
		t.Fatal("unobserved cached body changed")
	}
	done := 0
	underlying := &networkOwnedBody{ReadCloser: body}
	cached := &cacheBody{ReadCloser: underlying, observedDone: func() { done++ }}
	cached.ResponseBodyReleased()
	if done != 1 || underlying.released != 1 {
		t.Fatal("ownership not forwarded", done, underlying.released)
	}
	b, e := io.ReadAll(cached)
	if e != nil || string(b) != "kept" {
		t.Fatal("ownership released actual body early", string(b), e)
	}
	// The cached-only path remains usable without an estimator.
	c.network = nil
	request, _ = fhttp.NewRequestWithContext(context.Background(), "GET", "https://example.com/", nil)
	res, e := c.networkRoundTrip(ch, request, networkTestTrip(func(*fhttp.Request) (*fhttp.Response, error) {
		return &fhttp.Response{StatusCode: 200, Header: fhttp.Header{"Cache-Control": {"no-store"}}, Body: fhttp.NoBody}, nil
	}))
	if e != nil || res.StatusCode != 200 {
		t.Fatal(res, e)
	}
}
