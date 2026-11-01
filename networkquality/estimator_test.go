package networkquality

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func candidatePolicy(t *testing.T) Policy {
	t.Helper()
	raw, e := os.ReadFile("testdata/chromium156-nqe-source-candidate.json")
	if e != nil {
		t.Fatal(e)
	}
	var p Policy
	if e = json.Unmarshal(raw, &p); e != nil {
		t.Fatal(e)
	}
	return p
}

type testClock struct{ ns atomic.Int64 }

func newClock() *testClock                   { c := &testClock{}; c.ns.Store(time.Unix(1000, 0).UnixNano()); return c }
func (c *testClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }
func stateFor(t *testing.T, p Policy, c *testClock) *State {
	t.Helper()
	s, e := NewState(p, Context{Type: "wifi", Signal: nil}, c.now, bytes.NewReader(make([]byte, 1024)))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func blankSeeds(p *Policy) {
	for i := range p.Seeds {
		p.Seeds[i].HTTP = Metric{}
		p.Seeds[i].Transport = Metric{}
		p.Seeds[i].Downlink = Metric{}
	}
}

func TestStateBootstrapExplainsPlatformSeedThenTypicalCacheFill(t *testing.T) {
	p := candidatePolicy(t)
	c := newClock()
	s := stateFor(t, p, c)
	before, _ := s.Snapshot()
	if before.HTTP.Value != 116 || before.Transport.Value != 66 || before.Downlink.Value != 2658 || before.ECT != "4g" {
		t.Fatal("platform seed", before)
	}
	c.advance(time.Millisecond)
	s.Bootstrap()
	after, published := s.Snapshot()
	if after.HTTP.Value != 116 || after.Transport.Value != 125 || after.Downlink.Value != 1600 || published.Downlink.Value != 1600 {
		t.Fatal("deferred missing-field fill", after, published)
	}
	s.Bootstrap()
	again, _ := s.Snapshot()
	if again != after {
		t.Fatal("bootstrap replay changed state")
	}
	if s.salt != 1 {
		t.Fatal("test entropy not stable")
	}
}

func TestStateNoInputAndFreshStateRemainExplicitAndIndependent(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	c := newClock()
	s := stateFor(t, p, c)
	s.Bootstrap()
	q, _ := s.Snapshot()
	if q.HTTP.Available || q.Downlink.Available || q.ECT != "unknown" {
		t.Fatal(q)
	}
	h := s.Hints("example.test")
	if h["rtt"] != "0" || h["ect"] != "4g" || h["downlink"] == "1.45" {
		t.Fatal("missing input silently became captured strings", h)
	}
	other := stateFor(t, p, c)
	s.ObserveEndToEnd(time.Second)
	q, _ = s.Snapshot()
	oq, _ := other.Snapshot()
	if !q.HTTP.Available || oq.HTTP.Available {
		t.Fatal("cross-instance observation leak")
	}
	for i := range p.Metrics {
		p.Metrics[i].Buffer.Capacity = 1
	}
	p.Sources[0].Categories[0] = "end"
	p.Seeds[0].Type = "changed"
	p.Methods[0] = "POST"
	p.ECT[0].Label = "changed"
	if reflect.DeepEqual(s.policy, p) {
		t.Fatal("caller policy aliases state")
	}
}

func TestHeadersFilterEligibilityAndUseBothTimingEdges(t *testing.T) {
	p := candidatePolicy(t)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	blankSeeds(&p)
	c := newClock()
	s := stateFor(t, p, c)
	good := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	sent := c.now()
	for _, edit := range []func(*RequestMeta, *time.Time, *time.Time){
		func(m *RequestMeta, _, _ *time.Time) { m.Public = false }, func(m *RequestMeta, _, _ *time.Time) { m.Cached = true }, func(m *RequestMeta, _, _ *time.Time) { m.Method = "POST" }, func(m *RequestMeta, _, _ *time.Time) { m.Created = m.Created.Add(-time.Second) }, func(_ *RequestMeta, a, _ *time.Time) { *a = time.Time{} }, func(_ *RequestMeta, a, b *time.Time) { *b = *a },
	} {
		m := good
		a, b := sent, sent.Add(time.Second)
		edit(&m, &a, &b)
		s.Headers(1, m, a, b)
	}
	q, _ := s.Snapshot()
	if q.HTTP.Available {
		t.Fatal("ineligible observation accepted", q)
	}
	c.advance(225 * time.Millisecond)
	s.Headers(1, good, sent, c.now())
	q, _ = s.Snapshot()
	if q.HTTP.Value != 225 || !q.HTTP.Available {
		t.Fatal("wrong full-headers duration", q)
	}
	before := len(s.histories["http"].observations)
	s.Headers(1, good, sent, sent.Add(time.Hour))
	if len(s.histories["http"].observations) != before {
		t.Fatal("hanging GET accepted")
	}
}

func TestTransportSourcesAndNotificationLimitsAreIndependent(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	p.Socket.Capacity = 2
	p.Socket.TCPSource = "kernel-tcp-info"
	c := newClock()
	s := stateFor(t, p, c)
	s.ObserveTransport(1, "tcp", false, time.Second)
	s.ObserveTransport(1, "tcp", true, time.Microsecond)
	s.ObserveTransport(1, "bogus", true, time.Second)
	if len(s.sockets) != 0 {
		t.Fatal("invalid/private notifications retained")
	}
	s.ObserveTransport(1, "quic", true, 200*time.Millisecond)
	if len(s.histories["transport"].observations) != 0 {
		t.Fatal("first QUIC estimate retained")
	}
	s.ObserveTransport(1, "quic", true, 300*time.Millisecond)
	s.ObserveTransport(1, "quic", true, 900*time.Millisecond)
	if len(s.histories["transport"].observations) != 1 || len(s.histories["end"].observations) != 1 {
		t.Fatal("notification filtering/source categories")
	}
	c.advance(200 * time.Millisecond)
	s.ObserveTransport(1, "quic", true, 300*time.Millisecond)
	s.ObserveTransport(2, "tcp", true, 400*time.Millisecond)
	s.ObserveTransport(3, "tcp", true, 500*time.Millisecond)
	if len(s.sockets) != 2 {
		t.Fatal("socket history unbounded")
	}
	if _, ok := s.sockets[1]; ok {
		t.Fatal("old socket not evicted")
	}
	s.ForgetSocket(2)
	if len(s.sockets) != 1 {
		t.Fatal("socket ownership not released")
	}
	s.ObserveEndToEnd(0)
	s.ObserveEndToEnd(600 * time.Millisecond)
	if len(s.histories["http"].observations) != 1 {
		t.Fatal("PING not kept distinct")
	}
}

func TestJSONThresholdQuantizationAndStateMutationChangeHints(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	p.Noise.Base = 1
	p.Noise.Step = 0
	c := newClock()
	s := stateFor(t, p, c)
	deliver := func(target *State, delay time.Duration) {
		sent := c.now()
		meta := RequestMeta{Created: sent, Method: "GET", Public: true}
		c.advance(delay)
		target.Headers(1, meta, sent, c.now())
	}
	deliver(s, 225*time.Millisecond)
	if s.Hints("example.test")["rtt"] != "250" {
		t.Fatal(s.Hints("example.test"))
	}
	p.Noise.RTTQuantumMS = 100
	p.ECT[2].MinHTTPMS = 200
	other := stateFor(t, p, c)
	deliver(other, 225*time.Millisecond)
	h := other.Hints("example.test")
	if h["rtt"] != "200" || h["ect"] != "3g" {
		t.Fatal("JSON rules not applied", h)
	}
	before := s.Hints("example.test")
	c.advance(time.Second)
	deliver(s, 500*time.Millisecond)
	after := s.Hints("example.test")
	if reflect.DeepEqual(before, after) {
		t.Fatal("frozen generator")
	}
	if s.salt != other.salt {
		t.Fatal("equal test entropy differs")
	}
}

func TestNetworkResetRetainsSaltButResetsWindowsAndUsesCachePartition(t *testing.T) {
	p := candidatePolicy(t)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	p.Cache.Capacity = 1
	c := newClock()
	s := stateFor(t, p, c)
	s.Bootstrap()
	m := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	s.StartRequest(1, m)
	salt := s.salt
	if e := s.ChangeNetwork(Context{Type: "wifi", ID: "same-type-new-network", Generation: 1, Signal: nil}); e != nil {
		t.Fatal(e)
	}
	if !s.requests[1].degrading || !s.window.IsZero() || s.salt != salt {
		t.Fatal("network reset/lifecycle")
	}
	q, _ := s.Snapshot()
	if !q.HTTP.Available {
		t.Fatal("network cache not reused", q)
	}
	if e := s.ChangeNetwork(Context{Type: "none", Generation: 2, Signal: nil}); e != nil {
		t.Fatal(e)
	}
	q, _ = s.Snapshot()
	if q.ECT != "offline" {
		t.Fatal(q)
	}
	if e := s.ChangeNetwork(Context{Type: "wifi", Generation: 3, Signal: nil}); e != nil {
		t.Fatal(e)
	}
	s.CompleteRequest(1)
	if len(s.requests) != 0 {
		t.Fatal("old epoch request leaked")
	}
	before, _ := s.Snapshot()
	if e := s.ChangeNetwork(s.context); e != nil {
		t.Fatal(e)
	}
	after, _ := s.Snapshot()
	if before != after {
		t.Fatal("unchanged context reset")
	}
	if e := s.ChangeNetwork(Context{Type: "wifi", Signal: signalForTest(5)}); e == nil {
		t.Fatal("invalid context")
	}
}

func TestAggregateThroughputRequiresConcurrentLargeRealReceiveCounter(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	c := newClock()
	s := stateFor(t, p, c)
	m := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	s.ObserveEndToEnd(100 * time.Millisecond)
	for i := uint64(1); i <= 4; i++ {
		s.StartRequest(i, m)
	}
	s.Received(1 << 20)
	c.advance(100 * time.Millisecond)
	s.CompleteRequest(1)
	if len(s.histories["downlink"].observations) != 0 {
		t.Fatal("single/four-request rate became throughput")
	}
	for i := uint64(2); i <= 4; i++ {
		s.CompleteRequest(i)
	}
	for i := uint64(10); i <= 15; i++ {
		s.StartRequest(i, m)
	}
	s.Received(1024)
	c.advance(100 * time.Millisecond)
	s.CompleteRequest(10)
	if len(s.histories["downlink"].observations) != 0 {
		t.Fatal("small transfer accepted")
	}
	for i := uint64(11); i <= 15; i++ {
		s.CompleteRequest(i)
	}
	for i := uint64(20); i <= 25; i++ {
		s.StartRequest(i, m)
	}
	s.Received(1 << 20)
	c.advance(time.Second)
	s.BodyActivity(20, 1)
	s.CompleteRequest(20)
	obs := s.histories["downlink"].observations
	if len(obs) != 1 || obs[0].Value != 8389 {
		t.Fatal("not actual aggregate received bytes/time", obs)
	}
	s.BodyActivity(999, 0)
	s.Received(0)
	s.CompleteRequest(999)
}

func TestThroughputDegradingAndHangingRequestsBoundResources(t *testing.T) {
	p := candidatePolicy(t)
	p.Throughput.MaxRequests = 6
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	c := newClock()
	s := stateFor(t, p, c)
	good := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	private := good
	private.Public = false
	s.StartRequest(1, private)
	for i := uint64(2); i <= 6; i++ {
		s.StartRequest(i, good)
	}
	if !s.window.IsZero() {
		t.Fatal("private work did not degrade window")
	}
	s.CompleteRequest(1)
	if s.window.IsZero() {
		t.Fatal("window not opened after degrading work completed")
	}
	c.advance(6 * time.Minute)
	s.BodyActivity(2, 10)
	if len(s.requests) != 0 || !s.window.IsZero() {
		t.Fatal("hanging requests/window retained")
	}
	s.StartRequest(8, RequestMeta{Created: c.now(), Method: "POST", Public: true})
	if len(s.requests) != 0 {
		t.Fatal("non-GET tracked")
	}
	for i := uint64(10); i < 17; i++ {
		s.StartRequest(i, good)
	}
	if s.throughputDisabled || len(s.requests) != 0 {
		t.Fatal("good request overflow not bounded")
	}
	for i := uint64(20); i < 27; i++ {
		s.StartRequest(i, private)
	}
	if !s.throughputDisabled || len(s.requests) != 0 {
		t.Fatal("degrading overflow must disable lost tracking")
	}
	s.StartRequest(30, good)
	if len(s.requests) != 0 {
		t.Fatal("disabled tracker restarted silently")
	}
}

func TestUnderutilizedWindowAndClampedRTTCorrections(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	p.Throughput.HangingMinMS = 1000000
	p.Socket.TCPSource = "kernel-tcp-info"
	c := newClock()
	s := stateFor(t, p, c)
	s.ObserveEndToEnd(100 * time.Millisecond)
	m := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	for i := uint64(1); i <= 6; i++ {
		s.StartRequest(i, m)
	}
	s.Received(32768)
	c.advance(time.Minute)
	s.CompleteRequest(1)
	if len(s.requests) != 0 || len(s.histories["downlink"].observations) != 0 {
		t.Fatal("under-utilized window accepted")
	}
	for i := 0; i < 6; i++ {
		c.advance(time.Second)
		s.ObserveTransport(uint64(i), "tcp", true, 500*time.Millisecond)
		s.ObserveEndToEnd(time.Second)
	}
	s.Headers(99, m, c.now(), c.now().Add(10*time.Second))
	q, _ := s.Snapshot()
	if q.HTTP.Value < 1000 || q.HTTP.Value > 3000 {
		t.Fatal("RTT bounds not applied", q)
	}
}

func TestEstimatorConcurrencyAndStableNoiseForOneInstance(t *testing.T) {
	p := candidatePolicy(t)
	c := newClock()
	s := stateFor(t, p, c)
	s.Bootstrap()
	expected := s.Hints("example.test")
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			for range 10 {
				s.Hints("example.test")
				s.Received(1)
				s.BodyActivity(id, 1)
				s.ObserveTransport(id, "tcp", false, time.Second)
				s.ForgetSocket(id)
			}
		}(uint64(i))
	}
	wg.Wait()
	if !reflect.DeepEqual(expected, s.Hints("example.test")) {
		t.Fatal("request-scoped salt redraw")
	}
	p2 := p.Clone()
	p2.Cache.Key = "identity"
	other := stateFor(t, p2, c)
	if e := other.ChangeNetwork(Context{Type: "wifi", ID: "new", Signal: nil}); e != nil {
		t.Fatal(e)
	}
}

func TestStateRejectsInvalidInputsBeforeDrawingEntropy(t *testing.T) {
	p := candidatePolicy(t)
	c := newClock()
	for _, tc := range []struct {
		p       Policy
		c       Context
		clock   func() time.Time
		entropy io.Reader
	}{
		{Policy{}, Context{Type: "wifi", Signal: nil}, c.now, bytes.NewReader(nil)}, {p, Context{}, c.now, bytes.NewReader(nil)}, {p, Context{Type: "wifi", Signal: nil}, nil, bytes.NewReader(nil)}, {p, Context{Type: "wifi", Signal: nil}, c.now, nil}, {p, Context{Type: "wifi", Signal: nil}, c.now, bytes.NewReader(nil)},
	} {
		if _, e := NewState(tc.p, tc.c, tc.clock, tc.entropy); e == nil {
			t.Fatal("invalid constructor accepted")
		}
	}
}

func TestRecentWindowFallbackCacheEvictionAndSignalUpdate(t *testing.T) {
	p := candidatePolicy(t)
	p.Cache.Enabled = false
	p.Cache.ReadAfterBootstrap = false
	for i := range p.Metrics {
		p.Metrics[i].RecentMS = 1
	}
	c := newClock()
	s := stateFor(t, p, c)
	c.advance(time.Second)
	// A navigation triggers recomputation; no recent sample falls back to history.
	s.StartRequest(1, RequestMeta{Created: c.now(), Method: "POST", Navigation: true, Public: true})
	q, _ := s.Snapshot()
	if !q.HTTP.Available {
		t.Fatal("history fallback lost")
	}
	if e := s.ChangeNetwork(Context{Type: "wifi", Signal: signalForTest(4)}); e != nil {
		t.Fatal(e)
	}
	if len(s.histories["http"].observations) != 1 || s.context.signal() != 4 {
		t.Fatal("signal-only change cleared history")
	}
	p.Cache.Enabled = true
	p.Cache.Key = "identity"
	p.Cache.Capacity = 1
	other := stateFor(t, p, c)
	for i, id := range []string{"a", "b", "c"} {
		if e := other.ChangeNetwork(Context{Type: "wifi", ID: id, Generation: uint64(i), Signal: nil}); e != nil {
			t.Fatal(e)
		}
	}
	if len(other.cache) != 1 {
		t.Fatal("network cache not bounded", len(other.cache))
	}
	for _, entry := range other.cache {
		if !entry.quality.HTTP.Available {
			t.Fatal("in-memory known-ECT cache must contain HTTP")
		}
	}
}

func TestMetricBoundsSparseClampAndCachedDefaultSuppression(t *testing.T) {
	p := candidatePolicy(t)
	p.Compute.IntervalMS = 0
	blankSeeds(&p)
	c := newClock()
	s := stateFor(t, p, c)
	s.ObserveEndToEnd(time.Duration(math.MaxInt64))
	if len(s.histories["http"].observations) != 0 {
		t.Fatal("overflow metric accepted")
	}
	s.mu.Lock()
	s.addLocked("unregistered", "", 1)
	s.mu.Unlock()
	if len(s.histories["http"].observations) != 0 {
		t.Fatal("unknown source accepted")
	}
	m := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	s.Headers(1, m, c.now(), c.now().Add(400*time.Millisecond))
	q, _ := s.Snapshot()
	if q.HTTP.Value != 175 {
		t.Fatal("sparse sample cap", q)
	}
	p = candidatePolicy(t)
	s = stateFor(t, p, c)
	s.Bootstrap()
	before := len(s.histories["http"].observations)
	s.mu.Lock()
	s.addLocked("seed-http", "", 99)
	s.mu.Unlock()
	if len(s.histories["http"].observations) != before {
		t.Fatal("default observations replaced cached estimate")
	}
}

func TestComputedRTTCountsAndDownlinkClampsAreAppliedTogether(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	p.Socket.TCPSource = "kernel-tcp-info"
	for i := range p.Seeds {
		p.Seeds[i].Downlink = Metric{2658, true}
	}
	c := newClock()
	s := stateFor(t, p, c)
	for i := range 6 {
		c.advance(time.Second)
		s.ObserveTransport(uint64(i), "tcp", true, 500*time.Millisecond)
		s.ObserveEndToEnd(time.Second)
	}
	q, _ := s.Snapshot()
	if q.HTTP.Value != 1000 || q.Downlink.Value != 1400 || q.ECT != "3g" {
		t.Fatal("RTT correction/downlink clamp", q)
	}
	before := len(s.histories["http"].observations)
	m := RequestMeta{Created: c.now(), Method: "GET", Public: true, Navigation: true}
	s.Headers(1, m, c.now(), c.now().Add(3*time.Second))
	if len(s.histories["http"].observations) != before+1 {
		t.Fatal("qualified RTT rejected despite sufficient computed transport/end samples")
	}
}

func TestHangingDecisionUsesCountsFromLastComputation(t *testing.T) {
	p := candidatePolicy(t)
	p.Compute.IntervalMS = 1000000
	p.Compute.NewSamples = 65536
	p.Compute.GrowthRatio = 1000000
	p.Socket.TCPSource = "kernel-tcp-info"
	p.Cache.ReadAfterBootstrap = false
	for i := range p.Seeds {
		p.Seeds[i].HTTP = Metric{115, true}
		p.Seeds[i].Transport = Metric{500, true}
	}
	c := newClock()
	s := stateFor(t, p, c)
	c.advance(time.Millisecond)
	// A computation strictly after the epoch makes the following observations
	// pending; equal timestamps deliberately force another computation in source.
	s.StartRequest(0, RequestMeta{Created: c.now(), Method: "POST", Public: true, Navigation: true})
	m := RequestMeta{Created: c.now(), Method: "GET", Public: true}
	for i := range 4 {
		c.advance(time.Second)
		s.ObserveTransport(uint64(i), "tcp", true, 500*time.Millisecond)
	}
	if len(s.histories["transport"].observations) != 5 || s.transportCount != 1 {
		t.Fatal("fixture did not retain a pending recompute", s.transportCount)
	}
	before := len(s.histories["http"].observations)
	s.Headers(1, m, c.now(), c.now().Add(time.Second))
	if len(s.histories["http"].observations) != before {
		t.Fatal("live counts substituted for last computed counts")
	}
}

func signalForTest(value int) *int { return &value }

func TestDeferredTransactionStartKeepsOriginalReceiveCounterAndTime(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Compute.IntervalMS = 0
	p.Compute.SparseRTTCapMS = 0
	p.Throughput.MinInflight = 1
	p.Throughput.HangingCWNDMultiplier = 0
	c := newClock()
	s := stateFor(t, p, c)
	info := s.CaptureStart()
	s.Received(65536)
	c.advance(time.Second)
	m := RequestMeta{Created: info.At, Method: "GET", Public: true}
	s.StartRequestAt(1, m, info)
	if s.window != info.At || s.windowBytes != info.ReceivedBytes {
		t.Fatal("deferred callback replaced original timing/counter")
	}
	s.CompleteRequest(1)
	rows := s.histories["downlink"].observations
	if len(rows) != 1 || rows[0].Value != 525 {
		t.Fatal("did not include actual bytes since transaction start", rows)
	}
}

func TestThroughputBoundsKeepEligibleAndDegradingSetsSeparate(t *testing.T) {
	p := candidatePolicy(t)
	p.Throughput.MaxRequests = 2
	p.Throughput.MinInflight = 1
	clock := newClock()
	now := clock.now()
	s := stateFor(t, p, clock)
	meta := RequestMeta{Created: now, Method: "GET", Public: true}
	s.StartRequest(1, meta)
	s.StartRequest(2, meta)
	meta.Public = false
	s.StartRequest(3, meta)
	if s.throughputDisabled || len(s.requests) != 3 {
		t.Fatal("independent sets share capacity", s.throughputDisabled, len(s.requests))
	}
	meta.Public = true
	s.StartRequest(4, meta)
	if s.throughputDisabled || len(s.requests) != 1 || !s.requests[3].degrading {
		t.Fatal("eligible overflow lost degrading set", s.throughputDisabled, s.requests)
	}
	meta.Public = false
	s.StartRequest(5, meta)
	s.StartRequest(6, meta)
	if !s.throughputDisabled || len(s.requests) != 0 {
		t.Fatal("degrading overflow retained unreliable history")
	}
}

func TestDeferredHTTPObservationRetainsOriginalHeaderTimestamp(t *testing.T) {
	p := candidatePolicy(t)
	blankSeeds(&p)
	p.Cache.Enabled = false
	clock := newClock()
	s := stateFor(t, p, clock)
	sent := clock.now()
	received := sent.Add(100 * time.Millisecond)
	clock.advance(61 * time.Second)
	s.Headers(1, RequestMeta{Created: sent, Method: "GET", Public: true}, sent, received)
	rows := s.histories["http"].observations
	if len(rows) != 1 || !rows[0].At.Equal(received) {
		t.Fatal("delivery time replaced actual headers-end timestamp", rows)
	}
}
