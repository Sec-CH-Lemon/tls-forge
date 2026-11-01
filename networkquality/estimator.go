package networkquality

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strconv"
	"sync"
	"time"
)

// RequestMeta describes eligibility and request creation, distinct from send time.
type RequestMeta struct {
	Created    time.Time
	Method     string
	Public     bool
	Cached     bool
	Navigation bool
}
type activeRequest struct {
	meta      RequestMeta
	lastRead  time.Time
	degrading bool
}
type socketState struct {
	firstQUIC bool
	last      time.Time
}
type cachedQuality struct {
	key     string
	quality Quality
}

// State owns bounded observations, cache, publication and one browser-instance salt.
// Its mutex never spans actual I/O, caller callbacks, entropy reads or body close.
type State struct {
	mu                                       sync.Mutex
	policy                                   Policy
	now                                      func() time.Time
	salt                                     uint64
	context                                  Context
	changed, computed, lastSocket, lastSweep time.Time
	histories                                map[string]*Buffer
	metricPolicies                           map[string]MetricPolicy
	sources                                  map[string]SourceRule
	quality, published                       Quality
	cache                                    []cachedQuality
	cached, bootstrap                        bool
	transportCount, endCount                 int
	lastRTTCount, lastDownCount, newSamples  int
	requests                                 map[uint64]activeRequest
	sockets                                  map[uint64]socketState
	socketOrder                              []uint64
	bytes, windowBytes                       uint64
	window                                   time.Time
	throughputDisabled                       bool
}

// NewState validates all policy data and draws a fresh salt before network I/O.
// The caller supplies the clock and entropy source to make tests deterministic.
func NewState(policy Policy, network Context, now func() time.Time, entropy io.Reader) (*State, error) {
	if e := policy.Validate(); e != nil {
		return nil, e
	}
	if now == nil || entropy == nil {
		return nil, fmt.Errorf("requires clock and entropy source")
	}
	if e := network.Validate(); e != nil {
		return nil, e
	}
	draw, e := rand.Int(entropy, big.NewInt(policy.Noise.SaltMax-policy.Noise.SaltMin+1))
	if e != nil {
		return nil, fmt.Errorf("network salt: %w", e)
	}
	s := &State{policy: policy.Clone(), now: now, salt: uint64(draw.Int64() + policy.Noise.SaltMin), histories: map[string]*Buffer{}, metricPolicies: map[string]MetricPolicy{}, sources: map[string]SourceRule{}, requests: map[uint64]activeRequest{}, sockets: map[uint64]socketState{}}
	for _, m := range policy.Metrics {
		b, _ := NewBuffer(m.Buffer)
		s.histories[m.Name] = b
		s.metricPolicies[m.Name] = m
	}
	for _, r := range policy.Sources {
		s.sources[r.Name] = r
	}
	s.context = network.Clone()
	s.changed = now()
	s.quality.ECT = policy.UnknownECT
	s.published.ECT = policy.UnknownECT
	s.seedLocked()
	s.bootstrap = policy.Cache.ReadAfterBootstrap
	return s, nil
}

func (s *State) cacheKey(c Context) string {
	if s.policy.Cache.Key == "connection-type" {
		return c.Type
	}
	return c.Type + "\x00" + c.ID
}
func (s *State) storeLocked(q Quality) {
	if !s.policy.Cache.Enabled || q.ECT == s.policy.UnknownECT || q.ECT == s.policy.OfflineECT {
		return
	}
	key := s.cacheKey(s.context)
	s.cache = slices.DeleteFunc(s.cache, func(c cachedQuality) bool { return c.key == key })
	if len(s.cache) == s.policy.Cache.Capacity {
		copy(s.cache, s.cache[1:])
		s.cache = s.cache[:len(s.cache)-1]
	}
	s.cache = append(s.cache, cachedQuality{key, q})
}
func (s *State) seedLocked() {
	var seed NetworkSeed
	for _, r := range s.policy.Seeds {
		if r.Type == s.context.Type {
			seed = r
			break
		}
	}
	if !s.readCacheLocked() {
		if seed.HTTP.Available {
			s.addLocked("seed-http", "", seed.HTTP.Value)
		}
		if seed.Transport.Available {
			s.addLocked("seed-transport", "", seed.Transport.Value)
		}
		if seed.Downlink.Available {
			s.addLocked("seed-http", "downlink", seed.Downlink.Value)
		}
	}
	s.computeLocked()
}
func (s *State) readCacheLocked() bool {
	if !s.policy.Cache.Enabled {
		return false
	}
	key := s.cacheKey(s.context)
	for i := len(s.cache) - 1; i >= 0; i-- {
		if s.cache[i].key != key {
			continue
		}
		q := s.cache[i].quality
		for _, r := range s.policy.ECT {
			if q.ECT == r.Label {
				if !q.Transport.Available {
					q.Transport = Metric{r.TypicalTransportMS, true}
				}
				if !q.Downlink.Available {
					q.Downlink = Metric{r.TypicalKbps, true}
				}
				break
			}
		}
		s.cache[i].quality = q
		if q.HTTP.Available {
			s.addLocked("cache-http", "", q.HTTP.Value)
		}
		if q.Transport.Available {
			s.addLocked("cache-transport", "", q.Transport.Value)
		}
		if q.Downlink.Available {
			s.addLocked("cache-http", "downlink", q.Downlink.Value)
		}
		s.computeLocked()
		return true
	}
	return false
}

// Bootstrap completes an explicitly selected deferred in-memory cache read. It
// preserves the early seed observations instead of treating them as constants.
func (s *State) Bootstrap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bootstrap {
		s.bootstrap = false
		s.readCacheLocked()
	}
}

// ChangeNetwork resets histories and windows even when the connection type is
// unchanged. Old active requests degrade new windows until their completion.
func (s *State) ChangeNetwork(c Context) error {
	if e := c.Validate(); e != nil {
		return e
	}
	c = c.Clone()
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Type == s.context.Type && c.ID == s.context.ID && c.Generation == s.context.Generation {
		s.context.Signal = c.Signal
		return nil
	}
	s.storeLocked(s.quality)
	s.context = c
	s.changed = s.now()
	s.computed = time.Time{}
	s.lastSocket = time.Time{}
	s.lastSweep = time.Time{}
	s.cached = false
	for _, b := range s.histories {
		b.Clear()
	}
	s.quality = Quality{ECT: s.policy.UnknownECT}
	s.newSamples = 0
	s.lastRTTCount = 0
	s.lastDownCount = 0
	s.window = time.Time{}
	for id, r := range s.requests {
		r.degrading = true
		s.requests[id] = r
	}
	s.boundRequestsLocked()
	clear(s.sockets)
	s.socketOrder = nil
	s.seedLocked()
	return nil
}

func (s *State) addLocked(source, metric string, value int64) {
	s.addAtLocked(source, metric, value, s.now())
}
func (s *State) addAtLocked(source, metric string, value int64, at time.Time) {
	rule, ok := s.sources[source]
	if !ok || value < 0 || value > math.MaxInt32 || s.cached && rule.Default {
		return
	}
	targets := rule.Categories
	if metric != "" {
		targets = []string{metric}
	}
	if rule.Cached {
		s.cached = true
		for _, name := range targets {
			removed := map[string]bool{}
			for n, r := range s.sources {
				if r.Default {
					removed[n] = true
				}
			}
			s.histories[name].RemoveSources(removed)
		}
	}
	now := at
	signal := s.context.signal()
	if rule.Default || rule.Cached {
		signal = -1
	}
	for _, name := range targets {
		s.histories[name].Add(Observation{At: now, Value: value, Signal: signal, Source: source})
	}
	s.newSamples++
	if rule.Recompute && s.shouldComputeLocked() {
		s.computeLocked()
	}
}
func (s *State) shouldComputeLocked() bool {
	c := s.policy.Compute
	now := s.now()
	rttCount := len(s.histories["http"].observations) + len(s.histories["transport"].observations)
	down := len(s.histories["downlink"].observations)
	return now.Sub(s.computed) >= time.Duration(c.IntervalMS)*time.Millisecond || !s.changed.Before(s.computed) || s.quality.ECT == s.policy.UnknownECT || float64(s.lastRTTCount)*c.GrowthRatio < float64(rttCount) || float64(s.lastDownCount)*c.GrowthRatio < float64(down) || s.newSamples >= c.NewSamples
}
func (s *State) metricLocked(name string) (Metric, int) {
	// Policy validation requires every metric; all callers use implemented names.
	p := s.metricPolicies[name]
	begin := time.Time{}
	if p.RecentMS > 0 {
		begin = s.now().Add(-time.Duration(p.RecentMS) * time.Millisecond)
	}
	value, count, ok := s.histories[name].Percentile(s.now(), begin, s.context.signal(), p.Percentile)
	if !ok && p.FallbackAll {
		value, count, ok = s.histories[name].Percentile(s.now(), time.Time{}, s.context.signal(), p.Percentile)
	}
	return Metric{value, ok}, count
}

func (s *State) computeLocked() {
	now := s.now()
	oldECT := s.quality.ECT
	q := Quality{ECT: s.policy.UnknownECT}
	q.HTTP, _ = s.metricLocked("http")
	var transN, endN int
	q.Transport, transN = s.metricLocked("transport")
	q.EndToEnd, endN = s.metricLocked("end")
	q.Downlink, _ = s.metricLocked("downlink")
	c := s.policy.Compute
	if s.context.Type == "none" {
		q = Quality{ECT: s.policy.OfflineECT}
	} else if q.HTTP.Available {
		http := float64(q.HTTP.Value)
		if q.Transport.Available && transN >= c.MinTransportSamples {
			http = max(http, float64(q.Transport.Value)*c.TransportLower)
		}
		if c.UseEnd && q.EndToEnd.Available && endN >= c.MinEndSamples {
			http = max(http, float64(q.EndToEnd.Value)*c.EndLower)
			if c.EndUpper > 0 {
				http = min(http, float64(q.EndToEnd.Value)*c.EndUpper)
			}
		}
		if c.SparseRTTCapMS > 0 && transN < c.MinTransportSamples && (!c.UseEnd || endN < c.MinEndSamples) && (!s.cached || now.Sub(s.changed) > time.Duration(c.CacheGraceMS)*time.Millisecond) {
			http = min(http, float64(c.SparseRTTCapMS))
		}
		q.HTTP.Value = int64(http)
		for _, r := range s.policy.ECT {
			if q.HTTP.Value >= r.MinHTTPMS {
				q.ECT = r.Label
				if r.ClampDownlink && q.Downlink.Available && c.DownlinkTypicalCap > 0 {
					q.Downlink.Value = min(q.Downlink.Value, int64(float64(r.TypicalKbps)*c.DownlinkTypicalCap))
				}
				break
			}
		}
	}
	s.quality = q
	s.transportCount = transN
	s.endCount = endN
	s.computed = now
	s.lastRTTCount = len(s.histories["http"].observations) + len(s.histories["transport"].observations)
	s.lastDownCount = len(s.histories["downlink"].observations)
	s.newSamples = 0
	p := s.policy.Publication
	if changedMetric(s.published.HTTP, q.HTTP, p.LatencyDifference, p.Ratio) || changedMetric(s.published.Transport, q.Transport, p.LatencyDifference, p.Ratio) || changedMetric(s.published.Downlink, q.Downlink, p.BandwidthDifference, p.Ratio) {
		s.published.HTTP = q.HTTP
		s.published.Transport = q.Transport
		s.published.EndToEnd = q.EndToEnd
		s.published.Downlink = q.Downlink
	}
	s.published.ECT = q.ECT
	if oldECT != q.ECT {
		s.storeLocked(q)
	}
}
func changedMetric(old, current Metric, difference int64, ratio float64) bool {
	if old.Available != current.Available {
		return true
	}
	if !old.Available {
		return false
	}
	if absInt(old.Value-current.Value) < difference {
		return false
	}
	return !(float32(old.Value) < float32(ratio)*float32(current.Value) && float32(current.Value) < float32(ratio)*float32(old.Value))
}
func absInt(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// Snapshot returns actual computed and published values without forcing recompute.
func (s *State) Snapshot() (computed, published Quality) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quality, s.published
}

// ObserveTransport inserts actual socket/QUIC samples under the selected source,
// filtering private/synthetic/too-frequent notifications by policy.
func (s *State) ObserveTransport(id uint64, source string, public bool, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.policy.Socket
	if source == "tcp" && p.TCPSource == "none" || source != "tcp" && source != "quic" || !public && !p.AllowPrivate || rtt <= time.Duration(p.MinRTTUS)*time.Microsecond {
		return
	}
	row, exists := s.sockets[id]
	if !exists {
		if len(s.sockets) == p.Capacity {
			delete(s.sockets, s.socketOrder[0])
			s.socketOrder = s.socketOrder[1:]
		}
		s.socketOrder = append(s.socketOrder, id)
	}
	if source == "quic" && !row.firstQUIC {
		row.firstQUIC = true
		s.sockets[id] = row
		if p.SkipFirstQUIC {
			return
		}
	}
	now := s.now()
	if !row.last.IsZero() && now.Sub(row.last) < time.Duration(p.PerSocketMS)*time.Millisecond && now.Sub(s.lastSocket) < time.Duration(p.GlobalMS)*time.Millisecond {
		return
	}
	row.last = now
	s.sockets[id] = row
	s.lastSocket = now
	s.addLocked(source, "", int64(rtt/time.Millisecond))
}

// ForgetSocket removes only a closed connection's notification state.
func (s *State) ForgetSocket(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sockets, id)
	s.socketOrder = slices.DeleteFunc(s.socketOrder, func(v uint64) bool { return v == id })
}

// ObserveEndToEnd inserts a completed H2 PING measurement, separate from TCP RTT.
func (s *State) ObserveEndToEnd(rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rtt > 0 {
		s.addLocked("h2-ping", "", int64(rtt/time.Millisecond))
	}
}

// StartInfo preserves the actual transaction-start timestamp and global receive
// counter even when the selected browser rule defers notification until headers.
type StartInfo struct {
	At            time.Time
	ReceivedBytes uint64
}

// CaptureStart takes an actual observation snapshot, without resetting counters.
func (s *State) CaptureStart() StartInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StartInfo{s.now(), s.bytes}
}

// StartRequest records an immediate transaction start.
func (s *State) StartRequest(id uint64, meta RequestMeta) {
	s.StartRequestAt(id, meta, s.CaptureStart())
}

// StartRequestAt delivers a previously captured start. It never substitutes the
// later header callback timestamp or byte counter for the original observation.
func (s *State) StartRequestAt(id uint64, meta RequestMeta, info StartInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if meta.Navigation && s.policy.Compute.Navigation || s.shouldComputeLocked() {
		s.computeLocked()
	}
	if s.throughputDisabled {
		return
	}
	degrading := s.policy.ExcludePrivate && !meta.Public || meta.Created.Before(s.changed)
	if !degrading && !slices.Contains(s.policy.Methods, meta.Method) {
		return
	}
	s.sweepLocked(id)
	s.requests[id] = activeRequest{meta, info.At, degrading}
	if !s.boundRequestsLocked() {
		return
	}

	if degrading {
		s.window = time.Time{}
	} else {
		s.startWindowAtLocked(info)
	}
}

// Each source set has its own profile bound. Losing degrading work disables
// measurement; overflowing eligible work clears that set without losing the other.
func (s *State) boundRequestsLocked() bool {
	active, degrading := 0, 0
	for _, request := range s.requests {
		if request.degrading {
			degrading++
		} else {
			active++
		}
	}
	limit := s.policy.Throughput.MaxRequests
	if degrading > limit {
		clear(s.requests)
		s.window = time.Time{}
		s.throughputDisabled = true
		return false
	}
	if active > limit {
		for id, request := range s.requests {
			if !request.degrading {
				delete(s.requests, id)
			}
		}
		s.window = time.Time{}
		return false
	}
	return true
}

// Headers records the full-headers-end minus protocol-write-start observation.
func (s *State) Headers(id uint64, meta RequestMeta, sent, received time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy.ExcludePrivate && !meta.Public || s.policy.ExcludeCached && meta.Cached || meta.Created.Before(s.changed) || !slices.Contains(s.policy.Methods, meta.Method) || sent.IsZero() || !received.After(sent) {
		return
	}
	if meta.Navigation && s.policy.Compute.Navigation {
		s.computeLocked()
	}
	rtt := received.Sub(sent)
	c := s.policy.Compute
	hanging := true
	transN, endN := s.transportCount, s.endCount
	if c.UseEnd && s.quality.EndToEnd.Available && endN >= c.MinEndSamples && float64(rtt/time.Microsecond) < float64(s.quality.EndToEnd.Value)*1000*c.HangingTransport {
		hanging = false
	}
	if s.quality.Transport.Available && transN >= c.MinTransportSamples && float64(rtt/time.Microsecond) < float64(s.quality.Transport.Value)*1000*c.HangingTransport {
		hanging = false
	}
	http := c.MissingRTTMS
	if s.quality.HTTP.Available {
		http = s.quality.HTTP.Value
	}
	if float64(rtt/time.Microsecond) < float64(http)*1000*c.HangingHTTP || rtt <= time.Duration(c.HangingMinMS)*time.Millisecond {
		hanging = false
	}
	if hanging {
		return
	}
	s.addAtLocked("http", "", int64(rtt/time.Millisecond), received)
	s.activityAtLocked(id, received)
}

// BodyActivity stamps positive encoded-body reads, independently of the receive counter.
func (s *State) BodyActivity(id uint64, n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activityLocked(id)
}
func (s *State) activityLocked(id uint64) { s.activityAtLocked(id, s.now()) }
func (s *State) activityAtLocked(id uint64, at time.Time) {
	s.sweepLocked(id)
	if r, ok := s.requests[id]; ok && !r.degrading {
		r.lastRead = at
		s.requests[id] = r
	}
}

// Received adds actual transport bytes. It never substitutes decoded body size.
func (s *State) Received(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytes += uint64(n)
}
func (s *State) startWindowLocked() { s.startWindowAtLocked(StartInfo{s.now(), s.bytes}) }
func (s *State) startWindowAtLocked(info StartInfo) {
	if s.throughputDisabled || !s.window.IsZero() {
		return
	}
	active := 0
	for _, r := range s.requests {
		if r.degrading {
			return
		}
		active++
	}
	if active >= s.policy.Throughput.MinInflight {
		s.window = info.At
		s.windowBytes = info.ReceivedBytes
	}
}
func (s *State) sweepLocked(id uint64) {
	now := s.now()
	p := s.policy.Throughput
	http := p.MissingHTTPMS
	if s.quality.HTTP.Available {
		http = s.quality.HTTP.Value
	}
	all := s.lastSweep.IsZero() || now.Sub(s.lastSweep) >= time.Duration(p.SweepMS)*time.Millisecond
	if all {
		s.lastSweep = now
	}
	erased := false
	for key, r := range s.requests {
		if r.degrading || !all && key != id {
			continue
		}
		age := now.Sub(r.lastRead)
		if float64(age/time.Microsecond) >= float64(http)*1000*p.HangingRTTMultiplier && age >= time.Duration(p.HangingMinMS)*time.Millisecond {
			delete(s.requests, key)
			erased = true
		}
	}
	if erased {
		s.window = time.Time{}
	}
}

// CompleteRequest measures eligible aggregate windows and releases tracked work.
func (s *State) CompleteRequest(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.requests[id]; !ok {
		return
	}
	s.sweepLocked(id)
	p := s.policy.Throughput
	if !s.window.IsZero() {
		duration := s.now().Sub(s.window)
		bytes := s.bytes - s.windowBytes
		if bytes >= uint64(p.MinTransferBytes) && duration > 0 {
			http := s.policy.Compute.MissingRTTMS
			if s.quality.HTTP.Available {
				http = s.quality.HTTP.Value
			}
			receivedPerRTT := float64(bytes) * float64(time.Duration(http)*time.Millisecond) / float64(duration)
			if receivedPerRTT < float64(p.HangingCWNDBytes)*p.HangingCWNDMultiplier {
				clear(s.requests)
				s.window = time.Time{}
				return
			}
			rate := math.Ceil(float64(bytes) * 8 / duration.Seconds() / 1000)
			value := int64(min(rate, math.MaxInt32))
			s.window = time.Time{}
			s.startWindowLocked()
			if value > 0 {
				s.addLocked("http", "downlink", value)
			}
		}
	}
	delete(s.requests, id)
	if len(s.requests) < p.MinInflight {
		s.window = time.Time{}
	}
	s.startWindowLocked()
}

// Hints derives all aliases from one published snapshot and one stable salt.
func (s *State) Hints(host string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.policy.Noise
	q := s.published
	hash := LibcxxHash64(host, p.Hash == "libcxx-city64-le-abi2") + s.salt
	if p.SumBits == 32 {
		hash = uint64(uint32(hash))
	}
	factor := p.Base + float64(hash%p.Buckets)*p.Step
	rtt := float64(p.MissingRTTMS)
	if q.HTTP.Available {
		rtt = math.Trunc(float64(q.HTTP.Value)*1000*factor) / 1000
	}
	rtt = min(rtt, float64(p.RTTCapMS))
	rtt = math.Round(rtt/float64(p.RTTQuantumMS)) * float64(p.RTTQuantumMS)
	down := float64(p.MissingDownlinkKbps)
	if q.Downlink.Available {
		down = float64(q.Downlink.Value)
	}
	down = min(down*factor, float64(p.DownlinkCapKbps))
	down = math.Round(down/float64(p.DownlinkQuantumKbps)) * float64(p.DownlinkQuantumKbps) / 1000
	ect := q.ECT
	if ect == s.policy.UnknownECT || ect == s.policy.OfflineECT {
		ect = p.MissingECT
	}
	return map[string]string{"rtt": strconv.FormatInt(int64(rtt), 10), "downlink": strconv.FormatFloat(down, 'f', -1, 64), "ect": ect}
}
