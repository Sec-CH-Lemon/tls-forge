package networkquality

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

func FuzzNetworkStateEventSequences(f *testing.F) {
	raw, err := os.ReadFile("testdata/chromium156-nqe-source-candidate.json")
	if err != nil {
		f.Fatal(err)
	}
	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		f.Fatal(err)
	}
	policy.Throughput.MaxRequests = 6
	policy.Throughput.MinInflight = 2
	policy.Socket.Capacity = 6
	for _, seed := range [][]byte{{}, {0, 1, 1, 5, 1, 30, 1, 255, 2, 0, 1, 0}, {0, 0, 1, 1, 4, 1, 1, 9, 0, 0, 1, 7, 2, 0, 1, 0}, {0, 0, 1, 1, 3, 0, 0, 3, 2, 0, 1, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		clock := newClock()
		s, err := NewState(policy, Context{Type: "wifi"}, clock.now, bytes.NewReader(make([]byte, 32)))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i+3 < len(data) && i < 4096; i += 4 {
			clock.advance(time.Duration(data[i+1]) * time.Millisecond)
			id := uint64(data[i+2] % 16)
			method := "GET"
			if data[i+3]&1 != 0 {
				method = "POST"
			}
			meta := RequestMeta{Created: clock.now(), Method: method, Public: data[i+2]&1 != 0}
			switch data[i] % 8 {
			case 0:
				s.StartRequest(id, meta)
			case 1:
				s.Received(int(data[i+3]) * 1024)
				s.BodyActivity(id, int(data[i+3]))
			case 2:
				s.CompleteRequest(id)
			case 3:
				if err := s.ChangeNetwork(Context{Type: []string{"wifi", "unknown", "none"}[data[i+2]%3], ID: fmt.Sprint(data[i+3]), Generation: uint64(i)}); err != nil {
					t.Fatal(err)
				}
			case 4:
				sent := clock.now()
				clock.advance(time.Duration(data[i+3]) * time.Millisecond)
				s.Headers(id, meta, sent, clock.now())
			case 5:
				s.ObserveTransport(id, "quic", meta.Public, time.Duration(data[i+3])*time.Millisecond)
			case 6:
				s.ObserveEndToEnd(time.Duration(data[i+3]) * time.Millisecond)
			case 7:
				s.Bootstrap()
				s.ForgetSocket(id)
			}
			active, degrading := 0, 0
			for _, request := range s.requests {
				if request.degrading {
					degrading++
				} else {
					active++
				}
			}
			if active > policy.Throughput.MaxRequests || degrading > policy.Throughput.MaxRequests || s.throughputDisabled && len(s.requests) != 0 {
				t.Fatal("request history unbounded")
			}
			if !s.window.IsZero() && (degrading != 0 || active < policy.Throughput.MinInflight) {
				t.Fatal("ineligible throughput window")
			}
			if len(s.sockets) > policy.Socket.Capacity || len(s.socketOrder) != len(s.sockets) {
				t.Fatal("socket history unbounded or inconsistent")
			}
			for _, metric := range policy.Metrics {
				b := s.histories[metric.Name]
				if len(b.observations) > metric.Buffer.Capacity {
					t.Fatal("metric history unbounded")
				}
				for i, row := range b.observations {
					if row.Value < 0 || i > 0 && row.At.Before(b.observations[i-1].At) {
						t.Fatal("invalid metric sequence")
					}
				}
			}
			hints := s.Hints("example.test")
			if _, err := strconv.ParseUint(hints["rtt"], 10, 64); err != nil {
				t.Fatal("invalid RTT hint", hints)
			}
			if down, err := strconv.ParseFloat(hints["downlink"], 64); err != nil || down < 0 {
				t.Fatal("invalid downlink hint", hints)
			}
		}
	})
}
