package tlsforge

import (
	"sync/atomic"
	"testing"
	"time"
)

type closingPool struct {
	*idler
	calls            atomic.Int32
	entered, release chan struct{}
}

func (p *closingPool) CloseIdleConnections() {
	if p.calls.Add(1) == 1 {
		close(p.entered)
	}
	<-p.release
}

func TestConcurrentIdleClosesWaitForTheSameIO(t *testing.T) {
	tr, _ := idlers(t, "", refuseNone)
	s, err := tr.siteOf("old")
	if err != nil {
		t.Fatal(err)
	}
	pool := &closingPool{idler: &idler{}, entered: make(chan struct{}), release: make(chan struct{})}
	s.inner.HttpClient = pool
	tr.releaseSite(s)
	first, second := make(chan struct{}), make(chan struct{})
	go func() { tr.closeIdle(); close(first) }()
	<-pool.entered
	go func() { tr.closeIdle(); close(second) }()
	select {
	case <-second:
		t.Error("second idle close returned before pending I/O finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(pool.release)
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("idle close did not finish")
		}
	}
	if calls := pool.calls.Load(); calls != 1 {
		t.Fatalf("%d overlapping close calls, want one shared operation", calls)
	}
}
