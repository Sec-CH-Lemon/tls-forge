package tlsforge

import (
	"sync"
	"testing"
)

func TestRecorderSnapshotsDoNotAliasArrivingBodies(t *testing.T) {
	r := &recorder{}
	req := &keptRequest{headers: [][2]string{{"x-proof", "original"}}, priority: &[3]uint32{1, 2, 3}}
	r.keep(req)
	before := r.requests()[0]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			req.bodyMu.Lock()
			req.body += "x"
			req.bodyMu.Unlock()
		}
	}()
	for i := 0; i < 1000; i++ {
		snapshot := r.requests()[0]
		_ = len(snapshot.body)
	}
	wg.Wait()
	if before.body != "" || len(r.requests()[0].body) != 1000 {
		t.Fatal("snapshot changed or body lost")
	}
	before.headers[0][1] = "changed"
	before.priority[0] = 99
	after := r.requests()[0]
	if after.headers[0][1] != "original" || after.priority[0] != 1 {
		t.Fatal("snapshot aliases headers/priority")
	}
}
