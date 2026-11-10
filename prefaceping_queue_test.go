// This regression deliberately lets the real connection read a fast peer
// response before HEADERS Write returns. Chrome queues the PING decision at
// header creation; that late read must not suppress the already due PING.
package tlsforge

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/conntap"
)

type pingInterleaveTap struct {
	*seeingTap
	armed       atomic.Bool
	response    chan struct{}
	sawResponse atomic.Bool
	watching    atomic.Bool
}

func (p *pingInterleaveTap) Dialed(c net.Conn, began time.Time) net.Conn {
	return &pingInterleaveConn{Conn: p.seeingTap.Dialed(c, began), p: p}
}

type pingInterleaveConn struct {
	net.Conn
	p *pingInterleaveTap
}

func (c *pingInterleaveConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.p.watching.Load() {
		select {
		case c.p.response <- struct{}{}:
		default:
		}
	}
	return n, err
}
func (c *pingInterleaveConn) Write(b []byte) (int, error) {
	if !c.p.armed.CompareAndSwap(true, false) {
		return c.Conn.Write(b)
	}
	c.p.watching.Store(true)
	n, err := c.Conn.Write(b)
	select {
	case <-c.p.response:
		c.p.sawResponse.Store(true)
		time.Sleep(25 * time.Millisecond)
	case <-time.After(500 * time.Millisecond):
	}
	c.p.watching.Store(false)
	return n, err
}
func TestPrefacePingQueuedBeforeHeaderWriteCompletes(t *testing.T) {
	site := newPingSite(t)
	c := newTestClient(t, WithProfileValue(policyFile(t, map[string]any{"h2.preface_ping_idle_ms": 150, "h2.preface_ping_hung_ms": 400})), WithTimeout(5*time.Second))
	tap := &pingInterleaveTap{seeingTap: &seeingTap{}, response: make(chan struct{}, 1)}
	get(t, c, site.url+"/a", tap)
	site.expect(t, "1 H1")
	time.Sleep(300 * time.Millisecond)
	tap.armed.Store(true)
	ctx := conntap.With(context.Background(), tap)
	res, err := c.Do(&Request{URL: site.url + "/b", Context: ctx})
	if err != nil || res.Text() != "ok" {
		t.Fatalf("request: %v", err)
	}
	if !tap.sawResponse.Load() {
		t.Fatal("fixture did not read the fast peer response before HEADERS Write returned")
	}
	site.expect(t, "1 H3", "1 P1")
}
