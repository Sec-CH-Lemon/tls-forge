package tlsforge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	tc "github.com/igor-lemon/tls-client"
)

type badFirstTLS struct {
	net.Listener
	accepts atomic.Int32
	bad     int32
	alerts  chan []byte
}

func (l *badFirstTLS) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.accepts.Add(1) > l.bad {
			return c, nil
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			head := make([]byte, 5)
			if _, err := io.ReadFull(c, head); err != nil {
				return
			}
			if head[0] != 22 {
				return
			}
			hello := make([]byte, binary.BigEndian.Uint16(head[3:]))
			if _, err := io.ReadFull(c, hello); err != nil {
				return
			}
			// Complete TLS record, syntactically invalid empty ServerHello.
			_, _ = c.Write([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
			alert := make([]byte, 7)
			if _, err := io.ReadFull(c, alert); err == nil {
				l.alerts <- alert
			}
		}()
	}
}

func TestChromeRetriesAProtocolFailureBeforeSendingHTTP(t *testing.T) {
	for _, bad := range []int32{1, 100} {
		t.Run(string('0'+bad%10), func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, _ := io.ReadAll(r.Body)
				_, _ = w.Write(body)
			}))
			ln := &badFirstTLS{Listener: srv.Listener, bad: bad, alerts: make(chan []byte, 4)}
			srv.Listener = ln
			srv.StartTLS()
			defer srv.Close()
			// A POST without a context, as given.
			c, err := New(WithProfileValue(asGivenProfile(t, "chrome_155_macos")), WithInsecureSkipVerify(), WithTimeout(5*time.Second), WithTransportOption(tc.WithForceHttp1()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			res, err := c.Do(&Request{URL: srv.URL, Method: "POST", Body: []byte("one effect")})
			if bad == 1 {
				if err != nil || string(res.Body) != "one effect" || requests.Load() != 1 {
					t.Fatalf("request=%d response=%v error=%v", requests.Load(), res, err)
				}
			} else if err == nil || requests.Load() != 0 {
				t.Fatalf("invalid peer accepted or HTTP replayed: %v %d", err, requests.Load())
			}
			if ln.accepts.Load() != 2 {
				t.Fatalf("attempts=%d, want exactly two", ln.accepts.Load())
			}
			for i := int32(0); i < bad && i < 2; i++ {
				select {
				case a := <-ln.alerts:
					if a[0] != 21 || a[5] != 2 || a[6] != 10 {
						t.Fatalf("wrong fatal unexpected_message: %x", a)
					}
				case <-time.After(time.Second):
					t.Fatal("no actual unexpected_message alert")
				}
			}
		})
	}
}

func TestChromeDoesNotRetryFailedTrustOrCancellation(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("HTTP sent to an untrusted peer") }))
	ln := &badFirstTLS{Listener: srv.Listener}
	srv.Listener = ln
	srv.StartTLS()
	defer srv.Close()
	c, err := New(WithProfile("chrome_155_macos"), WithTimeout(3*time.Second), WithTransportOption(tc.WithForceHttp1()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Do(&Request{URL: srv.URL}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if ln.accepts.Load() != 1 {
		t.Fatalf("untrusted peer retried: %d", ln.accepts.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.Do(&Request{URL: srv.URL, Context: ctx}); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	if ln.accepts.Load() != 1 {
		t.Fatalf("cancelled request contacted peer: %d", ln.accepts.Load())
	}
}
