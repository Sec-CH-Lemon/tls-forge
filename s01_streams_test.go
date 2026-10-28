package tlsforge

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// RFC 9113 lets one connection carry several streams. A request its caller
// gives up on, by cancelling it or by its deadline, ends its own stream alone:
// the other streams of the connection go on, and the connection takes the
// next request. S01 ends a connection a server floods; an ordinary request
// given up must not end it.
func TestARequestGivenUpLeavesTheOtherStreamsOfItsConnection(t *testing.T) {
	for _, how := range []string{"cancelled", "deadline"} {
		t.Run(how, func(t *testing.T) {
			var connections atomic.Int32
			arrived := make(chan string, 8)
			ended := make(chan string, 8)
			release := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				arrived <- r.URL.Path + " " + r.RemoteAddr
				if r.URL.Path != "/after" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						ended <- r.URL.Path
						return
					}
				}
				_, _ = w.Write(bytes.Repeat([]byte("x"), 100_000))
			}))
			server.EnableHTTP2 = true
			server.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			defer close(release)
			client := newTestClient(t, WithProfile("chrome_155_macos"), WithTimeout(10*time.Second))

			ctx, cancel := context.WithCancel(context.Background())
			if how == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
			}
			defer cancel()
			givenUp := doing(client, &Request{Method: "GET", URL: server.URL + "/given-up", Context: ctx})
			first := <-arrived

			type answer struct {
				res *Response
				err error
			}
			goingOn := make(chan answer, 1)
			go func() {
				res, err := client.Do(&Request{Method: "GET", URL: server.URL + "/going-on"})
				goingOn <- answer{res, err}
			}()
			second := <-arrived
			if how == "cancelled" {
				cancel()
			}
			if err := <-givenUp; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the request given up ended with %v", err)
			}
			if path := <-ended; path != "/given-up" {
				t.Fatalf("the server saw %s end", path)
			}
			release <- struct{}{}
			got := <-goingOn
			if got.err != nil || got.res.Status != http.StatusOK || len(got.res.Body) != 100_000 {
				t.Fatalf("the other stream: %+v", got)
			}
			after, err := client.Do(&Request{Method: "GET", URL: server.URL + "/after"})
			if err != nil || after.Status != http.StatusOK || len(after.Body) != 100_000 {
				t.Fatalf("the next request: %v %v", after, err)
			}
			third := <-arrived
			on := func(seen string) string { return seen[strings.Index(seen, " ")+1:] }
			if connections.Load() != 1 || on(first) != on(second) || on(second) != on(third) {
				t.Fatalf("%d connections: %s, %s, %s", connections.Load(), first, second, third)
			}
		})
	}
}
