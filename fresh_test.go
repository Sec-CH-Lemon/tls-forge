package tlsforge

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	tls_client "github.com/igor-lemon/tls-client"
)

// wentOutOn is the one connection a request went out on.
func wentOutOn(t *testing.T, client *Client, url string) ConnInfo {
	t.Helper()
	var seen recorded
	if _, err := client.Do(&Request{URL: url, Trace: seen.trace()}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(seen.conns) != 1 {
		t.Fatalf("connections reported = %d", len(seen.conns))
	}
	return seen.conns[0]
}

func TestAFreshClientOpensConnectionsOfItsOwn(t *testing.T) {
	server := startEcho(t)
	via := startConnectProxy(t, false, exitAnswer)
	client := newTestClient(t, WithProxy(via.url()))
	page := server.URL() + "/api/all"

	first := wentOutOn(t, client, page)
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	// A tunnel of its own, which comes out of an address of its own.
	own := wentOutOn(t, fresh, page)
	if own.Reused || own.Tunnel == first.Tunnel || own.ProxyHeader.Get("x-exit-ip") != "203.0.113.2" {
		t.Errorf("a fresh client went out on %+v, after %+v", own, first)
	}
	// Which it keeps for what it sends next, as any client does.
	if again := wentOutOn(t, fresh, page); !again.Reused || again.Tunnel != own.Tunnel {
		t.Errorf("a fresh client's second request went out on %+v", again)
	}
	// Another is another again, and so is one made fresh from a fresh one.
	other, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	theirs := wentOutOn(t, other, page)
	nested, err := fresh.Fresh()
	if err != nil {
		t.Fatalf("Fresh of a fresh client: %v", err)
	}
	deeper := wentOutOn(t, nested, page)
	if tunnels := []uint64{first.Tunnel, own.Tunnel, theirs.Tunnel, deeper.Tunnel}; len(slices.Compact(slices.Sorted(slices.Values(tunnels)))) != 4 {
		t.Errorf("four clients went out on tunnels %v", tunnels)
	}

	// Closing them leaves the client as it was, on the tunnel it had, and each
	// closed one closed.
	for _, done := range []*Client{fresh, other, nested} {
		_ = done.Close()
	}
	if back := wentOutOn(t, client, page); !back.Reused || back.Tunnel != first.Tunnel {
		t.Errorf("the client went back out on %+v, not on %+v", back, first)
	}
	if _, err := fresh.Do(&Request{URL: page}); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a closed fresh client: %v", err)
	}
	if got := via.tunnels.Load(); got != 4 {
		t.Errorf("the proxy opened %d tunnels, want 4", got)
	}
}

func TestAFreshClientResumesNoSessionOfAnother(t *testing.T) {
	// A server that closes every connection, so that every request makes
	// another, which resumes the TLS session of the one before when it can.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
	}))
	t.Cleanup(server.Close)
	// A measured profile is a cold handshake, with no pre_shared_key, and the
	// transport keeps no sessions for one. A ClientHello that resumes is what
	// shows a fresh client resuming none of the client's.
	client := newTestClient(t, WithProfile("chrome_150_PSK"))
	if wentOutOn(t, client, server.URL).Resumed {
		t.Fatal("the first handshake resumed a session nobody had")
	}
	if !wentOutOn(t, client, server.URL).Resumed {
		t.Fatal("the client's own second connection did not resume its session, so a fresh one not doing so shows nothing")
	}
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if wentOutOn(t, fresh, server.URL).Resumed {
		t.Error("a fresh client resumed the TLS session of the client it came from")
	}
	// And then its own, as the client does.
	if !wentOutOn(t, fresh, server.URL).Resumed {
		t.Error("a fresh client did not resume a session of its own")
	}
}

func TestAFreshClientSharesTheSession(t *testing.T) {
	var mu sync.Mutex
	var heard []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies := strings.Split(r.Header.Get("Cookie"), "; ")
		slices.Sort(cookies)
		mu.Lock()
		heard = append(heard, strings.Join(cookies, "; "))
		mu.Unlock()
		switch r.URL.Path {
		case "/replace":
			http.SetCookie(w, &http.Cookie{Name: "warm", Value: "2", Path: "/"})
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "new", Value: "1", Path: "/"})
		}
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, WithCookies([]Cookie{{Name: "warm", Value: "1"}}))
	first, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = first.Close() }()
	second, err := first.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	defer func() { _ = second.Close() }()

	// The warmed cookie goes with whichever asks first, and what the server
	// replaced it with goes with the rest: it is filed once, and not put back.
	for _, ask := range []struct {
		client *Client
		path   string
	}{{first, "/replace"}, {second, "/set"}, {client, "/"}} {
		if _, err := ask.client.Do(&Request{URL: server.URL + ask.path}); err != nil {
			t.Fatalf("Do %s: %v", ask.path, err)
		}
	}
	if want := []string{"warm=1", "warm=2", "new=1; warm=2"}; !slices.Equal(heard, want) {
		t.Errorf("the server heard %q, want %q", heard, want)
	}
	// And the client holds what the fresh ones were given.
	held, err := client.Cookies(server.URL)
	if err != nil {
		t.Fatalf("Cookies: %v", err)
	}
	var names []string
	for _, cookie := range held {
		names = append(names, cookie.Name+"="+cookie.Value)
	}
	if slices.Sort(names); !slices.Equal(names, []string{"new=1", "warm=2"}) {
		t.Errorf("the client holds %q", names)
	}
}

func TestAFreshClientThatCannotBeMade(t *testing.T) {
	closed, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = closed.Close()
	if _, err := closed.Fresh(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a fresh client of a closed one: %v", err)
	}

	open := newTestClient(t)
	original := newInnerClient
	t.Cleanup(func() { newInnerClient = original })
	newInnerClient = func(tls_client.Logger, ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
		return nil, errors.New("no transport")
	}
	if _, err := open.Fresh(); err == nil || err.Error() != "tlsforge: no transport" {
		t.Errorf("a fresh client the transport would not build: %v", err)
	}
	// Nor one whose transport of requests that carry no credentials would
	// not build.
	built := 0
	newInnerClient = func(logger tls_client.Logger, options ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
		if built++; built == 2 {
			return nil, errors.New("no transport for requests without credentials")
		}
		return original(logger, options...)
	}
	if _, err := New(); err == nil || err.Error() != "tlsforge: no transport for requests without credentials" {
		t.Errorf("a client the second transport would not build: %v", err)
	}
}

func TestFreshClientsAtOnce(t *testing.T) {
	server := startEcho(t)
	via := startConnectProxy(t, false, exitAnswer)
	client := newTestClient(t, WithProxy(via.url()))
	tunnels := make([]uint64, 8)
	var wg sync.WaitGroup
	for i := range tunnels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := client.Fresh()
			if err != nil {
				t.Errorf("Fresh: %v", err)
				return
			}
			defer func() { _ = fresh.Close() }()
			var seen recorded
			if _, err := fresh.Do(&Request{URL: server.URL() + "/api/all", Trace: seen.trace()}); err != nil || len(seen.conns) != 1 {
				t.Errorf("Do: %v, %d connections", err, len(seen.conns))
				return
			}
			tunnels[i] = seen.conns[0].Tunnel
		}()
	}
	wg.Wait()
	if distinct := slices.Compact(slices.Sorted(slices.Values(tunnels))); len(distinct) != 8 || via.tunnels.Load() != 8 {
		t.Errorf("eight fresh clients at once went out on tunnels %v, of %d", tunnels, via.tunnels.Load())
	}
}
