package tlsforge

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// inTurn answers the nth request for each path, counted from 1, as answer
// says, once it has read the whole request.
func inTurn(answer func(w http.ResponseWriter, r *http.Request, n int)) http.HandlerFunc {
	var mu sync.Mutex
	asked := map[string]int{}
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		asked[r.URL.Path]++
		n := asked[r.URL.Path]
		mu.Unlock()
		answer(w, r, n)
	}
}

// misdirect answers 421 (Misdirected Request), with a body that says so, or
// with none.
func misdirect(w http.ResponseWriter, bodyless bool) {
	w.WriteHeader(http.StatusMisdirectedRequest)
	if !bodyless {
		_, _ = io.WriteString(w, "misdirected")
	}
}

func TestARequestAnswered421IsSentAgainOnce(t *testing.T) {
	// Every time: sent twice, its body and header fields as they were, and
	// the second 421 is the answer.
	for _, proto := range []string{"h2", "h1"} {
		for name, browser := range map[string]*BrowserContext{
			"without a context": nil,
			"fetch()":           {Kind: KindFetch, Initiator: "https://www.example.com/page"},
		} {
			t.Run(proto+" "+name, func(t *testing.T) {
				server := newRecorder(t, proto, inTurn(func(w http.ResponseWriter, _ *http.Request, _ int) {
					misdirect(w, false)
				}))
				book, log := newLogBook(slog.LevelInfo)
				client := contextClient(t, server, WithLogger(log))
				res, err := client.Do(&Request{Method: http.MethodPost, URL: "https://www.example.com/x?q=1",
					Header: Header{{Name: "Content-Type", Value: "text/plain"}}, Body: []byte("a=1"), Browser: browser})
				if err != nil || res.Status != http.StatusMisdirectedRequest || res.Text() != "misdirected" {
					t.Fatalf("Do: %+v, %v", res, err)
				}
				got := server.requests()
				if len(got) != 2 || got[1].method != http.MethodPost || got[1].body != "a=1" ||
					!slices.Equal(got[1].headers, got[0].headers) {
					t.Fatalf("sent %d requests: %+v", len(got), got)
				}
				if restarted := book.one(t, "restarted for a 421", "url", "https://www.example.com/x?q=1"); restarted.get("took") == "" {
					t.Errorf("%v", restarted)
				}
			})
		}
	}
}

func TestA421LeavesItsHTTP1ConnectionClosedAndItsHTTP2ConnectionOpen(t *testing.T) {
	// Sent again over HTTP/1.1 on another connection, the one the 421 came on
	// closed whether the 421 had a body or none; over HTTP/2 on the same.
	for _, tc := range []struct {
		proto    string
		bodyless bool
	}{{"h1", false}, {"h1", true}, {"h2", false}, {"h2", true}} {
		name := tc.proto + " with a body"
		if tc.bodyless {
			name = tc.proto + " with none"
		}
		t.Run(name, func(t *testing.T) {
			server := newRecorder(t, tc.proto, inTurn(func(w http.ResponseWriter, r *http.Request, n int) {
				if r.URL.Path == "/x" && n == 1 {
					misdirect(w, tc.bodyless)
				}
			}))
			client := contextClient(t, server)
			for _, url := range []string{"https://www.example.com/before", "https://www.example.com/x"} {
				if res, err := client.Get(url); err != nil || res.Status != http.StatusOK {
					t.Fatalf("Get %s: %+v, %v", url, res, err)
				}
			}
			got := server.requests()
			if len(got) != 3 || got[1].conn != got[0].conn {
				t.Fatalf("sent %+v", got)
			}
			if apart := got[2].conn != got[1].conn; apart != (tc.proto == "h1") {
				t.Errorf("sent again on connection %d, the 421 came on %d", got[2].conn, got[1].conn)
			}
			if tc.proto == "h1" {
				server.waitClosed(t, got[1].conn)
			}
		})
	}
}

func TestAHopIsSentAgainForA421OnceAnswerToA401AndAll(t *testing.T) {
	for name, browser := range map[string]*BrowserContext{
		"without a context": nil,
		"a navigation":      {Kind: KindNavigation, Initiator: "https://www.example.com/page"},
	} {
		t.Run(name, func(t *testing.T) {
			// A 421, a 401 answered, and a 421 again: the hop was sent again
			// once, and the last 421 is the answer.
			challenge := func(w http.ResponseWriter) {
				w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
				w.WriteHeader(http.StatusUnauthorized)
			}
			server := newRecorder(t, "h2", inTurn(func(w http.ResponseWriter, _ *http.Request, n int) {
				if n == 2 {
					challenge(w)
					return
				}
				misdirect(w, false)
			}))
			client := contextClient(t, server)
			res, err := client.Do(&Request{URL: "https://u:p@www.example.com/x", Browser: browser})
			got := server.requests()
			if err != nil || res.Status != http.StatusMisdirectedRequest || len(got) != 3 {
				t.Fatalf("Do: %+v, %v; sent %d requests", res, err, len(got))
			}
			if auth, _ := got[2].header("authorization"); auth != "Basic dTpw" {
				t.Errorf("the answer to the 401 said %q", auth)
			}
			// A 401 answered, then a 421: the answer is sent again as it
			// went, Authorization and all.
			server = newRecorder(t, "h2", inTurn(func(w http.ResponseWriter, _ *http.Request, n int) {
				switch n {
				case 1:
					challenge(w)
				case 2:
					misdirect(w, false)
				}
			}))
			client = contextClient(t, server)
			res, err = client.Do(&Request{URL: "https://u:p@www.example.com/x", Browser: browser})
			got = server.requests()
			if err != nil || res.Status != http.StatusOK || len(got) != 3 || !slices.Equal(got[2].headers, got[1].headers) {
				t.Fatalf("Do: %+v, %v; sent %+v", res, err, got)
			}
			if auth, _ := got[2].header("authorization"); auth != "Basic dTpw" {
				t.Errorf("sent again with %q", auth)
			}
		})
	}
}

func TestEachHopOfARedirectIsSentAgainForA421OfItsOwn(t *testing.T) {
	for name, browser := range map[string]*BrowserContext{
		"without a context": nil,
		"fetch()":           {Kind: KindFetch, Initiator: "https://www.example.com/page"},
	} {
		t.Run(name, func(t *testing.T) {
			server := newRecorder(t, "h2", inTurn(func(w http.ResponseWriter, r *http.Request, n int) {
				switch {
				case n == 1:
					misdirect(w, false)
				case r.URL.Path == "/a":
					w.Header().Set("Location", "/b")
					w.WriteHeader(http.StatusFound)
				}
			}))
			client := contextClient(t, server)
			res, err := client.Do(&Request{URL: "https://www.example.com/a", Browser: browser})
			var asked []string
			for _, r := range server.requests() {
				asked = append(asked, r.url)
			}
			want := []string{"https://www.example.com/a", "https://www.example.com/a", "https://www.example.com/b",
				"https://www.example.com/b"}
			if err != nil || res.Status != http.StatusOK || !slices.Equal(asked, want) {
				t.Errorf("Do: %+v, %v; asked for %q", res, err, asked)
			}
		})
	}
}

func TestAHopAfterOneSentAgainForA421GoesOutOnASharedConnection(t *testing.T) {
	// The hop to api.example.com goes out on www.example.com's connection, as
	// the hop sent again could not.
	server := newRecorder(t, "h2", inTurn(func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Path != "/x" {
			return
		}
		if n == 1 {
			misdirect(w, false)
			return
		}
		w.Header().Set("Location", "https://api.example.com/y")
		w.WriteHeader(http.StatusFound)
	}))
	client, err := New(WithProfile("chrome_155_macos"), server.trusting(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	for _, url := range []string{"https://www.example.com/page", "https://www.example.com/x"} {
		if res, err := client.Get(url); err != nil || res.Status != http.StatusOK {
			t.Fatalf("Get %s: %+v, %v", url, res, err)
		}
	}
	got := server.requests()
	if len(got) != 4 || got[3].url != "https://api.example.com/y" {
		t.Fatalf("sent %+v", got)
	}
	var conns []int64
	for _, r := range got {
		conns = append(conns, r.conn)
	}
	if !slices.Equal(conns, []int64{conns[0], conns[0], conns[0], conns[0]}) {
		t.Errorf("sent on connections %v", conns)
	}
}

func TestARequestSentAgainForA421CarriesTheCookiesItDid(t *testing.T) {
	// fetch() of another site with credentials included carries its cookie
	// of SameSite=None alone, and so does it sent again.
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := contextClient(t, server)
	if _, err := client.Get("https://www.example.net/p/set?cookie=2"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	res, err := client.Do(&Request{URL: "https://www.example.net/misdirected/x?first=1",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page", Credentials: "include"}})
	got := server.requests()[1:]
	if err != nil || res.Status != http.StatusOK || len(got) != 2 {
		t.Fatalf("Do: %+v, %v; sent %+v", res, err, got)
	}
	for _, r := range got {
		var cookies []string
		for _, h := range r.headers {
			if h[0] == "cookie" {
				cookies = append(cookies, h[1])
			}
		}
		if !slices.Equal(cookies, []string{"b=2"}) {
			t.Errorf("%s carried %q", r.url, cookies)
		}
	}
}

func TestAPreflightAnswered421IsAskedAgainOnce(t *testing.T) {
	for _, proto := range []string{"h2", "h1"} {
		t.Run(proto, func(t *testing.T) {
			server := newRecorder(t, proto, answeringAsMeasured)
			book, log := newLogBook(slog.LevelInfo)
			client := contextClient(t, server, WithLogger(log))
			if _, err := client.Get("https://www.example.net/p/set?cookie=1"); err != nil {
				t.Fatalf("Get: %v", err)
			}
			post := func(url string) error {
				_, err := client.Do(&Request{Method: http.MethodPost, URL: url, Body: []byte("{}"),
					Header: Header{{Name: "Content-Type", Value: "application/json"}},
					Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page",
						Credentials: "include"}})
				return err
			}
			// Asked again with no cookies, as the first time, over HTTP/1.1 on
			// another connection, and then the request.
			url := "https://www.example.net/misdirected/x?first=1&maxage=0"
			if err := post(url); err != nil {
				t.Fatalf("Do: %v", err)
			}
			got := server.requests()[1:]
			var methods []string
			for _, r := range got {
				methods = append(methods, r.method)
				if cookie, carried := r.header("cookie"); r.method == http.MethodOptions && carried {
					t.Errorf("a preflight carried Cookie %q", cookie)
				}
			}
			if !slices.Equal(methods, []string{http.MethodOptions, http.MethodOptions, http.MethodPost}) {
				t.Fatalf("sent %q", methods)
			}
			if apart := got[1].conn != got[0].conn; apart != (proto == "h1") {
				t.Errorf("asked again on connection %d, the 421 came on %d", got[1].conn, got[0].conn)
			}
			book.one(t, "restarted for a 421", "url", url)
			// Answered 421 again, the preflight did not allow the request,
			// which is not sent.
			err := post("https://www.example.net/misdirected/y?always=1&maxage=0")
			got = server.requests()[4:]
			if !errors.Is(err, ErrCORS) || !strings.Contains(err.Error(), "refused") || len(got) != 2 ||
				got[1].method != http.MethodOptions {
				t.Errorf("Do: %v; sent %+v", err, got)
			}
		})
	}
}

func TestA421SentAgainIsLeftUnreadAndItsStreamCancelled(t *testing.T) {
	// The 421's body is still coming when the request goes out again: its
	// HTTP/2 stream is cancelled, as Chrome cancels it, and not left open.
	cancelled := make(chan bool, 1)
	server := newRecorder(t, "h2", inTurn(func(w http.ResponseWriter, r *http.Request, n int) {
		if n > 1 {
			return
		}
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = io.WriteString(w, "misdirected, and more to come")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			cancelled <- true
		case <-time.After(5 * time.Second):
			cancelled <- false
		}
	}))
	client := contextClient(t, server)
	if res, err := client.Get("https://www.example.com/x"); err != nil || res.Status != http.StatusOK {
		t.Fatalf("Get: %+v, %v", res, err)
	}
	if !<-cancelled {
		t.Error("the stream of the 421 was left open")
	}
}

func TestAPreflightAnswered421WithNoBodyIsAskedAgainOnAnotherHTTP1Connection(t *testing.T) {
	server := newRecorder(t, "h1", inTurn(func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		switch {
		case r.Method != http.MethodOptions:
		case n == 1:
			w.WriteHeader(http.StatusMisdirectedRequest)
		default:
			w.Header().Set("Access-Control-Allow-Headers", "content-type")
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	client := contextClient(t, server)
	// A first request, so that the preflight goes out on a connection in use.
	if _, err := client.Get("https://www.example.net/before"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, err := client.Do(&Request{Method: http.MethodPost, URL: "https://www.example.net/x", Body: []byte("{}"),
		Header:  Header{{Name: "Content-Type", Value: "application/json"}},
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page", Credentials: "include"}})
	got := server.requests()
	if err != nil || len(got) != 4 || got[1].method != http.MethodOptions || got[2].method != http.MethodOptions {
		t.Fatalf("Do: %v; sent %+v", err, got)
	}
	if got[2].conn == got[1].conn {
		t.Errorf("asked again on connection %d, the one the 421 came on", got[2].conn)
	}
	server.waitClosed(t, got[1].conn)
}

func TestTheCookiesOfA421SentAgainAreNotKeptAndThoseOfOneHandedBackAre(t *testing.T) {
	// Answered 421 twice, each setting a cookie: the jar keeps the second's
	// alone, as Chrome hands it over and not the first.
	server := newRecorder(t, "h2", inTurn(func(w http.ResponseWriter, _ *http.Request, n int) {
		w.Header().Add("Set-Cookie", fmt.Sprintf("m%d=1; Max-Age=3600; Path=/", n))
		misdirect(w, false)
	}))
	client := contextClient(t, server)
	res, err := client.Get("https://www.example.com/x")
	if err != nil || res.Status != http.StatusMisdirectedRequest || !slices.Equal(res.Cookies, []string{"m2=1"}) {
		t.Fatalf("Get: %+v, %v", res, err)
	}
	if cookie, carried := server.requests()[1].header("cookie"); carried {
		t.Errorf("sent again with Cookie %q", cookie)
	}
}
