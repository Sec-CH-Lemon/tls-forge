package tlsforge

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Sec-CH-Lemon/tls-forge/internal/harness"
)

// page is the page the requests a browser sent here came from.
const sentPage = "https://www.example.com/page"

func TestARequestABrowserSentIsRefusedForWhatItsKindCannotBe(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	for _, tc := range []struct {
		name    string
		browser BrowserContext
		method  string
		body    []byte
		says    string
	}{
		{"a navigation by POST", BrowserContext{Kind: KindNavigation}, "POST", nil, "a navigation is a GET, not a POST"},
		{"a navigation with a body", BrowserContext{Kind: KindNavigation}, "GET", []byte{}, "a navigation sends no body"},
		{"a form from no page", BrowserContext{Kind: KindForm}, "POST", nil, "a form is submitted from a page"},
		{"a form by PUT", BrowserContext{Kind: KindForm, Initiator: sentPage}, "PUT", nil, "a form is sent by GET or POST"},
		{"a form by GET with a body", BrowserContext{Kind: KindForm, Initiator: sentPage}, "GET", []byte("a"),
			"a form sent by GET has its fields in the URL"},
		{"fetch() from no page", BrowserContext{Kind: KindFetch}, "GET", nil, "fetch() is sent by a page's script"},
		{"an XHR with a mode", BrowserContext{Kind: KindXHR, Initiator: sentPage, Mode: "cors"}, "GET", nil,
			"an XHR has no mode"},
		{"fetch() by TRACE", BrowserContext{Kind: KindFetch, Initiator: sentPage}, "TRACE", nil, "fetch() cannot send TRACE"},
		{"a kind there is none of", BrowserContext{Kind: "beacon", Initiator: sentPage}, "GET", nil,
			`kind "beacon" is not navigation, form, fetch or xhr`},
	} {
		b := tc.browser
		b.Sent = true
		_, err := client.Do(&Request{Method: tc.method, URL: "https://www.example.com/x", Body: tc.body, Browser: &b})
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.says)
		}
	}
	if got := server.requests(); len(got) != 0 {
		t.Errorf("sent %d requests", len(got))
	}
}

func TestARequestABrowserSentSaysTheProfilesOwnAndTheBrowsersRest(t *testing.T) {
	// The user agent, its client hints, Accept-Language and Accept-Encoding
	// are the profile's, given where the browser gave none too; a hint the
	// profile has no value of is the browser's; everything else is the
	// browser's, in Chrome's order for its kind, the browser's own fields
	// Chrome has no slot of its own for where @given stands.
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	p := shippedProfile(t, "chrome_155_macos")
	sent := NewHeader("User-Agent", "Mozilla/5.0 Firefox/150.0", "Accept-Language", "de", "Accept-Encoding", "gzip",
		"Accept", "text/html", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document",
		"Referer", sentPage, "Sec-CH-UA-Arch", `"x86"`, "Sec-CH-UA-Bogus", "?1", "X-Foo", "1", "Cookie", "a=1")
	if _, err := client.Do(&Request{URL: "https://www.example.com/x", Header: sent,
		Browser: &BrowserContext{Kind: KindNavigation, Initiator: sentPage, Sent: true}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()[0]
	want := []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "user-agent", "sec-ch-ua-bogus",
		"x-foo", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
		"accept-language", "cookie", "priority"}
	if names := regular(got); !slices.Equal(names, want) {
		t.Errorf("fields %v\nwant   %v", names, want)
	}
	for name, value := range map[string]string{"user-agent": p.UserAgent, "accept-language": "en-US,en;q=0.9",
		"accept-encoding": "gzip, deflate, br, zstd", "sec-ch-ua-arch": Header(p.ClientHints).Get("sec-ch-ua-arch"),
		"sec-ch-ua-bogus": "?1", "accept": "text/html", "sec-fetch-site": "same-origin", "referer": sentPage,
		"priority": "u=0, i"} {
		if got, _ := got.header(name); got != value {
			t.Errorf("%s: %q, want %q", name, got, value)
		}
	}
	if _, ok := got.header("sec-fetch-user"); ok {
		t.Error("Sec-Fetch-User was worked out where the browser sent none")
	}
}

func TestARequestABrowsersPageSentGoesAsFetchInItsModeDoes(t *testing.T) {
	// A page's subresource: its script's own fields in the renderer's map,
	// what the network stack adds in its slots, as Chrome 155 sent them
	// (testdata/chrome155-subresources.json); a font's Origin the renderer's,
	// fetch()'s after Accept; the Priority of what it is for, and the weight of
	// its urgency.
	for _, tc := range []struct {
		dest, mode, priority string
		weight               uint32
		origin               bool
		want                 []string
	}{
		{"image", "no-cors", "i", 146, false, []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language",
			"priority"}},
		{"script", "no-cors", "", 146, false, []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"}},
		{"font", "cors", "u=0", 255, true, []string{"origin", "sec-ch-ua-platform", "user-agent", "sec-ch-ua",
			"sec-ch-ua-mobile", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
			"accept-language", "priority"}},
		{"empty", "cors", "u=1, i", 219, true, []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "x-foo",
			"sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "priority"}},
		{"video", "no-cors", "", 146, false, []string{"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"}},
	} {
		t.Run(tc.dest, func(t *testing.T) {
			server := newRecorder(t, "h2", nil)
			client := contextClient(t, server)
			sent := NewHeader("Accept", "*/*", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", tc.mode,
				"Sec-Fetch-Dest", tc.dest, "Referer", sentPage)
			if tc.origin {
				sent.Add("Origin", "https://www.example.com")
			}
			if tc.dest == "empty" {
				sent.Add("X-Foo", "1")
			}
			if _, err := client.Do(&Request{URL: "https://www.example.com/x", Header: sent,
				Browser: &BrowserContext{Kind: KindFetch, Mode: tc.mode, Initiator: sentPage, Sent: true}}); err != nil {
				t.Fatalf("Do: %v", err)
			}
			got := server.requests()[0]
			if names := regular(got); !slices.Equal(names, tc.want) {
				t.Errorf("fields %v\nwant   %v", names, tc.want)
			}
			if priority, _ := got.header("priority"); priority != tc.priority {
				t.Errorf("priority %q, want %q", priority, tc.priority)
			}
			if got.priority == nil || got.priority[0] != 1 || got.priority[2] != tc.weight {
				t.Errorf("HEADERS priority %v, want exclusive, weight %d", got.priority, tc.weight)
			}
		})
	}
}

func TestARequestABrowserSentIsLeftToTheBrowserToDoWhatABrowserDoes(t *testing.T) {
	// No preflight and no check of CORS, no redirect followed, no 401
	// answered, no start again for a critical hint, nothing kept for later:
	// the browser does each itself, with what it is answered.
	var asked []string
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/r":
			http.Redirect(w, r, "/landed", http.StatusFound)
		case "/auth":
			w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/critical":
			w.Header().Set("Accept-CH", "sec-ch-ua-arch")
			w.Header().Set("Critical-CH", "sec-ch-ua-arch")
		case "/cached":
			w.Header().Set("Cache-Control", "max-age=600")
		}
	})
	client := contextClient(t, server)
	nav := &BrowserContext{Kind: KindNavigation, Sent: true}
	cors := &BrowserContext{Kind: KindFetch, Initiator: "https://shop.example/page", Sent: true}
	for _, tc := range []struct {
		method, url string
		header      Header
		browser     *BrowserContext
		status      int
	}{
		{"PUT", "https://www.example.com/cors", NewHeader("Content-Type", "application/json", "Sec-Fetch-Mode", "cors"),
			cors, http.StatusOK},
		{"GET", "https://www.example.com/r", nil, nav, http.StatusFound},
		{"GET", "https://u:p@www.example.com/auth", nil, nav, http.StatusUnauthorized},
		{"GET", "https://www.example.com/critical", nil, nav, http.StatusOK},
		{"GET", "https://www.example.com/cached", nil, nav, http.StatusOK},
		{"GET", "https://www.example.com/cached", nil, nav, http.StatusOK},
	} {
		res, err := client.Do(&Request{Method: tc.method, URL: tc.url, Header: tc.header, Browser: tc.browser})
		if err != nil || res.Status != tc.status {
			t.Fatalf("%s %s: %v, %+v", tc.method, tc.url, err, res)
		}
	}
	want := []string{"PUT /cors", "GET /r", "GET /auth", "GET /critical", "GET /cached", "GET /cached"}
	if !slices.Equal(asked, want) {
		t.Errorf("asked %v, want %v", asked, want)
	}
}

func TestARequestABrowserSentOverHTTP1KeepsItsPriorityToHTTP2(t *testing.T) {
	// The Priority it was sent with goes, and its urgency weighs its HEADERS
	// frame; over HTTP/1.1 Chrome writes none of its own, and none goes.
	for _, tc := range []struct {
		proto, sent, want string
		weight            uint32
	}{
		{"h2", "u=2", "u=2", 182},
		{"h2", "", "u=0, i", 255},
		{"h1", "", "", 0},
		{"h1", "u=2", "u=2", 0},
	} {
		server := newRecorder(t, tc.proto, nil)
		client := contextClient(t, server)
		sent := NewHeader("Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document")
		if tc.sent != "" {
			sent.Add("Priority", tc.sent)
		}
		if _, err := client.Do(&Request{URL: "https://www.example.com/x", Header: sent,
			Browser: &BrowserContext{Kind: KindNavigation, Sent: true}}); err != nil {
			t.Fatalf("Do: %v", err)
		}
		got := server.requests()[0]
		if priority, _ := got.header("priority"); priority != tc.want {
			t.Errorf("%s sent %q: priority %q, want %q", tc.proto, tc.sent, priority, tc.want)
		}
		if tc.proto == "h2" && (got.priority == nil || got.priority[2] != tc.weight) {
			t.Errorf("%s sent %q: HEADERS priority %v, want weight %d", tc.proto, tc.sent, got.priority, tc.weight)
		}
	}
}

func TestARequestABrowserSentWithAProfileOfNoWeightsKeepsTheProfilesFrame(t *testing.T) {
	// A profile that says no weight of an urgency (h2.urgency_weights) sends
	// its HEADERS frame with its own priority.
	server := newRecorder(t, "h2", nil)
	p := shippedProfile(t, "chrome_155_macos")
	delete(p.Behavior, "headers.sent_priority")
	delete(p.Behavior, "h2.urgency_weights")
	client := contextClient(t, server, WithProfileValue(p))
	if _, err := client.Do(&Request{URL: "https://www.example.com/x", Header: NewHeader("Sec-Fetch-Dest", "image"),
		Browser: &BrowserContext{Kind: KindFetch, Mode: "no-cors", Initiator: sentPage, Sent: true}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()[0]
	if _, ok := got.header("priority"); ok || got.priority == nil || got.priority[2] != 255 {
		t.Errorf("fields %v, HEADERS priority %v", regular(got), got.priority)
	}
}

func TestTheUrgencyAPrioritySays(t *testing.T) {
	for value, want := range map[string]int{"": 3, "i": 3, "u=0, i": 0, "u=1": 1, "i, u=7": 7, "u=8": 3, "u=-1": 3,
		"u=x": 3, " u=5 ": 5, "U=2": 3} {
		if got := urgencyOf(value); got != want {
			t.Errorf("%q: %d, want %d", value, got, want)
		}
	}
}

func TestAProfileSaysThePriorityOfWhatABrowserSent(t *testing.T) {
	p := shippedProfile(t, "chrome_155_macos")
	var priorities []string
	if err := json.Unmarshal(p.Behavior["headers.sent_priority"], &priorities); err != nil {
		t.Fatal(err)
	}
	r := &browserRequest{behavior: p.RuntimeBehavior()}
	for dest, want := range map[string]string{"document": "u=0, i", " Image ": "i", "script": "", "empty": "u=1, i",
		"manifest": ""} {
		if got := r.sentPriority(hop{given: NewHeader("sec-fetch-dest", dest)}); got != want {
			t.Errorf("%q: %q, want %q", dest, got, want)
		}
	}
}

func TestAFormABrowserPostedGoesAsChromePostsOne(t *testing.T) {
	// Its own Content-Type, whatever encoding it says, its Cache-Control and
	// Origin in the slots of a form's POST, and what it was given that Chrome
	// has no slot for after Origin (testdata/chrome155-given.json, form-given).
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	sent := NewHeader("Cache-Control", "max-age=0", "Content-Type", "multipart/form-data; boundary=x y",
		"Origin", "https://www.example.com", "Accept", "text/html", "Sec-Fetch-Site", "same-origin",
		"Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document", "Referer", sentPage, "X-Foo", "1")
	if _, err := client.Do(&Request{Method: "POST", URL: "https://www.example.com/x", Header: sent, Body: []byte("a=1"),
		Browser: &BrowserContext{Kind: KindForm, Initiator: sentPage, Sent: true}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()[0]
	want := []string{"content-length", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"content-type", "user-agent", "origin", "x-foo", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
		"referer", "accept-encoding", "accept-language", "priority"}
	if names := regular(got); !slices.Equal(names, want) {
		t.Errorf("fields %v\nwant   %v", names, want)
	}
	if typed, _ := got.header("content-type"); typed != "multipart/form-data; boundary=x y" || got.body != "a=1" {
		t.Errorf("Content-Type %q, body %q", typed, got.body)
	}
}

func TestAScriptsRequestABrowserSentSaysTheProfilesOwnToo(t *testing.T) {
	// Its user agent and client hints the profile's, in the renderer's map
	// once; its Range the renderer's, Accept-Encoding identity; two fields of
	// one name, which Chrome's renderer joins, one; no hint an origin asked
	// tls-forge for, which the browser sends itself or not.
	server := newRecorder(t, "h2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Accept-CH", "sec-ch-ua-model")
	})
	client := contextClient(t, server)
	if _, err := client.Get("https://www.example.com/asks"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	sent := NewHeader("User-Agent", "Mozilla/5.0 Firefox/150.0", "Sec-CH-UA-Arch", `"x86"`, "Range", "bytes=0-",
		"X-Foo", "1", "X-Foo", "2", "Accept", "*/*", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "no-cors",
		"Sec-Fetch-Dest", "video", "Referer", sentPage)
	if _, err := client.Do(&Request{URL: "https://www.example.com/x", Header: sent,
		Browser: &BrowserContext{Kind: KindFetch, Mode: "no-cors", Initiator: sentPage, Sent: true}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := server.requests()[1]
	p := shippedProfile(t, "chrome_155_macos")
	for name, value := range map[string]string{"user-agent": p.UserAgent, "sec-ch-ua-arch": Header(p.ClientHints).Get("sec-ch-ua-arch"),
		"range": "bytes=0-", "accept-encoding": "identity", "x-foo": "1, 2"} {
		if got, _ := got.header(name); got != value {
			t.Errorf("%s: %q, want %q", name, got, value)
		}
	}
	names := regular(got)
	if strings.Count(strings.Join(names, " "), "user-agent") != 1 || slices.Contains(names, "sec-ch-ua-model") ||
		strings.Count(strings.Join(names, " "), "x-foo") != 1 {
		t.Errorf("fields %v", names)
	}
}

func TestARequestABrowserSentTakesNoHintsTheALPSOfItsConnectionAsks(t *testing.T) {
	// The hints a browser sent are all it sends: the ALPS of the connection
	// its request goes on, which asks for three, adds none, and the request
	// is not started again for them.
	server, err := harness.StartALPSServer()
	if err != nil {
		t.Fatalf("StartALPSServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, origin := alpsBench(t, server, "accept-ch")
	if _, err := client.Do(&Request{URL: origin + "/p/after", Header: NewHeader("Accept", "text/html",
		"Sec-Fetch-Site", "none", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document"),
		Browser: &BrowserContext{Kind: KindNavigation, Sent: true}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	client.CloseIdleConnections()
	var sent []harness.WrittenRequest
	for _, c := range sentToALPS(t, server, "accept-ch") {
		sent = append(sent, c...)
	}
	if len(sent) != 1 || slices.Contains(fieldNames(sent[0]), "sec-ch-ua-arch") {
		t.Errorf("sent %+v", sent)
	}
}
