package tlsforge

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

func TestTheHintsAnAcceptCHNames(t *testing.T) {
	for _, tc := range []struct {
		fields []string
		want   string
	}{
		{[]string{"sec-ch-ua-arch"}, "sec-ch-ua-arch"},
		// Chrome's order, whatever the header's, and any case of ASCII.
		{[]string{"Sec-CH-UA-Bitness, Sec-CH-UA-Arch, Sec-CH-UA-Model"}, "sec-ch-ua-arch sec-ch-ua-model sec-ch-ua-bitness"},
		{[]string{"rtt", "dpr"}, "dpr rtt"},
		{[]string{"\tdpr\t,  rtt "}, "dpr rtt"},
		{[]string{"dpr, dpr, DPR"}, "dpr"},
		{[]string{"sec-ch-ua-arch;v=1, ect;x"}, "ect sec-ch-ua-arch"},
		{[]string{"sec-ch-ua, sec-ch-ua-mobile"}, "sec-ch-ua sec-ch-ua-mobile"},
		// What Chrome does not send when asked.
		{[]string{"nonsense, save-data, sec-ch-width, width"}, ""},
		{[]string{""}, ""},
		{[]string{",,"}, ""},
		// A long s is no s, nor a dotless i an i, to ASCII.
		{[]string{"\u017fec-ch-ua-arch, sec-ch-ua-b\u0131tness"}, ""},
		// Nor a Kelvin sign a k, though Unicode lowers it to one.
		{[]string{"downlin\u212a"}, ""},
		{[]string{`"sec-ch-ua-arch"`}, ""},
	} {
		if got := strings.Join(askedHints(tc.fields), " "); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.fields, got, tc.want)
		}
	}
}

func TestAnOriginsHintsAreKeptForTheSession(t *testing.T) {
	store := newHintStore()
	a := originOf(mustURL(t, "https://www.example.com/"))
	b := originOf(mustURL(t, "https://api.example.com/"))
	said := func(o origin, field ...string) ([]string, bool) {
		header := fhttp.Header{}
		for _, f := range field {
			header.Add("Accept-CH", f)
		}
		return store.remember(o, header)
	}
	if asked, ok := said(a, "sec-ch-ua-arch"); !ok || strings.Join(asked, " ") != "sec-ch-ua-arch" {
		t.Errorf("asked %v, %v", asked, ok)
	}
	if _, ok := store.remember(a, fhttp.Header{}); ok || strings.Join(store.of(a), " ") != "sec-ch-ua-arch" {
		t.Errorf("an answer that says nothing changed what was asked: %v", store.of(a))
	}
	if store.of(b) != nil {
		t.Errorf("another origin of the site: %v", store.of(b))
	}
	if asked, ok := said(a, "sec-ch-ua-bitness"); !ok || strings.Join(store.of(a), " ") != "sec-ch-ua-bitness" ||
		strings.Join(asked, " ") != "sec-ch-ua-bitness" {
		t.Errorf("not replaced: %v", store.of(a))
	}
	if asked, ok := said(a, ""); !ok || asked != nil || store.of(a) != nil {
		t.Errorf("an empty Accept-CH left %v, %v", store.of(a), asked)
	}
	said(a, "dpr")
	if asked, ok := said(a, "nonsense"); !ok || asked != nil || store.of(a) != nil {
		t.Errorf("asking for nothing Chrome knows left %v", store.of(a))
	}
	// Over a connection a page may not trust, nothing is asked for; to the
	// machine itself it is.
	for raw, kept := range map[string]bool{"http://www.example.com/": false, "http://localhost:8080/": true} {
		o := originOf(mustURL(t, raw))
		if _, ok := said(o, "dpr"); ok != kept || (store.of(o) != nil) != kept {
			t.Errorf("%s: %v, %v", raw, ok, store.of(o))
		}
	}
}

func TestAPagesHintsGoToItsOriginAlone(t *testing.T) {
	server := newRecorder(t, "h2", nil)
	client := contextClient(t, server)
	page := mustURL(t, "https://www.example.com/page")
	client.hints.asked[originOf(page)] = []string{"sec-ch-ua-arch", "sec-ch-ua-bitness"}
	for _, tc := range []struct {
		kind   RequestKind
		target string
		want   string
	}{
		{KindNavigation, "https://www.example.com/x", "sec-ch-ua-arch sec-ch-ua-bitness"},
		{KindNavigation, "https://api.example.com/x", ""},
		{KindFetch, "https://www.example.com/x", "sec-ch-ua-arch sec-ch-ua-bitness"},
		{KindFetch, "https://api.example.com/x", ""},
	} {
		r := &browserRequest{kind: tc.kind, initiator: page, from: originOf(page)}
		if got := strings.Join(client.hintsOf(r, r.first(mustURL(t, tc.target))).Names(), " "); got != tc.want {
			t.Errorf("%s to %s: %q, want %q", tc.kind, tc.target, got, tc.want)
		}
	}
	// A page of another site asking the origin that asked for hints: none.
	other := mustURL(t, "https://www.example.net/page")
	r := &browserRequest{kind: KindFetch, initiator: other, from: originOf(other)}
	if got := client.hintsOf(r, r.first(mustURL(t, "https://www.example.com/x"))); got != nil {
		t.Errorf("%v", got)
	}
	// A client made Fresh shares what was asked, as the session's.
	fresh, err := client.Fresh()
	if err != nil {
		t.Fatalf("Fresh: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	if fresh.hints != client.hints {
		t.Error("a fresh client keeps hints of its own")
	}
}

func TestAProfileWithoutAValueSendsNoHint(t *testing.T) {
	values := Header{{Name: "sec-ch-ua-arch", Value: `"arm"`}, {Name: "dpr", Value: "1"}}
	if got := hintValues([]string{"dpr", "sec-ch-ua-bitness", "sec-ch-ua-arch"}, values); got.Names()[0] != "dpr" ||
		len(got) != 2 || got.Get("sec-ch-ua-arch") != `"arm"` {
		t.Errorf("%v", got)
	}
	if got := hintValues(nil, values); got != nil {
		t.Errorf("%v", got)
	}
}

func TestNoScriptsRequestAsksForHints(t *testing.T) {
	// Neither the answer to a fetch() nor a redirect it followed: Chrome keeps
	// what a navigation was answered with alone.
	server := newRecorder(t, "h2", answeringAsMeasured)
	client := contextClient(t, server)
	page := &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}
	for _, url := range []string{"https://www.example.com/p/x?accept=sec-ch-ua-arch",
		"https://www.example.com/r/302/x?accept=sec-ch-ua-arch&to=/p/y"} {
		if _, err := client.Do(&Request{URL: url, Browser: page}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if asked := client.hints.of(originOf(mustURL(t, "https://www.example.com/"))); asked != nil {
		t.Errorf("asked for %v", asked)
	}
}

func TestALogSaysWhatAnOriginAskedFor(t *testing.T) {
	server := newRecorder(t, "h2", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Has("accept") {
			w.Header().Set("Accept-CH", q.Get("accept"))
		}
	})
	book, log := newLogBook(slog.LevelDebug)
	client := contextClient(t, server, WithLogger(log))
	for _, accept := range []string{"sec-ch-ua-arch, dpr", ""} {
		if _, err := client.Do(&Request{URL: "https://www.example.com/x?accept=" + accept,
			Browser: &BrowserContext{Kind: KindNavigation}}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	asked := book.with(t, "client hints asked")
	if len(asked) != 2 || asked[0].get("origin") != "https://www.example.com" || asked[0].get("hints") != "dpr,sec-ch-ua-arch" ||
		asked[1].get("hints") != "" {
		t.Errorf("%v", asked)
	}
	// A request without a browser context, or of a script, asks nothing.
	if _, err := client.Get("https://www.example.com/x?accept=rtt"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := client.Do(&Request{URL: "https://www.example.com/x?accept=rtt",
		Browser: &BrowserContext{Kind: KindFetch, Initiator: "https://www.example.com/page"}}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := book.with(t, "client hints asked"); len(got) != 2 {
		t.Errorf("%v", got)
	}
}
