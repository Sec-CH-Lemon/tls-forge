package tlsforge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/v2/profile"
	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/cookiejar"
	"golang.org/x/net/dns/dnsmessage"
)

// cookieIdentityFixture is what Chrome sent of the cookies a page at each
// host set: testdata/chrome156-cookie-identity.json. A step sets a cookie
// from the page's host (set), or is what went to the page's host (show) or
// to sub.example.test (subshow), the Cookie field as it came.
type cookieIdentityFixture struct {
	Browser string `json:"browser"`
	Pages   map[string]struct {
		Steps []map[string]string `json:"steps"`
	} `json:"pages"`
}

// cookiesShown sends each step of a page of the fixture through one client of
// p, over plain http to its names, and gives what each show and subshow was
// answered with: the Cookie field as it came.
func cookiesShown(t *testing.T, p *profile.Profile, host string, steps []map[string]string) []string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			w.Header().Add("Set-Cookie", r.URL.Query().Get("c"))
		case "/show":
			_, _ = fmt.Fprint(w, strings.Join(r.Header.Values("Cookie"), " | "))
		}
	}))
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	dns := startDNS(t, func(q dnsmessage.Question) ([]dnsRecord, time.Duration, dnsmessage.RCode) {
		name := strings.TrimSuffix(q.Name.String(), ".")
		if q.Type == dnsmessage.TypeA && strings.HasSuffix("."+name, ".example.test") {
			return []dnsRecord{{name: name, ttl: 30, a: netip.MustParseAddr("127.0.0.1")}}, 0, 0
		}
		return nil, 0, 0
	})
	c := newTestClient(t, WithProfileValue(p), WithDNSServer(dns.addr))
	var shown []string
	for i, step := range steps {
		target := "http://" + host + ":" + port + "/show"
		if set, ok := step["set"]; ok {
			target = "http://" + host + ":" + port + "/set?c=" + url.QueryEscape(set)
		} else if _, ok := step["subshow"]; ok {
			target = "http://sub.example.test:" + port + "/show"
		}
		res, err := c.Do(&Request{URL: target})
		if err != nil {
			t.Fatalf("%s, step %d %v: %v", host, i, step, err)
		}
		if _, ok := step["set"]; !ok {
			shown = append(shown, string(res.Body))
		}
	}
	return shown
}

// A cookie its host's alone and one of a Domain naming that host are two
// cookies, as Chrome keeps them: both go, each replaced and removed by its own
// kind alone, a Domain naming the host itself is its domain's, and the order
// is Chrome's. Where the profile says nothing of cookie.identity they are one,
// as RFC 6265 has it, and the answers are not Chrome's.
func TestAHostsOwnCookieAndItsDomainsAreKeptApartAsChromeKeepsThem(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome156-cookie-identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cookieIdentityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	hosts := make([]string, 0, len(fixture.Pages))
	for host := range fixture.Pages {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	if strings.Join(hosts, " ") != "example.test www.example.test" {
		t.Fatalf("pages %v", hosts)
	}
	for _, apart := range []bool{true, false} {
		for _, host := range hosts {
			p := shippedProfile(t, "chrome_156_macos")
			p.Behavior["http.instance_scope"] = json.RawMessage(`"client"`)
			if !apart {
				delete(p.Behavior, "cookie.identity")
			}
			steps := fixture.Pages[host].Steps
			var want []string
			for _, step := range steps {
				if _, ok := step["set"]; !ok {
					want = append(want, step["show"]+step["subshow"])
				}
			}
			got := cookiesShown(t, p, host, steps)
			same := strings.Join(got, "\n") == strings.Join(want, "\n")
			if apart && !same {
				t.Errorf("%s: sent\n%s\nChrome (%s) sent\n%s", host, strings.Join(got, "\n"), fixture.Browser,
					strings.Join(want, "\n"))
			}
			if !apart && same {
				t.Errorf("%s: without cookie.identity, sent what Chrome sent", host)
			}
		}
	}
}

// apartJar is a jar of tls-forge's own wearing chrome_156_macos's policy, one
// that keeps a host's cookies apart from its domain's where apart.
func apartJar(t *testing.T, apart bool) *keptJar {
	t.Helper()
	inner, err := newDefaultCookieJar(apart)
	if err != nil {
		t.Fatal(err)
	}
	j := newKeptJar(inner)
	j.behavior = shippedProfile(t, "chrome_156_macos").RuntimeBehavior()
	j.apart = apart
	return j
}

// said is what a jar says of its cookies: each one's pair, domain and scope.
func said(cookies []Cookie) string {
	var out []string
	for _, c := range cookies {
		scope := "domain"
		if c.HostOnly {
			scope = "host"
		}
		out = append(out, c.Name+"="+c.Value+" "+c.Domain+" "+scope)
	}
	return strings.Join(out, ", ")
}

// A jar that keeps a host's cookies apart says of each which it is, its
// domain without the dot the inner jar marks a domain's with, set in either
// order; one that does not holds the one set last, and says of it what was
// said when it was set. A partition's jar keeps them as its jar does.
func TestAJarSaysOfEachCookieWhetherItIsItsHostsAlone(t *testing.T) {
	u := mustURL(t, "https://example.test/")
	host := &fhttp.Cookie{Name: "a", Value: "host", Path: "/"}
	domains := &fhttp.Cookie{Name: "a", Value: "dom", Path: "/", Domain: "example.test"}
	for _, tc := range []struct {
		apart bool
		order []*fhttp.Cookie
		want  string
	}{
		{true, []*fhttp.Cookie{host, domains}, "a=host example.test host, a=dom example.test domain"},
		{true, []*fhttp.Cookie{domains, host}, "a=dom example.test domain, a=host example.test host"},
		{false, []*fhttp.Cookie{host, domains}, "a=dom example.test domain"},
		{false, []*fhttp.Cookie{domains, host}, "a=host example.test host"},
	} {
		j := apartJar(t, tc.apart)
		for _, c := range tc.order {
			j.SetCookies(u, []*fhttp.Cookie{c})
		}
		if got := said(j.forURL(u)); got != tc.want {
			t.Errorf("apart %v, %s first: for the URL %q, want %q", tc.apart, tc.order[0].Value, got, tc.want)
		}
		all := j.all()
		sort.SliceStable(all, func(a, b int) bool { return all[a].Value > all[b].Value })
		want := strings.Split(tc.want, ", ")
		sort.Sort(sort.Reverse(sort.StringSlice(want)))
		if got := said(all); got != strings.Join(want, ", ") {
			t.Errorf("apart %v, %s first: all %q, want %q", tc.apart, tc.order[0].Value, got, strings.Join(want, ", "))
		}
	}
	// A request in a browser context carries each by its own SameSite: to
	// another site, the domain's of None, not the host's Strict one.
	j := apartJar(t, true)
	strict, none := *host, *domains
	strict.SameSite, none.SameSite, none.Secure = fhttp.SameSiteStrictMode, fhttp.SameSiteNoneMode, true
	j.SetCookies(u, []*fhttp.Cookie{&strict, &none})
	j.restrict(u, sendRule{crossSite: true, topLevel: true, safe: true})
	var sent []string
	for _, c := range j.Cookies(u) {
		sent = append(sent, c.Name+"="+c.Value)
	}
	j.release(u)
	if strings.Join(sent, "; ") != "a=dom" {
		t.Errorf("a navigation from another site carried %v, want the domain's of None alone", sent)
	}
	j = apartJar(t, true)
	partitioned := func(c *fhttp.Cookie) *fhttp.Cookie {
		out := *c
		out.Secure, out.Unparsed = true, []string{"Partitioned"}
		return &out
	}
	j.SetCookies(u, []*fhttp.Cookie{partitioned(host), partitioned(domains)})
	part := j.partitions[originOf(u).site()]
	if part == nil || !part.apart {
		t.Fatalf("partition %+v", part)
	}
	if got := said(part.forURL(u)); got != "a=host example.test host, a=dom example.test domain" {
		t.Errorf("partition: %q", got)
	}
}

// Only a jar of tls-forge's own keeps a host's cookies apart, and only where
// the profile says cookie.identity name-domain-host-only-path: a caller's
// jar says nothing of which cookie is which.
func TestOnlyAJarOfTLSForgesOwnKeepsAHostsCookiesApart(t *testing.T) {
	scoped := func(identity bool) Option {
		p := shippedProfile(t, "chrome_156_macos")
		p.Behavior["http.instance_scope"] = json.RawMessage(`"client"`)
		if !identity {
			delete(p.Behavior, "cookie.identity")
		}
		return WithProfileValue(p)
	}
	caller, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		opts []Option
		want bool
	}{
		{"its own, the profile saying so", []Option{scoped(true)}, true},
		{"its own, the profile saying nothing", []Option{scoped(false)}, false},
		{"the caller's", []Option{scoped(true), WithCookieJar(caller)}, false},
	} {
		c := newTestClient(t, tc.opts...)
		if got := c.session.jar.apart; got != tc.want {
			t.Errorf("%s: apart %v, want %v", tc.name, got, tc.want)
		}
	}
}
