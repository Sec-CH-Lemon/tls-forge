package tlsforge

import (
	"errors"
	"slices"
	"testing"
	"time"

	fhttp "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
)

// chromeJar is the jar a client wearing chrome_155_macos gets: its cookie
// policy the profile's.
func chromeJar(t *testing.T) *keptJar {
	t.Helper()
	j := newTestJar()
	j.behavior = shippedProfile(t, "chrome_155_macos").RuntimeBehavior()
	return j
}

func TestRawCookieFieldsAreReadAsChromeReadsThem(t *testing.T) {
	j := chromeJar(t)
	u := mustURL(t, "https://www.example.com/")
	// A field with nothing, or nothing but a name's '=', sets nothing; one with
	// a control byte in its pair is passed over; a pair with no '=' is a
	// value with no name, as Chrome takes it.
	taken := j.RawSetCookieHeaders(u, fhttp.Header{"Set-Cookie": {
		"", " ; Path=/", "=", " = ; Path=/", "a=b\x01c", "solo", `q="x y"; Path=/`,
	}})
	if !taken {
		t.Fatal("a Chrome jar left the fields to the transport")
	}
	var got []string
	for _, c := range j.Cookies(u) {
		got = append(got, c.Name+"|"+c.Value)
	}
	slices.Sort(got)
	if want := []string{"q|\"x y\"", "|solo"}; !slices.Equal(got, want) {
		t.Errorf("filed %q, want %q", got, want)
	}
	if line, ok := j.RawCookieHeader(u); !ok || (line != `q="x y"; solo` && line != `solo; q="x y"`) {
		t.Errorf("Cookie %q, %v", line, ok)
	}
	// One the caller filed that could end the field, or begin another, is not sent.
	j.file(u, []*fhttp.Cookie{{Name: "split", Value: "a;b", Path: "/"}, {Name: "line", Value: "a\r\nb", Path: "/"}})
	if line, _ := j.RawCookieHeader(u); line != `q="x y"; solo` && line != `solo; q="x y"` {
		t.Errorf("Cookie %q with a value that ends the field", line)
	}

	// Without the policy the transport reads the fields itself.
	plain := newTestJar()
	if plain.RawSetCookieHeaders(u, fhttp.Header{"Set-Cookie": {"a=1"}}) {
		t.Error("a jar without raw fields took them")
	}
	if _, ok := plain.RawCookieHeader(u); ok {
		t.Error("a jar without raw fields wrote the Cookie")
	}
}

func TestAPartitionedCookieIsKeptApartOrNotAtAll(t *testing.T) {
	u := mustURL(t, "https://www.example.com/a")
	partitioned := func(name string, secure bool, more ...string) *fhttp.Cookie {
		return &fhttp.Cookie{Name: name, Value: "1", Path: "/", Secure: secure, Unparsed: append([]string{"Partitioned"}, more...)}
	}
	j := chromeJar(t)
	// Without a rule the partition is the URL's own site; one that is not
	// Secure is not kept at all, and an attribute the jar did not read stays.
	j.SetCookies(u, []*fhttp.Cookie{partitioned("open", false), partitioned("kept", true, "Priority=High")})
	part := j.partitions[originOf(u).site()]
	if part == nil {
		t.Fatalf("no partition of %s: %v", originOf(u).site(), j.partitions)
	}
	cookies := part.inner.Cookies(u)
	if len(cookies) != 1 || cookies[0].Name != "kept" {
		t.Fatalf("partition holds %v", cookies)
	}
	if facts := part.kept[cookieKey{"kept", "www.example.com", "/"}]; !facts.hostOnly {
		t.Errorf("facts %+v", facts)
	}
	// A request that carries no credentials keeps none.
	none := chromeJar(t)
	none.rules.Store(u, sendRule{none: true})
	none.SetCookies(u, []*fhttp.Cookie{partitioned("kept", true)})
	if len(none.partitions) != 0 {
		t.Errorf("a request without credentials kept %v", none.partitions)
	}
	// A partition whose jar cannot be made keeps nothing.
	broken := chromeJar(t)
	original := newDefaultCookieJar
	t.Cleanup(func() { newDefaultCookieJar = original })
	newDefaultCookieJar = func() (fhttp.CookieJar, error) { return nil, errors.New("no jar") }
	broken.SetCookies(u, []*fhttp.Cookie{partitioned("kept", true)})
	if len(broken.partitions) != 0 {
		t.Errorf("a partition without a jar: %v", broken.partitions)
	}
}

func TestAChromeJarTakesAnAddressAsItsCookiesHost(t *testing.T) {
	u := mustURL(t, "https://127.0.0.1:8443/")
	// Chrome takes Domain=127.0.0.1 from 127.0.0.1 as the host's alone; the
	// jar under it refuses a Domain on an address, so it is filed without one.
	j := chromeJar(t)
	j.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "1", Domain: "127.0.0.1", Path: "/"}})
	if got := j.Cookies(u); len(got) != 1 || got[0].Name != "a" {
		t.Errorf("Chrome's jar holds %v", got)
	}
	plain := newTestJar()
	plain.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "1", Domain: "127.0.0.1", Path: "/"}})
	if got := plain.Cookies(u); len(got) != 0 {
		t.Errorf("a jar without the rule holds %v", got)
	}
}

func TestACookieTheJarHasNoOrderForGoesAfterThoseItHas(t *testing.T) {
	j := chromeJar(t)
	u := mustURL(t, "https://www.example.com/")
	j.SetCookies(u, []*fhttp.Cookie{{Name: "known", Value: "1", Path: "/"}})
	// Set behind the wrapper: no order of its own, so last among equal paths.
	j.inner.SetCookies(u, []*fhttp.Cookie{{Name: "behind", Value: "2", Path: "/"}})
	got := j.Cookies(u)
	if len(got) != 2 || got[0].Name != "known" || got[1].Name != "behind" {
		t.Errorf("order %v", got)
	}
}

func TestLimitsAndLifetimesAreThePolicysOrNone(t *testing.T) {
	long := string(make([]byte, 5000))
	c := &fhttp.Cookie{Name: "a", Value: "1", Path: "/" + long, MaxAge: 1 << 30}
	if got := withinLimits(c, behavior.Policy{}); got != c {
		t.Error("a policy without an attribute limit changed the cookie")
	}
	got := capLifetime(c, time.Now(), behavior.Policy{})
	if got == c || got.MaxAge != c.MaxAge {
		t.Errorf("without a lifetime: %+v, want an unchanged copy", got)
	}
}
