package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge/v7"
	"github.com/Sec-CH-Lemon/tls-forge/v7/profile"
)

// shippedServices is the list as it ships, kept from before TestMain puts a
// stand-in in its place.
var shippedServices = ipServices

// waitAtMost lowers how long a lookup waits, for one test.
func waitAtMost(t *testing.T, d time.Duration) {
	t.Helper()
	original := exitLookupWait
	t.Cleanup(func() { exitLookupWait = original })
	exitLookupWait = d
}

// answering is a stand-in address service that says the same thing every time,
// and counts how often it was asked.
func answering(t *testing.T, read func([]byte) egress, status int, body string) (addressService, *atomic.Int32) {
	t.Helper()
	asked := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return addressService{URL: server.URL, read: read}, asked
}

// silent is a stand-in address service that takes the question and never
// answers it.
func silent(t *testing.T) (addressService, *atomic.Int32) {
	t.Helper()
	asked := &atomic.Int32{}
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		asked.Add(1)
		<-release
	}))
	// Registered first so it runs last: the handler has to be let go before the
	// server can finish closing.
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	return addressService{URL: server.URL, read: readJSON}, asked
}

// tracePage is what Cloudflare's trace page looks like.
const tracePage = "fl=1f1\nh=www.cloudflare.com\nip=203.0.113.7\nts=1760000000.000\n" +
	"visit_scheme=https\nuag=Mozilla/5.0\ncolo=WAW\nhttp=http/2\nloc=PL\ntls=TLSv1.3\nwarp=off\n"

func TestTheServicesAskedAndTheirOrder(t *testing.T) {
	// The order is a decision, and the README states it. Each of the four is
	// run by somebody different, which is the point of having more than one.
	var names []string
	for _, service := range shippedServices {
		names = append(names, service.name())
		if !strings.HasPrefix(service.URL, "https://") {
			t.Errorf("%s is not asked over TLS", service.URL)
		}
		if service.read == nil {
			t.Errorf("%s has nothing to read its answer with", service.URL)
		}
	}
	want := []string{"www.cloudflare.com", "checkip.amazonaws.com", "api.ipify.org", "ipinfo.io"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("services = %v, want %v", names, want)
	}
}

func TestReadingWhatEachServiceSays(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func([]byte) egress
		body string
		want egress
	}{
		{"a trace page", readTrace, tracePage, egress{IP: "203.0.113.7", Country: "PL"}},
		// XX is how the page says it does not know, and it is not a country.
		{"a trace page that does not know the country", readTrace, "ip=203.0.113.7\nloc=XX\n",
			egress{IP: "203.0.113.7"}},
		{"a trace page with Windows line endings", readTrace, "ip=203.0.113.7\r\nloc=PL\r\n",
			egress{IP: "203.0.113.7", Country: "PL"}},
		{"a page that is not a trace", readTrace, "<html>blocked</html>", egress{}},
		{"an address on a line of its own", readAddress, "203.0.113.7\n", egress{IP: "203.0.113.7"}},
		{"an address and nothing else", readJSON, `{"ip":"203.0.113.7"}`, egress{IP: "203.0.113.7"}},
		{"an address and a country", readJSON, `{"ip":"203.0.113.7","country":"PL","city":"Warsaw"}`,
			egress{IP: "203.0.113.7", Country: "PL"}},
		{"an answer that is not JSON", readJSON, "<html>blocked</html>", egress{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.read([]byte(tc.body)); got != tc.want {
				t.Errorf("read %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAServiceIsCalledByItsHost(t *testing.T) {
	if got := (addressService{URL: "https://api.ipify.org?format=json"}).name(); got != "api.ipify.org" {
		t.Errorf("name = %q", got)
	}
	// Something that is not a URL is called what it was given as, rather than
	// nothing.
	for _, given := range []string{"checkip", "://nowhere"} {
		if got := (addressService{URL: given}).name(); got != given {
			t.Errorf("name of %q = %q", given, got)
		}
	}
}

func TestSayingWhoIsAsked(t *testing.T) {
	askOnly(t, addressService{URL: "https://one.example/trace"}, addressService{URL: "https://two.example"})
	if got := askedOf(); got != "one.example, then two.example" {
		t.Errorf("askedOf = %q", got)
	}
}

func TestTheFirstServiceToAnswerIsTheOnlyOneAsked(t *testing.T) {
	// The ordinary case, and the reason there is an order at all: one question,
	// to one party.
	first, _ := answering(t, readTrace, http.StatusOK, tracePage)
	second, askedSecond := answering(t, readAddress, http.StatusOK, "198.51.100.9\n")
	askOnly(t, first, second)

	found, err := lookupExit(context.Background(), insecureFlags(t), "")
	if err != nil {
		t.Fatalf("lookupExit: %v", err)
	}
	if want := (egress{IP: "203.0.113.7", Country: "PL"}); found != want {
		t.Errorf("found %+v, want %+v", found, want)
	}
	if got := askedSecond.Load(); got != 0 {
		t.Errorf("the second service was asked %d times after the first had answered", got)
	}
}

func TestTheNextServiceIsAskedAtOnceWhenOneFails(t *testing.T) {
	// Something came back and it was not an address, so there is nothing left
	// to wait for from that service.
	first, askedFirst := answering(t, readTrace, http.StatusServiceUnavailable, "down for maintenance")
	second, _ := answering(t, readAddress, http.StatusOK, "198.51.100.9\n")
	askOnly(t, first, second)

	started := time.Now()
	found, err := lookupExit(context.Background(), insecureFlags(t), "")
	took := time.Since(started)
	if err != nil {
		t.Fatalf("lookupExit: %v", err)
	}
	// From the second, which says the address and no country.
	if want := (egress{IP: "198.51.100.9"}); found != want {
		t.Errorf("found %+v, want %+v", found, want)
	}
	if got := askedFirst.Load(); got != 1 {
		t.Errorf("the first service was asked %d times, want once", got)
	}
	// At once: the first service's share of the wait is for a service that has
	// said nothing yet, not for one that has already failed.
	if share := exitLookupWait / 2; took >= share {
		t.Errorf("took %s, which is the first service's whole share of the wait (%s)", took, share)
	}
}

func TestTheNextServiceIsAskedWhenOneSaysNothing(t *testing.T) {
	// The first has its share of the wait and is not given up on, but the
	// second is asked as well, and whoever answers first is believed.
	first, askedFirst := silent(t)
	second, _ := answering(t, readJSON, http.StatusOK, `{"ip":"198.51.100.9","country":"de"}`)
	askOnly(t, first, second)
	waitAtMost(t, 2*time.Second)

	found, err := lookupExit(context.Background(), insecureFlags(t), "")
	if err != nil {
		t.Fatalf("lookupExit: %v", err)
	}
	if found.IP != "198.51.100.9" {
		t.Errorf("found %+v, want the second service's answer", found)
	}
	if got := askedFirst.Load(); got != 1 {
		t.Errorf("the first service was asked %d times, want once", got)
	}
}

func TestWhenNobodyAnswersTheFirstFailureIsTheOneReported(t *testing.T) {
	first, _ := answering(t, readJSON, http.StatusTooManyRequests, "slow down")
	second, _ := answering(t, readJSON, http.StatusOK, "<html>not an address</html>")
	askOnly(t, first, second)

	_, err := lookupExit(context.Background(), insecureFlags(t), "")
	// What the first one made of it, and that it was not the only one asked.
	want := first.URL + ": HTTP 429 (2 of 2 services asked, none answered)"
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %s", err, want)
	}
}

func TestTheWaitEndsWhateverAQuestionIsInTheMiddleOf(t *testing.T) {
	// Reading an answer is not something a deadline can interrupt, so this
	// question is still going when the time runs out. The wait ends anyway, and
	// says how far down the list it got.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stuck, _ := answering(t, func([]byte) egress {
		<-release
		return egress{}
	}, http.StatusOK, "anything")
	never, _ := silent(t)
	askOnly(t, stuck, never)
	waitAtMost(t, 400*time.Millisecond)

	started := time.Now()
	_, err := lookupExit(context.Background(), insecureFlags(t), "")
	took := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want the wait running out", err)
	}
	if !strings.Contains(err.Error(), "of 2 services asked, none answered") {
		t.Errorf("error does not say how many were asked: %v", err)
	}
	// Nowhere near the half minute a request is allowed.
	if took > 10*time.Second {
		t.Errorf("took %s", took)
	}
}

func TestExitIn(t *testing.T) {
	answer := func(fields ...string) tlsforge.Header {
		var header tlsforge.Header
		for i := 0; i < len(fields); i += 2 {
			header = append(header, profile.Field{Name: fields[i], Value: fields[i+1]})
		}
		return header
	}
	table, err := parseExitTable(builtInExitHeaders, "exit-headers.json")
	builtIn := table.Fields
	if err != nil {
		t.Fatalf("the fields built in: %v", err)
	}
	for _, tc := range []struct {
		name   string
		answer tlsforge.Header
		named  string
		want   egress
	}{
		{"Massive's, with its country", answer("x-exit-country", "NL", "x-exit-ip", " 198.51.100.1 "), "",
			egress{IP: "198.51.100.1", Country: "NL"}},
		{"ProxyMesh's, written the way an address is", answer("x-proxymesh-ip", "2001:DB8:0::1"), "",
			egress{IP: "2001:db8::1"}},
		{"an address with its port", answer("x-exit-ip", "[2001:db8::1]:8080"), "", egress{IP: "2001:db8::1"}},
		{"a field of a file of one's own comes first", answer("x-exit-ip", "198.51.100.1", "x-egress", "192.0.2.44:3128"),
			"X-Egress", egress{IP: "192.0.2.44"}},
		{"a field nobody knows", answer("x-egress", "192.0.2.44"), "", egress{}},
		{"nothing said", nil, "", egress{}},
		// Somebody else's text, which fetch prints on a terminal: it is an
		// address or it is nothing, and the next field is read instead.
		{"an address that is not one", answer("x-exit-ip", "203.0.113.7\x1b[2J", "x-proxymesh-ip", "192.0.2.1"), "",
			egress{IP: "192.0.2.1"}},
		{"an address with a zone", answer("x-exit-ip", "fe80::1%\x1b[2J"), "", egress{}},
		{"an IPv4 address with a zone, written as IPv6", answer("x-exit-ip", "::ffff:198.51.100.1%eth0"), "", egress{}},
		// 0.0.0.0 and :: name no exit, and the next field is read instead.
		{"the unspecified address", answer("x-exit-ip", "0.0.0.0", "x-proxymesh-ip", "192.0.2.1"), "",
			egress{IP: "192.0.2.1"}},
		{"the unspecified IPv6 address, with a port", answer("x-exit-ip", "[::]:3128"), "", egress{}},
		// One address, two ways of writing it, one exit.
		{"an IPv4 address written as IPv6", answer("x-exit-ip", "::ffff:198.51.100.1"), "", egress{IP: "198.51.100.1"}},
		{"an IPv4 address written as IPv6, with a port", answer("x-exit-ip", "[::ffff:198.51.100.1]:80"), "",
			egress{IP: "198.51.100.1"}},
		// Bright Data's, which says a hash of the address and not the address.
		{"a hash of the address", answer("x-brd-ip", "raecd029229048fbbfd0b932221a3e40a"), "",
			egress{Hash: "raecd029229048fbbfd0b932221a3e40a"}},
		{"the address before a hash of it", answer("x-brd-ip", "raecd029229048fbbfd0b932221a3e40a", "x-exit-ip", "198.51.100.1"),
			"", egress{IP: "198.51.100.1"}},
		{"a hash in a field of one's own", answer("x-egress", "0123456789abcdef"), "x-egress", egress{Hash: "0123456789abcdef"}},
		// Too short to be one, or with something in it no hash has.
		{"a word", answer("x-brd-ip", "unknown"), "", egress{}},
		{"a hash with more in it", answer("x-brd-ip", "raecd029229048fbbfd0b932221a3e40a\x1b[2J"), "", egress{}},
		// A field says what it holds, and holds nothing else.
		{"a hash where an address goes", answer("x-exit-ip", "raecd029229048fbbfd0b932221a3e40a"), "", egress{}},
		{"an address where a hash goes", answer("x-hashed", "198.51.100.1"), "x-hashed", egress{}},
		// Bright Data's holds the address on some zones, and on none when the
		// super proxy was the exit.
		{"Bright Data's address", answer("x-brd-ip", "198.51.100.9"), "", egress{IP: "198.51.100.9"}},
		{"Bright Data's super proxy", answer("x-brd-ip", "superproxy bypass"), "", egress{}},
		// A parameter of a field made of them.
		{"Bright Data's Proxy-Status", answer("proxy-status",
			`brd.superproxy.io; received-status=200; brd_ip="raecd029229048fbbfd0b932221a3e40a"; brd_timeline="init:0,auth:10"`),
			"", egress{Hash: "raecd029229048fbbfd0b932221a3e40a"}},
		{"g3proxy's egress", answer("x-bd-dynamic-egress-info", "edge-1; isp=Example; ip=203.0.113.20; area=a/b"), "",
			egress{IP: "203.0.113.20"}},
		{"a field without the parameter", answer("proxy-status", "brd.superproxy.io; received-status=200"), "", egress{}},
		// A Proxy-Status that two proxies wrote, and a parameter written inside
		// the quotes of another's value, which is not one.
		{"a Proxy-Status of two proxies", answer("proxy-status",
			`edge.example; received-status=200, brd.superproxy.io; brd_ip="raecd029229048fbbfd0b932221a3e40a"`),
			"", egress{Hash: "raecd029229048fbbfd0b932221a3e40a"}},
		{"a parameter inside another's quotes", answer("proxy-status",
			`brd.superproxy.io; details="x; brd_ip=198.51.100.66, y"; brd_ip="raecd029229048fbbfd0b932221a3e40a"`),
			"", egress{Hash: "raecd029229048fbbfd0b932221a3e40a"}},
		// SOAX's, when the CONNECT asked for it.
		{"SOAX's, with its country", answer("node-ip", "203.0.113.30", "node-country", "al"), "",
			egress{IP: "203.0.113.30", Country: "al"}},
	} {
		fields := builtIn
		if tc.named == "x-hashed" {
			fields = []exitField{{Header: tc.named, Value: "hash"}}
		} else if tc.named != "" {
			fields = append([]exitField{{Header: tc.named}}, builtIn...)
		}
		if got, _ := exitIn(tc.answer, fields, "connect"); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestExitFieldsOfOtherShapes(t *testing.T) {
	answer := tlsforge.Header{
		// Scrapoxy names the connector and the proxy it went out through.
		{Name: "x-scrapoxy-proxyname", Value: "6f1c0d9e-2b4a:7f8e09ed-8c00"},
		// Bright Data's Web Unlocker says the peer and its country in one field.
		{Name: "x-brd-debug", Value: "req_id=1; peer_ip=r868133f79d0c3fa9d7c7ccca0151af2e; peer_country=us"},
	}
	for _, tc := range []struct {
		name  string
		field exitField
		want  egress
	}{
		{"a name", exitField{Header: "X-Scrapoxy-Proxyname", Value: "name"}, egress{Hash: "6f1c0d9e-2b4a:7f8e09ed-8c00"}},
		{"a name is not a hash", exitField{Header: "X-Scrapoxy-Proxyname", Value: "hash"}, egress{}},
		{"a parameter, and the country in another", exitField{Header: "x-brd-debug", Param: "peer_ip", Value: "hash",
			Country: "x-brd-debug", CountryParam: "peer_country"},
			egress{Hash: "r868133f79d0c3fa9d7c7ccca0151af2e", Country: "us"}},
		// Somebody else's text, which a name has to be as plain as a hash.
		{"a name that is not one", exitField{Header: "x-brd-debug", Value: "name"}, egress{}},
	} {
		if got, _ := exitIn(answer, []exitField{tc.field}, "connect"); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// What every CONNECT says, for the proxies that answer only when asked.
	asked := askedBy([]exitField{
		{Header: "Node-Ip", Ask: map[string]string{"Respond-With": "ip,country"}},
		{Header: "X-Exit-IP"},
		{Header: "X-Other", Ask: map[string]string{"A-First": "1"}},
	})
	if want := (tlsforge.Header{{Name: "A-First", Value: "1"}, {Name: "Respond-With", Value: "ip,country"}}); !reflect.DeepEqual(asked, want) {
		t.Errorf("asked = %v, want %v", asked, want)
	}
	// A name asked for twice is said once, in any case, as the first field to
	// ask for it asks, whatever order a field's own names are read in.
	for range 50 {
		asked = askedBy([]exitField{
			{Header: "X-Mine", Ask: map[string]string{"respond-with": "ip", "Respond-With": "country"}},
			{Header: "Node-Ip", Ask: map[string]string{"Respond-With": "ip,country"}},
		})
		if want := (tlsforge.Header{{Name: "Respond-With", Value: "country"}}); !reflect.DeepEqual(asked, want) {
			t.Fatalf("asked twice = %v, want %v", asked, want)
		}
	}
}

func TestBuiltInExitHeaders(t *testing.T) {
	// Every field and probe says who sends it and where that is written down, so
	// that the file can be checked against what each provider says it does, and
	// none of them is there twice.
	table, err := parseExitTable(builtInExitHeaders, "exit-headers.json")
	if err != nil || len(table.Fields) < 3 || len(table.Probes) == 0 {
		t.Fatalf("the table built in: %d fields, %d probes, %v", len(table.Fields), len(table.Probes), err)
	}
	seen := map[string]bool{}
	for _, field := range table.Fields {
		if field.Provider == "" || !strings.HasPrefix(field.Source, "https://") || seen[field.key()] || field.Off {
			t.Errorf("%+v says nothing of where it comes from, is there twice, or is off", field)
		}
		seen[field.key()] = true
	}
	for _, probe := range table.Probes {
		if probe.Provider == "" || !strings.HasPrefix(probe.Source, "https://") || seen[probe.key()] || probe.Off {
			t.Errorf("%+v says nothing of where it comes from, is there twice, or is off", probe)
		}
		seen[probe.key()] = true
	}
}

func TestTheExampleExitHeaders(t *testing.T) {
	// The example is a file laid over the table built in, doing each thing such
	// a file can do.
	data, err := os.ReadFile(filepath.Join("..", "..", "example", "exit-headers.json"))
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	over, err := parseExitTable(data, "example/exit-headers.json")
	if err != nil {
		t.Fatalf("the example: %v", err)
	}
	builtIn, _ := parseExitTable(builtInExitHeaders, "exit-headers.json")
	merged := mergeExitTables(builtIn, over)
	keys := map[string]exitField{}
	for _, field := range merged.Fields {
		keys[field.key()] = field
	}
	// A field added, and read first; one replaced, without its resolve; one
	// taken out, and with it what every CONNECT said for it; the probe out.
	if merged.Fields[0].Header != "X-Egress-IP" || keys["x-brd-ip in connect"].Resolve != nil ||
		keys["node-ip in connect"].Header != "" || len(askedBy(merged.Fields)) != 0 || len(merged.Probes) != 0 {
		t.Errorf("the example laid over the table built in: %+v", merged)
	}
}

func TestParseExitFields(t *testing.T) {
	for _, tc := range []struct{ name, file, want string }{
		{"not JSON", `[`, "unexpected EOF"},
		{"a name misspelled", `{"fields": [{"headr": "X-Exit-IP"}]}`, `unknown field "headr"`},
		{"no header", `{"fields": [{"value": "address"}]}`, "field 1 needs a header"},
		{"a value nobody knows", `{"fields": [{"header": "X-Exit-IP"}, {"header": "X-Egress", "value": "ip"}]}`,
			"field 2 needs a value of address, hash, name or none"},
		{"a place nobody knows", `{"fields": [{"header": "X-Egress", "in": "body"}]}`,
			"and to be in connect, response or nowhere said"},
		// What is taken out still has to say what it takes out.
		{"a field off without its name", `{"fields": [{"off": true}]}`, "field 1 needs a header"},
		{"a probe off without its path", `{"fields": [], "probes": [{"when": "cf-ray", "off": true}]}`, "probe 1 needs"},

		// Nothing, or more than one table: a file cut short or two run together.
		{"nothing in the file", "", "the file is empty"},
		{"only whitespace", " \n\t", "the file is empty"},
		{"two tables", `{"fields": []} {"fields": []}`, "more after the table, which nothing would read"},
		{"something after the table", `{"fields": []} x`, "more after the table"},

		// A name no header field can have would never be found.
		{"a header with a colon after it", `{"fields": [{"header": "X-Exit-IP:"}]}`,
			`field 1 needs a header, and "X-Exit-IP:" is not the name of one`},
		{"a header with a space in it", `{"fields": [{"header": "X Exit"}]}`, `"X Exit" is not the name of one`},
		{"a header with spaces around it", `{"fields": [{"header": " X-Exit-IP "}]}`, `" X-Exit-IP " is not the name`},
		{"a country that is not a field", `{"fields": [{"header": "X-Exit-IP", "country": "X Country"}]}`,
			`field 1 names its country in "X Country", which is not the name of a header field`},
		{"a probe that waits for no field", `{"fields": [], "probes": [{"when": "cf ray", "path": "/p", "format": "lines",
			"ip": "ip"}]}`, "probe 1 needs a field to come when"},

		// What every CONNECT is made to say has to be something it can say.
		{"an ask no field can be", `{"fields": [{"header": "Node-Ip", "ask": {"Respond With": "ip"}}]}`,
			`field 1 asks every CONNECT to say "Respond With": "ip", which a CONNECT cannot say`},
		{"an ask with a line break in it", `{"fields": [{"header": "Node-Ip", "ask": {"Respond-With": "ip\r\nX-More: 1"}}]}`,
			"which a CONNECT cannot say"},
		{"an ask that frames the CONNECT", `{"fields": [{"header": "Node-Ip", "ask": {"Content-Length": "5"}}]}`,
			`to say "Content-Length"`},
		{"an ask for the credentials", `{"fields": [{"header": "Node-Ip", "ask": {"proxy-authorization": "Basic eA=="}}]}`,
			`to say "proxy-authorization"`},

		// A resolve has to ask the web.
		{"a resolve of no scheme it can ask", `{"fields": [{"header": "x", "resolve": {"user": "{value}", "url": "httpx://a/",
			"format": "json", "ip": "ip"}}]}`, "an http or https URL"},
		{"a resolve of no host", `{"fields": [{"header": "x", "resolve": {"user": "{value}", "url": "https:///myip.json",
			"format": "json", "ip": "ip"}}]}`, "an http or https URL"},

		// The second of two of the same key would never be read.
		{"the same field twice", `{"fields": [{"header": "X-Exit-IP"}, {"header": "x-exit-ip", "value": "address"}]}`,
			"field 2 has the key of field 1, x-exit-ip in connect"},
		{"the same parameter twice", `{"fields": [{"header": "Proxy-Status", "param": "brd_ip"},
			{"header": "proxy-status", "param": "BRD_IP"}]}`, "field 2 has the key of field 1, proxy-status in connect param brd_ip"},
		{"a field, and the same taken out", `{"fields": [{"header": "X-Exit-IP"}, {"header": "X-Exit-IP", "off": true}]}`,
			"field 2 has the key of field 1"},
		{"the same probe twice", `{"fields": [], "probes": [{"when": "cf-ray", "path": "/p", "format": "lines", "ip": "ip"},
			{"when": "CF-Ray", "path": "/p", "format": "json", "ip": "ip"}]}`, "probe 2 has the key of probe 1, cf-ray /p"},
	} {
		if _, err := parseExitTable([]byte(tc.file), "mine.json"); err == nil ||
			!strings.HasPrefix(err.Error(), "fetch: mine.json: ") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	// What may be: a byte order mark before the table, one field read for two
	// parameters, the same field in either answer, and a file of nothing to lay
	// over.
	for _, file := range []string{
		"\xef\xbb\xbf" + `{"fields": [{"header": "X-Exit-IP"}]}`,
		`{"fields": [{"header": "Proxy-Status", "param": "brd_ip"}, {"header": "Proxy-Status", "param": "exit_ip"}]}`,
		`{"fields": [{"header": "X-Crawlera-Slave"}, {"header": "X-Crawlera-Slave", "in": "response"}]}`,
		"null\n",
	} {
		if _, err := parseExitTable([]byte(file), "mine.json"); err != nil {
			t.Errorf("%q: %v", file, err)
		}
	}
}

func TestMergeExitTables(t *testing.T) {
	base := exitTable{
		About: "ours",
		Fields: []exitField{
			{Header: "X-Exit-IP", Provider: "ours"}, {Header: "x-brd-ip"}, {Header: "X-Crawlera-Slave", In: "response"},
		},
		Probes: []exitProbe{{When: "cf-ray", Path: "/cdn-cgi/trace"}, {When: "x-other", Path: "/ip"}},
	}
	over := exitTable{
		Fields: []exitField{
			// Added, replacing, and taking out: the key is the name in any case,
			// and the answer it comes in.
			{Header: "X-Egress"}, {Header: "x-exit-ip", Provider: "mine"}, {Header: "X-BRD-IP", Off: true},
			{Header: "X-Crawlera-Slave", In: "response", Off: true},
		},
		Probes: []exitProbe{{When: "CF-Ray", Path: "/cdn-cgi/trace", Off: true}},
	}
	merged := mergeExitTables(base, over)
	var fields []string
	for _, field := range merged.Fields {
		fields = append(fields, field.Header+" "+field.Provider)
	}
	if want := []string{"X-Egress ", "x-exit-ip mine"}; !slices.Equal(fields, want) || merged.About != "ours" {
		t.Errorf("fields %q, about %q, want %q and ours", fields, merged.About, want)
	}
	if len(merged.Probes) != 1 || merged.Probes[0].When != "x-other" {
		t.Errorf("probes %+v", merged.Probes)
	}
	// A field in the response is another field than one of the same name in
	// the answer to CONNECT, and an about of its own replaces ours.
	merged = mergeExitTables(base, exitTable{About: "mine", Fields: []exitField{{Header: "X-Crawlera-Slave"}}})
	if len(merged.Fields) != 4 || merged.About != "mine" {
		t.Errorf("a field in the answer to CONNECT laid over one in the response: %+v", merged)
	}
	// One field read for more than one parameter: a parameter of one's own is
	// added beside the table's, and the table's is taken out by its own name.
	withParam := exitTable{Fields: []exitField{{Header: "Proxy-Status", Param: "brd_ip"}}}
	merged = mergeExitTables(withParam, exitTable{Fields: []exitField{{Header: "proxy-status", Param: "exit_ip"}}})
	if len(merged.Fields) != 2 || merged.Fields[0].Param != "exit_ip" || merged.Fields[1].Param != "brd_ip" {
		t.Errorf("a parameter of one's own: %+v", merged.Fields)
	}
	merged = mergeExitTables(withParam, exitTable{Fields: []exitField{{Header: "Proxy-Status", Param: "BRD_IP", Off: true}}})
	if len(merged.Fields) != 0 {
		t.Errorf("the table's parameter taken out: %+v", merged.Fields)
	}
	merged = mergeExitTables(withParam, exitTable{Fields: []exitField{{Header: "Proxy-Status", Off: true}}})
	if len(merged.Fields) != 1 {
		t.Errorf("the field taken out without the parameter takes out another: %+v", merged.Fields)
	}
}

func TestLoadExitTable(t *testing.T) {
	builtIn, err := loadExitTable("")
	if err != nil || len(builtIn.Fields) == 0 || builtIn.Fields[0].Header != "X-Exit-IP" {
		t.Fatalf("the table built in: %+v, %v", builtIn.Fields, err)
	}
	// The file named, wherever it is, laid over the table built in.
	dir := t.TempDir()
	mine := filepath.Join(dir, "mine.json")
	if err := os.WriteFile(mine, []byte(`{"fields": [{"header": "X-Named"}, {"header": "X-Exit-IP", "off": true}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	table, err := loadExitTable(mine)
	if err != nil || table.Fields[0].Header != "X-Named" || len(table.Fields) != len(builtIn.Fields) {
		t.Errorf("with a file named: %+v, %v", table.Fields, err)
	}
	// A file that was named has to be there, and one that is broken is said.
	if _, err := loadExitTable(filepath.Join(dir, "none.json")); err == nil || !strings.Contains(err.Error(), "none.json") {
		t.Errorf("a file named and not there: %v", err)
	}
	if err := os.WriteFile(mine, []byte(`{"fields": [{}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadExitTable(mine); err == nil || !strings.Contains(err.Error(), "mine.json: field 1") {
		t.Errorf("a file named that is broken: %v", err)
	}
	original := builtInExitHeaders
	t.Cleanup(func() { builtInExitHeaders = original })
	builtInExitHeaders = []byte(`{`)
	if _, err := loadExitTable(""); err == nil || !strings.Contains(err.Error(), "built in") {
		t.Errorf("a broken table built in: %v", err)
	}
}

func TestEgressShown(t *testing.T) {
	hashed := egress{Hash: "raecd029229048fbbfd0b932221a3e40a"}
	for _, tc := range []struct {
		exit  egress
		known bool
		shown string
		said  string
		args  traceArgs
	}{
		{egress{}, false, "", "", traceArgs{}},
		{egress{IP: "203.0.113.7", Country: "pl"}, true, "203.0.113.7", "203.0.113.7 · PL",
			traceArgs{"exit_ip": "203.0.113.7", "exit_country": "PL"}},
		// The whole of a hash, which is what can be compared with another.
		{hashed, true, "raecd029229048fbbfd0b932221a3e40a", "raecd029229048fbbfd0b932221a3e40a (the proxy's name for the address)",
			traceArgs{"exit_hash": "raecd029229048fbbfd0b932221a3e40a"}},
		{egress{Hash: "0123456789abcdef"}, true, "0123456789abcdef", "0123456789abcdef (the proxy's name for the address)",
			traceArgs{"exit_hash": "0123456789abcdef"}},
		// Found by asking, when the proxy did not say: and by asking whom.
		{egress{IP: "198.51.100.1", Country: "NL", By: "Cloudflare /cdn-cgi/trace, on the same connection"}, true,
			"198.51.100.1", "198.51.100.1 · NL (by Cloudflare /cdn-cgi/trace, on the same connection)",
			traceArgs{"exit_ip": "198.51.100.1", "exit_country": "NL", "exit_by": "Cloudflare /cdn-cgi/trace, on the same connection"}},
	} {
		args := traceArgs{}
		tc.exit.into(args)
		if tc.exit.Known() != tc.known || tc.exit.Shown() != tc.shown || !reflect.DeepEqual(args, tc.args) {
			t.Errorf("%+v: known %v, shown %q, traced %v", tc.exit, tc.exit.Known(), tc.exit.Shown(), args)
		}
		if tc.known {
			if got := describeExit(tc.exit, nil, ""); got != tc.said {
				t.Errorf("%+v is said as %q, want %q", tc.exit, got, tc.said)
			}
		}
	}
}

func TestExitThrough(t *testing.T) {
	said := tlsforge.ConnInfo{ProxyHeader: tlsforge.Header{{Name: "x-exit-ip", Value: "203.0.113.1"}}}
	for _, tc := range []struct {
		name  string
		tries []try
		want  egress
		why   string
	}{
		// The tries were not kept, so there is nothing to read.
		{"no tries", nil, egress{}, ""},
		{"the last try never connected", []try{{Connected: true, Conn: said}, {}}, egress{}, ""},
		{"the proxy said nothing", []try{{Connected: true}}, egress{}, "the proxy did not say"},
		{"the proxy said", []try{{}, {Connected: true, Conn: said}}, egress{IP: "203.0.113.1"}, ""},
	} {
		found, why, _ := exitThrough(tc.tries, nil, []exitField{{Header: "x-exit-ip"}})
		if found != tc.want || why != tc.why {
			t.Errorf("%s: %+v, %q", tc.name, found, why)
		}
	}
	// No file to read the answer with is not a proxy that said nothing.
	if found, why, _ := exitThrough([]try{{Connected: true, Conn: said}}, nil, nil); found.Known() ||
		why != "no field in exit-headers.json to read the proxy's answer with" {
		t.Errorf("without fields: %+v, %q", found, why)
	}
	// Every try is given where its own connection came out.
	tries := []try{{Connected: true, Conn: said}, {}}
	_, _, _ = exitThrough(tries, nil, []exitField{{Header: "x-exit-ip"}})
	if tries[0].Exit.IP != "203.0.113.1" || tries[1].Exit.IP != "" {
		t.Errorf("the tries came out of %+v and %+v", tries[0].Exit, tries[1].Exit)
	}

	// A proxy that reads the traffic says it in the answer to the request, which
	// is believed only when the answer to CONNECT said nothing.
	fields := []exitField{{Header: "x-exit-ip"}, {Header: "x-crawlera-slave", In: "response"}}
	answer := map[string][]string{"x-crawlera-slave": {"107.183.168.12:4444"}, "server": {"test"}}
	if found, why, _ := exitThrough([]try{{Connected: true}}, answer, fields); found.IP != "107.183.168.12" || why != "" {
		t.Errorf("from the answer to the request: %+v, %q", found, why)
	}
	if found, _, _ := exitThrough([]try{{Connected: true, Conn: said}}, answer, fields); found.IP != "203.0.113.1" {
		t.Errorf("the answer to the request was believed over the proxy's: %+v", found)
	}
	// And a field of the answer to the request is not looked for in the answer to CONNECT.
	crawlera := tlsforge.ConnInfo{ProxyHeader: tlsforge.Header{{Name: "x-crawlera-slave", Value: "107.183.168.12:4444"}}}
	if found, why, _ := exitThrough([]try{{Connected: true, Conn: crawlera}}, nil, fields); found.Known() || why != "the proxy did not say" {
		t.Errorf("a field of the response read in the answer to CONNECT: %+v, %q", found, why)
	}
}
