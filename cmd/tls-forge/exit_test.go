package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
