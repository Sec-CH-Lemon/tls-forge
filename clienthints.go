package tlsforge

import (
	"github.com/igor-lemon/utls/behavior"
	"slices"
	"strings"
	"sync"

	fhttp "github.com/igor-lemon/fhttp"

	"github.com/Sec-CH-Lemon/tls-forge/v6/profile"
)

// Client hints a server asks for, as Chrome 155 was measured keeping and
// sending them (testdata/chrome155-requests.json). An origin asks with
// Accept-CH on the answer to a navigation, a form's or a redirect's included,
// and over a connection a page may trust; what it asked for replaces what it
// asked before, an empty Accept-CH asks for nothing, and an answer without
// one leaves it as it was. From then on, for the session, every navigation to
// that origin carries those hints, and so do the fetch() and XHR requests a
// page of it makes to it. Another origin, of the same site or not, gets none
// of them, nor does a page of another site asking that origin.

// hintStore is what each origin asked for, for a session: every client made
// Fresh from one shares it.
type hintStore struct {
	behavior behavior.Policy
	mu       sync.Mutex
	asked    map[origin][]string
}

func newHintStore(policies ...behavior.Policy) *hintStore {
	return &hintStore{behavior: policyArgument(policies), asked: map[origin][]string{}}
}

// remember keeps what an answer from origin o asked for with Accept-CH, when
// it says it at all, and says what that is.
func (s *hintStore) remember(o origin, header fhttp.Header) (asked []string, said bool) {
	fields := header.Values("Accept-CH")
	if fields == nil || !trustworthy(o) {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if asked = askedHints(fields, s.behavior); len(asked) > 0 {
		s.asked[o] = asked
		return asked, true
	}
	delete(s.asked, o)
	return nil, true
}

// of are the hints origin o asked for, in Chrome's order.
func (s *hintStore) of(o origin) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked[o]
}

// askedHints are the client hints the fields of an Accept-CH or Critical-CH
// name, in Chrome's order: each a token of a comma-separated list, its
// parameters aside, in any case of ASCII, and one Chrome knows; the rest
// passed over.
func askedHints(fields []string, policies ...behavior.Policy) []string {
	var named []string
	for _, field := range fields {
		for _, member := range strings.Split(field, ",") {
			token, _, _ := strings.Cut(member, ";")
			named = append(named, strings.Map(lowerASCII, strings.Trim(token, " \t")))
		}
	}
	var out []string
	for _, name := range policyArgument(policies).Strings("headers.client_hint_order") {
		if slices.Contains(named, name) {
			out = append(out, name)
		}
	}
	return out
}

// hintsOf are the client hints hop h of a request in a browser context
// carries: for a page's request, those the origin it goes to asked for; for a
// script's, those its page's origin asked for, to that origin alone.
func (c *Client) hintsOf(r *browserRequest, h hop) Header {
	if r.scripted() && h.to != r.from {
		return nil
	}
	return hintValues(c.session.hints.of(h.to), Header(c.profile.ClientHints))
}

// hintValues are the hints of names a profile has values for, as it says
// them, in Chrome's order: those Chrome sends unasked are the profile's
// headers, and left out.
func hintValues(names []string, hints Header) Header {
	var out Header
	for _, name := range names {
		if value := hints.Get(name); value != "" {
			out = append(out, profile.Field{Name: name, Value: value})
		}
	}
	return out
}
