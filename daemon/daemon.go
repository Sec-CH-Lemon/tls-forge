// Package daemon speaks JSON lines on a pipe, so a program in any language can
// borrow a browser's fingerprint without reimplementing one.
//
// The protocol is one JSON object per line in, one per line out:
//
//	in : {"id":7,"url":"https://…","headers":{"a":"b"},"order":["a"]}
//	out: {"id":7,"status":200,"url":"…","body":"…","headers":{…}}
//
// The process is long-lived and holds one client, which means one TLS
// fingerprint, one cookie jar and one exit IP for its whole life. That is not a
// simplification — it is the point. A fresh handshake and an empty jar for every
// request is itself a signal, and no browser produces it.
//
// # Why every response carries an id
//
// The protocol is strictly one request at a time, so an id looks redundant. It
// is not, and the failure it prevents is silent.
//
// A caller that gives up on a slow request will typically kill this process and
// start another. But the abandoned process can already have a complete answer
// on its way up the pipe, and that answer arrives after the caller has moved on
// to the next request. Without an id it is indistinguishable from the new
// request's answer — and the response URL cannot stand in for one, because it is
// the post-redirect URL. The result is one page filed under another page's
// request: well-formed, plausible and wrong.
//
// So the id is echoed on EVERY response, including every error path, and a
// caller is expected to drop any line whose id it is not waiting for.
package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge"
)

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Request is one line of input.
type Request struct {
	// ID is caller-assigned and echoed on the response. See the package comment.
	ID uint64 `json:"id"`

	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`

	// Order is the header order to send. JSON objects have no order, so a caller
	// that cares must say so here. When omitted, the profile's own order is
	// used, and headers the profile does not name go last.
	Order []string `json:"order,omitempty"`

	Body string `json:"body,omitempty"`

	// SetCookie seeds the jar with "name=value" pairs before the request.
	SetCookie []string `json:"setCookie,omitempty"`
}

// Response is one line of output.
type Response struct {
	// Never omitempty: a caller has to be able to tell "id 0" from "no id at
	// all", and read the latter as "this binary is older than the code driving
	// it" rather than letting every request time out unexplained.
	ID      uint64              `json:"id"`
	Status  int                 `json:"status"`
	URL     string              `json:"url"`
	Body    string              `json:"body"`
	Headers map[string][]string `json:"headers"`
	Cookies []string            `json:"cookies"`
	Error   string              `json:"error,omitempty"`
}

// Client is the part of *tlsforge.Client the daemon needs, named so tests can
// substitute one without opening a socket.
type Client interface {
	Do(*tlsforge.Request) (*tlsforge.Response, error)
	Headers() tlsforge.Header
}

// Limits on one line of input. A request larger than this is a caller bug; the
// buffer is generous because a POST body travels inline.
const (
	initialLineBuffer = 64 * 1024
	maxLineBuffer     = 16 * 1024 * 1024
)

// Serve reads requests until the input ends.
//
// It returns an error only for a broken pipe. Everything a request can do wrong
// comes back as a response with an Error field, attached to that request's id —
// a daemon that exited on a bad URL would take the session's cookie jar with it.
func Serve(in io.Reader, out io.Writer, client Client) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, initialLineBuffer), maxLineBuffer)
	encoder := json.NewEncoder(out)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := encoder.Encode(handle(line, client)); err != nil {
			return fmt.Errorf("daemon: writing response: %w", err)
		}
	}
	return scanner.Err()
}

func handle(line string, client Client) Response {
	var req Request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		// req.ID is usable here for the failure that actually happens: a caller
		// building this line with a JSON encoder never sends malformed JSON, but
		// it can send JSON of the wrong SHAPE, and encoding/json records the type
		// error while continuing to decode — so the id is already in place. A
		// genuine syntax error leaves it at 0, and the caller lets that request
		// time out, which is the safe way to lose one.
		return Response{ID: req.ID, Error: "bad request: " + err.Error()}
	}
	if req.URL == "" {
		return Response{ID: req.ID, Error: "bad request: no url"}
	}

	requestHeaders, err := orderedHeaders(req, client)
	if err != nil {
		return Response{ID: req.ID, Error: "bad request: " + err.Error()}
	}
	cookies, err := parseCookies(req.SetCookie)
	if err != nil {
		return Response{ID: req.ID, Error: "bad request: " + err.Error()}
	}

	res, err := client.Do(&tlsforge.Request{
		Method:  req.Method,
		URL:     req.URL,
		Header:  requestHeaders,
		Body:    []byte(req.Body),
		Cookies: cookies,
	})
	if err != nil {
		return Response{ID: req.ID, Error: err.Error()}
	}

	headers := make(map[string][]string, len(res.Header))
	for name, values := range res.Header {
		headers[name] = append([]string(nil), values...)
	}
	return Response{
		ID:      req.ID,
		Status:  res.Status,
		URL:     res.URL,
		Body:    string(res.Body),
		Headers: headers,
		Cookies: res.Cookies,
	}
}

// orderedHeaders turns the request's map back into an ordered list.
//
// With an explicit order, that order wins and anything not named in it follows
// in a stable, sorted position — stable because a Go map iterates randomly, and
// a header set that reordered itself between two otherwise identical requests
// would be a fingerprint of its own.
func orderedHeaders(req Request, client Client) (tlsforge.Header, error) {
	if len(req.Headers) == 0 {
		return nil, nil
	}

	lower := make(map[string]string, len(req.Headers))
	for name, value := range req.Headers {
		lowerName := strings.ToLower(name)
		if _, exists := lower[lowerName]; exists {
			return nil, fmt.Errorf("header %q is repeated with different casing", lowerName)
		}
		lower[lowerName] = value
	}

	out := make(tlsforge.Header, 0, len(lower))
	take := func(name string) {
		name = strings.ToLower(name)
		if value, ok := lower[name]; ok {
			out.Set(name, value)
			delete(lower, name)
		}
	}

	for _, name := range req.Order {
		take(name)
	}
	// Without an explicit order, fall back to the profile's — which is the
	// browser's — so a caller who just wants "Chrome's order" gets it by saying
	// nothing.
	if len(req.Order) == 0 {
		for _, name := range client.Headers().Names() {
			take(name)
		}
	}
	for _, name := range sortedKeys(lower) {
		out.Set(name, lower[name])
	}
	return out, nil
}

func parseCookies(raw []string) ([]tlsforge.Cookie, error) {
	var out []tlsforge.Cookie
	for _, entry := range raw {
		name, value, found := strings.Cut(entry, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !found || name == "" {
			return nil, fmt.Errorf("cookie: expected name=value, got %q", entry)
		}
		out = append(out, tlsforge.Cookie{Name: name, Value: value})
	}
	return out, nil
}
