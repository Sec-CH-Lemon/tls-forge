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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sec-CH-Lemon/tls-forge/v2"
	"github.com/Sec-CH-Lemon/tls-forge/v2/engine"
	"github.com/Sec-CH-Lemon/tls-forge/v2/internal/redact"
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
	ID          uint64 `json:"id"`
	EngineMajor *int   `json:"engine_major"`

	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`

	// Order is the header order to send. JSON objects have no order, so a caller
	// that cares must say so here. When omitted, the profile's own order is
	// used, and headers the profile does not name go last.
	Order []string `json:"order,omitempty"`

	Body string `json:"body,omitempty"`

	// BodyEncoding says how to read Body. Absent or "utf8" means Body is the
	// bytes themselves; "base64" means it is standard base64.
	//
	// A JSON string cannot hold arbitrary bytes: encoding/json replaces every
	// byte that is not valid UTF-8 with U+FFFD, silently and without an error.
	// So a body that is not text has to travel as base64 or not at all.
	BodyEncoding string `json:"bodyEncoding,omitempty"`

	// SetCookie seeds the jar with "name=value" pairs before the request.
	SetCookie []string `json:"setCookie,omitempty"`

	// Control makes the line a question for the daemon rather than a request
	// to send: "hello" asks which protocol it speaks and what it can do. A
	// control line names no url, and is answered without a connection.
	Control string `json:"control,omitempty"`

	// Browser is the browser context a request is made in, what kind of
	// request from which page: BrowserContext, read strictly. A daemon that
	// predates the field sends the request as though it had none, so a client
	// asks first, with hello, for browser_context.
	Browser json.RawMessage `json:"browser,omitempty"`

	// Proxy is the proxy an init line names: see ReadInit.
	Proxy string `json:"proxy,omitempty"`
}

// BrowserContext is a request's browser context as a line carries it: the
// library's tlsforge.BrowserContext, field for field.
type BrowserContext struct {
	Kind           string `json:"kind"`
	Initiator      string `json:"initiator,omitempty"`
	ReferrerPolicy string `json:"referrerPolicy,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Credentials    string `json:"credentials,omitempty"`
}

// browserContextOf is the context a line carries, or nil for none: read
// strictly, so that a field the protocol does not have, or a value of the
// wrong type, is a bad request rather than a context applied in part. What
// the library refuses of the context itself, it says, and nothing is sent.
func browserContextOf(raw json.RawMessage) (*tlsforge.BrowserContext, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var said BrowserContext
	if err := decoder.Decode(&said); err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}
	return &tlsforge.BrowserContext{Kind: tlsforge.RequestKind(said.Kind), Initiator: said.Initiator,
		ReferrerPolicy: said.ReferrerPolicy, Mode: said.Mode, Credentials: said.Credentials}, nil
}

// Protocol is the version of the protocol this daemon speaks: 3 requires an
// exact engine_major on requests and init, and reports compiled identity; 2 answers
// control lines. A daemon of protocol 1 predates them, and answers hello as a
// request with no url.
const Protocol = 3

// capabilities are what this daemon can do that a client has to ask about
// before it relies on it: browser_context, a request's browser field applied.
// A client that needs one a daemon does not say finds it missing, and says so
// instead of being ignored.
var capabilities = []string{"browser_context", "engine_major"}

// Response is one line of output.
type Response struct {
	// Never omitempty: a caller has to be able to tell "id 0" from "no id at
	// all", and read the latter as "this binary is older than the code driving
	// it" rather than letting every request time out unexplained.
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	URL    string `json:"url"`
	Body   string `json:"body"`

	// BodyEncoding is absent when Body is the response text, and "base64" when
	// the response was not valid UTF-8 and could not be carried as a JSON
	// string. Absent rather than "utf8" for the common case, so a reader that
	// predates this field is unaffected by it for every text response.
	BodyEncoding string              `json:"bodyEncoding,omitempty"`
	Headers      map[string][]string `json:"headers"`
	Cookies      []string            `json:"cookies"`
	Error        string              `json:"error,omitempty"`

	// Protocol and Capabilities answer hello: the protocol the daemon speaks,
	// and what it can do that a client must ask about. Absent from the answer
	// to a request.
	EngineMajor  *int     `json:"engine_major,omitempty"`
	Version      string   `json:"version,omitempty"`
	Protocol     int      `json:"protocol,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// How a body is spelled on the wire.
const (
	BodyUTF8   = "utf8"
	BodyBase64 = "base64"
)

// decodeBody reads a request body according to its declared encoding.
func decodeBody(body, encoding string) ([]byte, error) {
	switch encoding {
	case "", BodyUTF8:
		return []byte(body), nil
	case BodyBase64:
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("body is not valid base64: %w", err)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unknown bodyEncoding %q", encoding)
	}
}

// encodeBody renders a response body, saying how when it is not text.
//
// Checked rather than always base64: a base64 body would be unreadable by eye
// and a third larger, and almost every response this carries is a page.
func encodeBody(body []byte) (text, encoding string) {
	if utf8.Valid(body) {
		return string(body), ""
	}
	return base64.StdEncoding.EncodeToString(body), BodyBase64
}

// validateResponseHeaders prevents encoding/json from silently replacing
// invalid bytes with U+FFFD. Header values cannot use bodyEncoding without
// changing their public type in every wrapper, so fail explicitly instead of
// returning a successful but corrupted response.
func validateResponseHeaders(headers map[string][]string) error {
	for name, values := range headers {
		if !utf8.ValidString(name) {
			return fmt.Errorf("response header name is not valid UTF-8")
		}
		for _, value := range values {
			if !utf8.ValidString(value) {
				return fmt.Errorf("response header %q is not valid UTF-8", name)
			}
		}
	}
	return nil
}

// Client is the part of *tlsforge.Client the daemon needs, named so tests can
// substitute one without opening a socket.
type Client interface {
	Do(*tlsforge.Request) (*tlsforge.Response, error)
	Headers() tlsforge.Header
}

// Limits on one line of input. A request larger than this is a caller bug; the
// buffer is generous because a POST body travels inline. A line is read when it
// is at most maxLineBuffer bytes, its newline included, which is what the
// Node.js and Python packages check a request against before they send it.
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
	return ServeContext(context.Background(), in, out, client)
}

// answerGrace is how long the answer to the request in flight has, once ctx is
// done, before a write waiting on the output is given up.
const answerGrace = 250 * time.Millisecond

// ServeContext is Serve until ctx is done.
//
// Once it is, no more requests are taken, the request in flight is cancelled
// and answered with why, and ServeContext returns ctx's error. The input and
// the output are the caller's, and are not closed. A read already waiting on
// the input goes on waiting, on a goroutine of its own, until the input ends,
// which is when its owner closes it: the daemon command's process ends. A
// write waiting on the output is given a deadline in the past once the answer
// to the request in flight has had answerGrace to be written, when the output
// takes one, as a net.Conn does; one that does not is its owner's to release.
func ServeContext(ctx context.Context, in io.Reader, out io.Writer, client Client) error {
	if in == nil {
		return errors.New("daemon: nil input")
	}
	if out == nil {
		return errors.New("daemon: nil output")
	}
	if client == nil {
		return errors.New("daemon: nil client")
	}

	stop := make(chan struct{})
	defer close(stop)
	go release(ctx, stop, out)

	// Read on a goroutine of its own, so that ctx is answered while a read is
	// waiting for a line that may never come.
	lines := make(chan string)
	ended := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, initialLineBuffer), maxLineBuffer)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case lines <- line:
			case <-stop:
				return
			}
		}
		ended <- scanner.Err()
	}()

	encoder := json.NewEncoder(out)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-ended:
			// A line too long to read ends the input rather than being skipped
			// to the next newline, which could be any distance away: the
			// memory it takes is the buffer's, and the time it takes is that
			// of reading the buffer full.
			switch {
			case errors.Is(err, bufio.ErrTooLong):
				return fmt.Errorf("daemon: a request line is longer than %d bytes, its newline included: %w",
					maxLineBuffer, err)
			case err != nil:
				return fmt.Errorf("daemon: reading requests: %w", err)
			}
			return nil
		case line := <-lines:
			if err := encoder.Encode(handle(ctx, line, client)); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("daemon: writing response: %w", err)
			}
		}
	}
}

// Init is what the init line says: the first line of a daemon that takes its
// proxy on its input, read before the client that goes through it is made,
// as {"id":1,"control":"init","proxy":"http://user:pass@host:port"}. A
// command line is what ps shows every user of the machine, and the
// environment is what the process's owner can read while it runs; the input
// is read once, and gone.
type Init struct {
	ID    uint64
	Proxy string
}

// ReadInit reads the init line from in, and is the input after it, where the
// requests are. A line that is no init line, or that names no proxy, is an
// error, with the line's id when it has one; so is an input that ends first.
func ReadInit(in io.Reader) (Init, io.Reader, error) {
	reader := bufio.NewReaderSize(in, initialLineBuffer)
	for {
		line, err := readLine(reader)
		if err != nil {
			return Init{}, reader, err
		}
		if line = bytes.TrimSpace(line); len(line) == 0 {
			continue
		}
		var said Request
		if err := json.Unmarshal(line, &said); err != nil {
			return Init{ID: said.ID}, reader, fmt.Errorf("bad request: %w; running engine major %d", err, engine.Major())
		}
		init := Init{ID: said.ID, Proxy: said.Proxy}
		if err := checkRequestMajor(line); err != nil {
			return init, reader, err
		}
		switch {
		case said.Control != "init" || said.URL != "":
			return init, reader, errors.New("bad request: the first line of a daemon started with --proxy-stdin " +
				`is its init line, {"id":1,"control":"init","proxy":"<url>"}, and nothing is sent before it`)
		case said.Proxy == "":
			return init, reader, errors.New("bad request: the init line names no proxy")
		}
		return init, reader, nil
	}
}

// readLine is a line of in: one longer than a request line may be is an
// error, as it is to Serve, which counts a last line without a newline as one
// with it.
func readLine(in *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := in.ReadSlice('\n')
		line = append(line, part...)
		size := len(line)
		if !bytes.HasSuffix(line, []byte("\n")) {
			size++
		}
		switch {
		case size > maxLineBuffer:
			return nil, fmt.Errorf("daemon: a request line is longer than %d bytes, its newline included: %w",
				maxLineBuffer, bufio.ErrTooLong)
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, errors.New("daemon: the input ended before the init line")
		case err != nil && !errors.Is(err, io.EOF):
			return nil, fmt.Errorf("daemon: reading the init line: %w", err)
		}
		return line, nil
	}
}

// AnswerInit writes the answer to the init line to out: none of an error, the
// daemon being ready for requests, or the error, without the password of the
// proxy or of any URL it quotes.
func AnswerInit(out io.Writer, id uint64, err error) error {
	answer := Response{ID: id}
	if err != nil {
		answer = failed(id, err)
	}
	return json.NewEncoder(out).Encode(answer)
}

// release gives a write waiting on out a deadline in the past, when out takes
// one, once ctx is done and the answer to the request in flight has had
// answerGrace to be written; until stop, which is ServeContext returning.
func release(ctx context.Context, stop <-chan struct{}, out io.Writer) {
	select {
	case <-ctx.Done():
	case <-stop:
		return
	}
	grace := time.NewTimer(answerGrace)
	defer grace.Stop()
	select {
	case <-grace.C:
	case <-stop:
		return
	}
	if writer, ok := out.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = writer.SetWriteDeadline(time.Unix(1, 0))
	}
}

// failed is the answer to a request that could not be made. What it says has
// the password of any URL in it taken out: a request's URL that would not
// parse is quoted back whole, and the answer goes to another process, which
// may log it.
func failed(id uint64, err error) Response {
	return Response{ID: id, Error: redact.Text(err.Error())}
}

func handle(ctx context.Context, line string, client Client) Response {
	var req Request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		// req.ID is usable here for the failure that actually happens: a caller
		// building this line with a JSON encoder never sends malformed JSON, but
		// it can send JSON of the wrong SHAPE, and encoding/json records the type
		// error while continuing to decode — so the id is already in place. A
		// genuine syntax error leaves it at 0, and the caller lets that request
		// time out, which is the safe way to lose one.
		return failed(req.ID, fmt.Errorf("bad request: %w; running engine major %d", err, engine.Major()))
	}
	if req.Control != "" {
		// hello is offline discovery. Other controls cannot bypass the gate.
		if req.Control != "hello" {
			if err := checkRequestMajor([]byte(line)); err != nil {
				return failed(req.ID, err)
			}
		}
		return control(req)
	}
	if err := checkRequestMajor([]byte(line)); err != nil {
		return failed(req.ID, err)
	}
	if req.URL == "" {
		return Response{ID: req.ID, Error: "bad request: no url"}
	}
	browser, err := browserContextOf(req.Browser)
	if err != nil {
		return failed(req.ID, fmt.Errorf("bad request: %w", err))
	}

	requestHeaders, err := orderedHeaders(req, client)
	if err != nil {
		return failed(req.ID, fmt.Errorf("bad request: %w", err))
	}
	cookies, err := parseCookies(req.SetCookie)
	if err != nil {
		return failed(req.ID, fmt.Errorf("bad request: %w", err))
	}

	body, err := decodeBody(req.Body, req.BodyEncoding)
	if err != nil {
		return failed(req.ID, fmt.Errorf("bad request: %w", err))
	}

	res, err := client.Do(&tlsforge.Request{
		Method:  req.Method,
		URL:     req.URL,
		Header:  requestHeaders,
		Body:    body,
		Cookies: cookies,
		Context: ctx,
		Browser: browser,
	})
	if err != nil {
		return failed(req.ID, err)
	}
	if err := validateResponseHeaders(res.Header); err != nil {
		return failed(req.ID, err)
	}

	headers := make(map[string][]string, len(res.Header))
	for name, values := range res.Header {
		headers[name] = append([]string(nil), values...)
	}
	// An empty list rather than null when the jar holds nothing for the URL,
	// as docs/protocol.md has always shown it. Null is how a failure says it
	// has nothing to report, and a reader should not have to tell an answer
	// from a failure by anything but `error`.
	held := res.Cookies
	if held == nil {
		held = []string{}
	}
	responseBody, encoding := encodeBody(res.Body)
	return Response{
		ID:           req.ID,
		Status:       res.Status,
		URL:          res.URL,
		Body:         responseBody,
		BodyEncoding: encoding,
		Headers:      headers,
		Cookies:      held,
	}
}

// control answers a control line: what the daemon is, never a connection.
func control(req Request) Response {
	if req.URL != "" {
		return Response{ID: req.ID, Error: "bad request: a control line is not a request, and has no url"}
	}
	switch req.Control {
	case "hello":
		major := engine.Major()
		return Response{ID: req.ID, Protocol: Protocol, EngineMajor: &major, Version: engine.Version(), Capabilities: append([]string(nil), capabilities...)}
	case "init":
		return Response{ID: req.ID, Error: "bad request: init is the first line of a daemon started with " +
			"--proxy-stdin, and no other"}
	default:
		return Response{ID: req.ID, Error: fmt.Sprintf("bad request: unknown control %q", req.Control)}
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

func checkRequestMajor(data []byte) error {
	major, err := engine.DeclaredMajor(data)
	if err != nil {
		return fmt.Errorf("daemon request: %w; running engine major %d", err, engine.Major())
	}
	return engine.CheckMajor("daemon request", major)
}
