# Go package `daemon`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```text
package daemon // import "github.com/Sec-CH-Lemon/tls-forge/daemon"

Package daemon speaks JSON lines on a pipe, so a program in any language can
borrow a browser's fingerprint without reimplementing one.

The protocol is one JSON object per line in, one per line out:

    in : {"id":7,"url":"https://…","headers":{"a":"b"},"order":["a"]}
    out: {"id":7,"status":200,"url":"…","body":"…","headers":{…}}

The process is long-lived and holds one configured client. The selected profile
decides whether requests use separate browser network instances or share state
across calls. Shipped profiles use request scope: redirects and retries share
one request's state, while later requests start independently.

# Why every response carries an id

The protocol is strictly one request at a time, so an id looks redundant.
It is not, and the failure it prevents is silent.

A caller that gives up on a slow request will typically kill this process and
start another. But the abandoned process can already have a complete answer on
its way up the pipe, and that answer arrives after the caller has moved on to
the next request. Without an id it is indistinguishable from the new request's
answer — and the response URL cannot stand in for one, because it is the
post-redirect URL. The result is one page filed under another page's request:
well-formed, plausible and wrong.

So the id is echoed on EVERY response, including every error path, and a caller
is expected to drop any line whose id it is not waiting for.

CONSTANTS

const (
	BodyUTF8   = "utf8"
	BodyBase64 = "base64"
)
    How a body is spelled on the wire.

const Protocol = 3
    Protocol is the version of the protocol this daemon speaks: 3 requires an
    exact engine_major on requests and init, and reports compiled identity;
    2 answers control lines. A daemon of protocol 1 predates them, and answers
    hello as a request with no url.


FUNCTIONS

func AnswerInit(out io.Writer, id uint64, err error) error
    AnswerInit writes the answer to the init line to out: none of an error,
    the daemon being ready for requests, or the error, without the password of
    the proxy or of any URL it quotes.

func Serve(in io.Reader, out io.Writer, client Client) error
    Serve reads requests until the input ends.

    It returns an error only for a broken pipe. Everything a request can
    do wrong comes back as a response with an Error field, attached to that
    request's id — a daemon that exited on a bad URL would take the session's
    cookie jar with it.

func ServeContext(ctx context.Context, in io.Reader, out io.Writer, client Client) error
    ServeContext is Serve until ctx is done.

    Once it is, no more requests are taken, the request in flight is cancelled
    and answered with why, and ServeContext returns ctx's error. The input and
    the output are the caller's, and are not closed. A read already waiting on
    the input goes on waiting, on a goroutine of its own, until the input ends,
    which is when its owner closes it: the daemon command's process ends. A
    write waiting on the output is given a deadline in the past once the answer
    to the request in flight has had answerGrace to be written, when the output
    takes one, as a net.Conn does; one that does not is its owner's to release.


TYPES

type BrowserContext struct {
	Kind           string `json:"kind"`
	Initiator      string `json:"initiator,omitempty"`
	ReferrerPolicy string `json:"referrerPolicy,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Credentials    string `json:"credentials,omitempty"`
}
    BrowserContext is a request's browser context as a line carries it:
    the library's tlsforge.BrowserContext, field for field.

type Client interface {
	Do(*tlsforge.Request) (*tlsforge.Response, error)
	Headers() tlsforge.Header
}
    Client is the part of *tlsforge.Client the daemon needs, named so tests can
    substitute one without opening a socket.

type Init struct {
	ID    uint64
	Proxy string
}
    Init is what the init line says: the first line of a daemon that takes its
    proxy on its input, read before the client that goes through it is made,
    as {"id":1,"control":"init","proxy":"http://user:pass@host:port"}. A command
    line is what ps shows every user of the machine, and the environment is
    what the process's owner can read while it runs; the input is read once,
    and gone.

func ReadInit(in io.Reader) (Init, io.Reader, error)
    ReadInit reads the init line from in, and is the input after it, where the
    requests are. A line that is no init line, or that names no proxy, is an
    error, with the line's id when it has one; so is an input that ends first.

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
	Network json.RawMessage `json:"network,omitempty"`

	// Proxy is the proxy an init line names: see ReadInit.
	Proxy string `json:"proxy,omitempty"`
}
    Request is one line of input.

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
    Response is one line of output.
```
