# Go package `echo`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/echo"
```

Package echo is a local HTTPS server that tells every client what it just sent.

It is the measuring instrument this library is verified with. Point a real browser at it and it reports that browser's ClientHello, HTTP/2 preamble and header order; point this library at it and it reports the same fields for the same connection. Comparing the two answers is the whole verification story, and because both sides are measured by one instrument on one machine, a difference is a real difference rather than a difference in how two services happened to render their output.

Running locally also removes the third-party dependency that makes this kind of check rot: no rate limit, no outage, no silent change of output format, no sending anybody's traffic to a stranger's host to find out what it looks like.

## Types

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Option { .tf-symbol }

<div class="tf-ref__docs" markdown>

Option configures a Server.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Option func(*options)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### WithAddr() { .tf-member }

<div class="tf-ref__docs" markdown>

WithAddr sets the listen address. The default binds an ephemeral port on loopback, which is what makes it safe to run several at once — in tests, for instance: at 127.0.0.1 and at \[::1\] on that port, both of which localhost names (listenLoopback).

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func WithAddr(addr string) Option
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### WithHost() { .tf-member }

<div class="tf-ref__docs" markdown>

WithHost sets the hostname used in URL and in the certificate. "localhost" rather than an IP keeps the browser's SNI populated, which JA4 records as `d` instead of `i`.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func WithHost(host string) Option
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### WithManual() { .tf-member }

<div class="tf-ref__docs" markdown>

WithManual serves a browser a person opens the page in, rather than one launched with its certificate check turned off: Firefox, Safari, a phone's.

Such a browser has to be talked into this run's certificate first, and the visit it makes after saying yes is not one to measure: it may be a reload, and it is not one a person makes by opening an address. So its first visit only shows it what to do next, and the visit measured is a later one, typed or pasted into a new tab, on a connection of its own: every answer that is not part of a measurement ends its connection, so that nothing the browser keeps open can carry the visit that counts. A visit that is a reload, or comes from a link, or on a connection that has carried another, is turned away with the reason, and the browser can try again.

It is measured over HTTP/2 alone: a browser nobody launched cannot be sent to the HTTP/1.1 listener without the trip showing in what it sends.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func WithManual(enabled bool) Option
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### WithSessionTickets() { .tf-member }

<div class="tf-ref__docs" markdown>

WithSessionTickets re-enables TLS session resumption, which is off by default.

Off by default because resumption changes the fingerprint being measured: a resumed connection carries pre\_shared\_key, which is one more extension, which is a different JA4. Real Chrome 151 sends t13d1516h2\_…\_806a8c22fdea on a cold connection and t13d1517h2\_…\_a87ad97598a9 on a resumed one. Both are honest, but only the cold one is what a server sees on first contact, and a capture that silently alternated between them would produce a profile that matched the browser about half the time.

Turn it on to study resumption itself.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func WithSessionTickets(enabled bool) Option
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Server { .tf-symbol }

<div class="tf-ref__docs" markdown>

Server is the listener. The zero value is not usable; call Start.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Server struct {
	// Has unexported fields.
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Start() { .tf-member }

<div class="tf-ref__docs" markdown>

Start binds the listener and begins accepting. The caller must Close it.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func Start(opts ...Option) (*Server, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.Addr() { .tf-member }

<div class="tf-ref__docs" markdown>

Addr is the address actually bound, with the resolved port.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) Addr() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.Await() { .tf-member }

<div class="tf-ref__docs" markdown>

Await blocks until a browser has completed a capture: it navigated to the capture page, and the page reported back what JavaScript can see.

The session returned is the one that carried the DOCUMENT NAVIGATION, which is not necessarily the one that delivered the report. Chrome keeps spare connections open and will happily send the page's fetch() down a different one — and that connection resumes the first one's session, so it carries an extra pre\_shared\_key extension and a different JA4, and its headers are a fetch's rather than a navigation's.

Measured, before this was separated out: the capture came back with `content-length, sec-ch-ua-platform, user-agent, content-type, origin…` — the header order of an XHR — presented as the browser's navigation fingerprint. It is wrong in a way that looks entirely plausible, which is why the navigation is tracked explicitly rather than inferred from whichever connection spoke last.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) Await(ctx context.Context) (*Session, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.CaptureURL() { .tf-member }

<div class="tf-ref__docs" markdown>

CaptureURL is the protocol-restricted endpoint the capture page navigates through after the main listener has recorded HTTP/2.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) CaptureURL() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.Certificate() { .tf-member }

<div class="tf-ref__docs" markdown>

Certificate exposes the generated certificate so a client can pin it instead of disabling verification wholesale.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) Certificate() []byte
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.Close() { .tf-member }

<div class="tf-ref__docs" markdown>

Close stops accepting, ends open connections and waits for their handlers.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) Close() error
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.Panics() { .tf-member }

<div class="tf-ref__docs" markdown>

Panics is a diagnostic: what has been recovered from connection handlers, the latest of them, which should be nothing. A handler that panics costs its connection and not the process, and is kept here rather than swallowed, so that a program or a test running the server can ask afterwards whether one did. Each call hands back a copy.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) Panics() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.Sessions() { .tf-member }

<div class="tf-ref__docs" markdown>

Sessions returns the latest connections observed, 128 of them, oldest first: a server left running keeps what is recent, not everything.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) Sessions() []*Session
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Server.URL() { .tf-member }

<div class="tf-ref__docs" markdown>

URL is the base URL clients should use.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Server) URL() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Session { .tf-symbol }

<div class="tf-ref__docs" markdown>

Session is everything one connection revealed about its client.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Session struct {
	// Has unexported fields.
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Session.Capture() { .tf-member }

<div class="tf-ref__docs" markdown>

Capture renders the session in the exchange format.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Session) Capture(source string) *capture.Capture
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Session.Navigator() { .tf-member }

<div class="tf-ref__docs" markdown>

Navigator reports the JavaScript-side data, if the capture page delivered it.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Session) Navigator() *capture.Navigator
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Session.Remote() { .tf-member }

<div class="tf-ref__docs" markdown>

Remote is the client's address, which is the only way to tell two otherwise identical local sessions apart.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s *Session) Remote() string
```

</div>

</div>
