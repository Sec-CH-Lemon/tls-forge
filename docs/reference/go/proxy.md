# Go package `proxy`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/proxy"
```

Package proxy is an HTTP proxy that re-originates every request with a browser's TLS fingerprint.

It intercepts rather than tunnels, and that is the whole point. A proxy that answers CONNECT by piping bytes leaves the client's own TLS to reach the destination, so the destination sees the client's handshake — Go's, Python's, curl's — and the fingerprint has not changed at all. To replace it, the proxy has to terminate TLS itself, which means presenting a certificate for the requested host, which means signing with an authority the client trusts.

That is the cost, and it is not hidden: `tls-forge proxy` writes its authority to a file and prints where. Trusting it is a real decision, because anything holding that key can impersonate every site to anyone who trusts it.

## Constants

### DefaultMaxRequestBody { .tf-symbol }

```go linenums="0"
const DefaultMaxRequestBody int64 = 16 << 20
```

DefaultMaxRequestBody is large enough for ordinary browser traffic while preventing an exposed proxy from buffering an unbounded upload in memory.

## Types

### CA { .tf-symbol }

```go linenums="0"
type CA struct {
	// Has unexported fields.
}
```

CA is a certificate authority and the leaf certificates it has minted.

#### LoadOrCreateCA() { .tf-member }

```go linenums="0"
func LoadOrCreateCA(certFile, keyFile string) (*CA, error)
```

LoadOrCreateCA reads the authority from certFile and keyFile, generating a new one only when both are missing. An incomplete pair is an error: silently replacing the surviving half would invalidate a certificate somebody may already trust.

#### CA.CertPEM() { .tf-member }

```go linenums="0"
func (c *CA) CertPEM() []byte
```

CertPEM is the authority certificate, which is what a client has to trust.

### Client { .tf-symbol }

```go linenums="0"
type Client interface {
	Do(*tlsforge.Request) (*tlsforge.Response, error)
	Headers() tlsforge.Header
}
```

Client is the part of \*tlsforge.Client the proxy needs, named so tests can answer without opening a socket.

### Options { .tf-symbol }

```go linenums="0"
type Options struct {
	// Addr to listen on. Defaults to 127.0.0.1:0.
	Addr string

	// CA signs the per-host certificates. Required.
	CA *CA

	// Client performs the outbound requests. Required.
	Client Client

	// MaxRequestBody bounds the body buffered before it is re-issued. Zero uses
	// DefaultMaxRequestBody.
	MaxRequestBody int64

	// OnError receives per-connection failures. A proxy that printed them to
	// stdout would corrupt nothing, but a caller that wants them quiet should
	// not have to redirect a stream. What each says has the password of any
	// URL in it taken out, as it is made to be printed; what it wraps is
	// underneath, for errors.Is and errors.As.
	OnError func(error)
}
```

Options configure a Server.

### Server { .tf-symbol }

```go linenums="0"
type Server struct {
	// Has unexported fields.
}
```

Server is a running proxy.

#### Start() { .tf-member }

```go linenums="0"
func Start(opts Options) (*Server, error)
```

Start binds the listener and begins accepting. The caller must Close it.

#### Server.Addr() { .tf-member }

```go linenums="0"
func (s *Server) Addr() string
```

Addr is the address actually bound.

#### Server.Close() { .tf-member }

```go linenums="0"
func (s *Server) Close() error
```

Close stops accepting, ends open connections and waits for their handlers.
