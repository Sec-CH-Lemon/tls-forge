# Go package `capture`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/capture"
```

Package capture is the exchange format between a client that connects and the report describing what it sent.

One shape serves both sides on purpose. The echo server answers every client — a real browser or this library — with the same JSON, so comparing the two is comparing two values of one type rather than reconciling two formats. The alternative, a browser-shaped struct and a client-shaped struct, is where "these fields look equivalent" quietly becomes "these fields are equivalent".

The authoritative field is RawClientHello: the bytes as they arrived. Every list below is derived from it and exists to be read by a human. A comparison re-parses the raw bytes instead of trusting the rendering, so a bug in the rendering can never make two different handshakes look identical.

## Constants

### SourceBrowser, SourceTLSFetch { .tf-symbol }

```go linenums="0"
const (
	SourceBrowser  = "browser"
	SourceTLSFetch = "tlsforge"
)
```

Source labels which side produced a capture.

## Types

### Brand { .tf-symbol }

```go linenums="0"
type Brand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}
```

Brand is one entry of navigator.userAgentData.brands.

### Capture { .tf-symbol }

```go linenums="0"
type Capture struct {
	Source     string `json:"source,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Negotiated string `json:"alpn_negotiated,omitempty"`

	// RawClientHello is the ClientHello exactly as it arrived, record layer
	// included. Everything in TLS below is derived from it.
	RawClientHello []byte `json:"raw_client_hello"`

	TLS       TLS        `json:"tls"`
	HTTP2     *HTTP2     `json:"http2,omitempty"`
	HTTP1     *HTTP1     `json:"http1,omitempty"`
	Navigator *Navigator `json:"navigator,omitempty"`

	// Connections are the ClientHellos of the other connections the page
	// opened after the navigation, one each, as they arrived, oldest first:
	// what a browser draws anew for every connection shows across them.
	// ResumedClientHello is the hello of one that resumed a session another
	// was given. A browser a person opens gives them (echo.WithManual).
	Connections        [][]byte `json:"connections,omitempty"`
	ResumedClientHello []byte   `json:"resumed_client_hello,omitempty"`

	// ClientHints are the client hints the browser sent with its page's
	// report, the page having asked for every one: what a server that asks
	// is sent, names in lower case, in the order Chrome sends them. None for
	// a browser that sent none, and none from a server before they were kept.
	ClientHints []HeaderField `json:"client_hints,omitempty"`
}
```

Capture is one client's complete self-description.

#### Capture.Hello() { .tf-member }

```go linenums="0"
func (c *Capture) Hello() (*fingerprint.ClientHello, error)
```

Hello re-parses the authoritative bytes.

Comparison goes through here rather than through the rendered lists so that a mistake in the rendering cannot make two different handshakes compare equal.

#### Capture.UserAgent() { .tf-member }

```go linenums="0"
func (c *Capture) UserAgent() string
```

UserAgent returns the user-agent the request carried, which is the one that has to agree with the TLS handshake.

### HTTP1 { .tf-symbol }

```go linenums="0"
type HTTP1 struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Proto  string `json:"proto"`
	// HeaderOrder stays lower-case so an HTTP/1.1 set can still be compared
	// directly with HTTP/2, where HPACK requires lower-case names. HeaderNames
	// is the same sequence as it appeared on the HTTP/1.1 wire.
	HeaderOrder []string      `json:"header_order"`
	HeaderNames []string      `json:"header_names,omitempty"`
	Headers     []HeaderField `json:"headers"`
	// Layout is how the request was written where a server reads it alike:
	// the target's form first, then each line that ended in LF alone and
	// each field with other than one space after its colon or spaces after
	// its value. A browser's is its target's form alone. None in a capture
	// made before it was recorded.
	Layout []string `json:"layout,omitempty"`
}
```

HTTP1 is what an HTTP/1.1 client sent.

#### HTTP1.Fingerprint() { .tf-member }

```go linenums="0"
func (h *HTTP1) Fingerprint() *fingerprint.HTTP1
```

Fingerprint converts the rendered HTTP/1.1 view into its comparable form.

### HTTP2 { .tf-symbol }

```go linenums="0"
type HTTP2 struct {
	Akamai            string        `json:"akamai_fingerprint"`
	Settings          []Setting     `json:"settings"`
	WindowUpdate      uint32        `json:"window_update"`
	Priorities        []Priority    `json:"priorities,omitempty"`
	HeaderPriority    *Priority     `json:"header_priority,omitempty"`
	PseudoHeaderOrder []string      `json:"pseudo_header_order"`
	HeaderOrder       []string      `json:"header_order"`
	Headers           []HeaderField `json:"headers"`

	// RawFrames is what the client sent from the end of its preface to the
	// end of its first request's header block, as it went: the frames and the
	// HPACK a comparison reads, as RawClientHello is for the handshake. Absent
	// from a capture made before it was kept, whose frames are then not
	// checked.
	RawFrames []byte `json:"raw_frames,omitempty"`
}
```

HTTP2 is the readable rendering of the connection preamble and first request.

#### FromHTTP2() { .tf-member }

```go linenums="0"
func FromHTTP2(h *fingerprint.HTTP2) *HTTP2
```

FromHTTP2 renders observed HTTP/2 traffic for humans.

#### HTTP2.Fingerprint() { .tf-member }

```go linenums="0"
func (h *HTTP2) Fingerprint() *fingerprint.HTTP2
```

Fingerprint converts the rendered HTTP/2 view back into the comparable form.

### HeaderField { .tf-symbol }

```go linenums="0"
type HeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
```

HeaderField is one header in wire order.

### Navigator { .tf-symbol }

```go linenums="0"
type Navigator struct {
	UserAgent           string          `json:"user_agent"`
	Languages           []string        `json:"languages,omitempty"`
	Platform            string          `json:"platform,omitempty"`
	Mobile              bool            `json:"mobile"`
	Brands              []Brand         `json:"brands,omitempty"`
	FullVersionList     []Brand         `json:"full_version_list,omitempty"`
	Architecture        string          `json:"architecture,omitempty"`
	Bitness             string          `json:"bitness,omitempty"`
	Model               string          `json:"model,omitempty"`
	PlatformVersion     string          `json:"platform_version,omitempty"`
	UAFullVersion       string          `json:"ua_full_version,omitempty"`
	WOW64               bool            `json:"wow64,omitempty"`
	FormFactors         []string        `json:"form_factors,omitempty"`
	DeviceMemory        float64         `json:"device_memory,omitempty"`
	HardwareConcurrency int             `json:"hardware_concurrency,omitempty"`
	Extra               json.RawMessage `json:"extra,omitempty"`
}
```

Navigator is what the browser says about itself in JavaScript.

It is collected because the HTTP layer has to agree with it: a request whose user-agent claims Chrome 151 while sec-ch-ua-platform-version claims a macOS that shipped with Chrome 120 is a contradiction no real browser produces. The high-entropy hints are stored verbatim rather than re-derived for the same reason — inventing one would be inventing a machine.

### Priority { .tf-symbol }

```go linenums="0"
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}
```

Priority is a standalone PRIORITY frame.

### Setting { .tf-symbol }

```go linenums="0"
type Setting struct {
	ID    uint16 `json:"id"`
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}
```

Setting is one HTTP/2 setting, named.

### TLS { .tf-symbol }

```go linenums="0"
type TLS struct {
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
	JA4     string `json:"ja4"`
	JA4Raw  string `json:"ja4_r"`

	LegacyVersion       Value    `json:"legacy_version"`
	ServerName          string   `json:"server_name,omitempty"`
	CipherSuites        []Value  `json:"cipher_suites"`
	Extensions          []Value  `json:"extensions"`
	SupportedVersions   []Value  `json:"supported_versions,omitempty"`
	SupportedGroups     []Value  `json:"supported_groups,omitempty"`
	SignatureAlgorithms []Value  `json:"signature_algorithms,omitempty"`
	KeyShareGroups      []Value  `json:"key_share_groups,omitempty"`
	CertCompression     []Value  `json:"compress_certificate,omitempty"`
	ECPointFormats      []uint8  `json:"ec_point_formats,omitempty"`
	PSKKeyExchangeModes []uint8  `json:"psk_key_exchange_modes,omitempty"`
	ALPN                []string `json:"alpn,omitempty"`
	ApplicationSettings []string `json:"application_settings,omitempty"`

	// Resumed reports a pre_shared_key extension, which changes the extension
	// count and therefore the JA4. A resumed hello and a cold one from the SAME
	// browser have different JA4s; comparing across that line reports a
	// difference that is not one.
	Resumed bool `json:"session_resumed"`
}
```

TLS is the readable rendering of a ClientHello.

#### FromClientHello() { .tf-member }

```go linenums="0"
func FromClientHello(hello *fingerprint.ClientHello) TLS
```

FromClientHello renders a parsed hello for humans.

### Value { .tf-symbol }

```go linenums="0"
type Value struct {
	Code uint16 `json:"code"`
	Name string `json:"name"`
}
```

Value is a wire code together with its human name, so the JSON is readable without a registry lookup and still exact.
