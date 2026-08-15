// Package capture is the exchange format between a client that connects and
// the report describing what it sent.
//
// One shape serves both sides on purpose. The echo server answers every client
// — a real browser or this library — with the same JSON, so comparing the two
// is comparing two values of one type rather than reconciling two formats. The
// alternative, a browser-shaped struct and a client-shaped struct, is where
// "these fields look equivalent" quietly becomes "these fields are equivalent".
//
// The authoritative field is RawClientHello: the bytes as they arrived. Every
// list below is derived from it and exists to be read by a human. A comparison
// re-parses the raw bytes instead of trusting the rendering, so a bug in the
// rendering can never make two different handshakes look identical.
package capture

import (
	"encoding/json"
	"fmt"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
)

// Source labels which side produced a capture.
const (
	SourceBrowser  = "browser"
	SourceTLSFetch = "tlsforge"
)

// Capture is one client's complete self-description.
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
}

// HTTP1 is what an HTTP/1.1 client sent. No browser takes this path against
// this server — they all negotiate h2 — but a client that DOES is worth
// describing rather than hanging up on, and header order is as fingerprintable
// over HTTP/1.1 as it is over HTTP/2.
type HTTP1 struct {
	Method      string        `json:"method"`
	Path        string        `json:"path"`
	Proto       string        `json:"proto"`
	HeaderOrder []string      `json:"header_order"`
	Headers     []HeaderField `json:"headers"`
}

// Value is a wire code together with its human name, so the JSON is readable
// without a registry lookup and still exact.
type Value struct {
	Code uint16 `json:"code"`
	Name string `json:"name"`
}

// TLS is the readable rendering of a ClientHello.
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

// HTTP2 is the readable rendering of the connection preamble and first request.
type HTTP2 struct {
	Akamai            string        `json:"akamai_fingerprint"`
	Settings          []Setting     `json:"settings"`
	WindowUpdate      uint32        `json:"window_update"`
	Priorities        []Priority    `json:"priorities,omitempty"`
	HeaderPriority    *Priority     `json:"header_priority,omitempty"`
	PseudoHeaderOrder []string      `json:"pseudo_header_order"`
	HeaderOrder       []string      `json:"header_order"`
	Headers           []HeaderField `json:"headers"`
}

// Setting is one HTTP/2 setting, named.
type Setting struct {
	ID    uint16 `json:"id"`
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}

// Priority is a standalone PRIORITY frame.
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}

// HeaderField is one header in wire order.
type HeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Brand is one entry of navigator.userAgentData.brands.
type Brand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

// Navigator is what the browser says about itself in JavaScript.
//
// It is collected because the HTTP layer has to agree with it: a request whose
// user-agent claims Chrome 151 while sec-ch-ua-platform-version claims a macOS
// that shipped with Chrome 120 is a contradiction no real browser produces. The
// high-entropy hints are stored verbatim rather than re-derived for the same
// reason — inventing one would be inventing a machine.
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

// FromClientHello renders a parsed hello for humans.
func FromClientHello(hello *fingerprint.ClientHello) TLS {
	serverName, _ := hello.ServerName()
	_, resumed := hello.Extension(fingerprint.ExtPreSharedKey)
	return TLS{
		JA3:                 hello.JA3(),
		JA3Hash:             hello.JA3Hash(),
		JA4:                 hello.JA4(),
		JA4Raw:              hello.JA4Raw(),
		LegacyVersion:       value(hello.LegacyVersion, fingerprint.VersionName),
		ServerName:          serverName,
		CipherSuites:        values(hello.CipherSuites, fingerprint.CipherName),
		Extensions:          values(hello.ExtensionTypes(), fingerprint.ExtensionName),
		SupportedVersions:   values(hello.SupportedVersions(), fingerprint.VersionName),
		SupportedGroups:     values(hello.SupportedGroups(), fingerprint.GroupName),
		SignatureAlgorithms: values(hello.SignatureAlgorithms(), fingerprint.SignatureName),
		KeyShareGroups:      values(hello.KeyShareGroups(), fingerprint.GroupName),
		CertCompression:     values(hello.CertCompressionAlgorithms(), certCompressionName),
		ECPointFormats:      hello.ECPointFormats(),
		PSKKeyExchangeModes: hello.PSKKeyExchangeModes(),
		ALPN:                hello.ALPN(),
		ApplicationSettings: hello.ApplicationSettings(),
		Resumed:             resumed,
	}
}

// FromHTTP2 renders observed HTTP/2 traffic for humans.
func FromHTTP2(h *fingerprint.HTTP2) *HTTP2 {
	if h == nil {
		return nil
	}
	out := &HTTP2{
		Akamai:            h.Akamai(),
		WindowUpdate:      h.WindowUpdate,
		PseudoHeaderOrder: h.PseudoHeaderOrder(),
		HeaderOrder:       h.HeaderOrder(),
		Settings:          make([]Setting, len(h.Settings)),
		Headers:           make([]HeaderField, len(h.Headers)),
	}
	for i, s := range h.Settings {
		out.Settings[i] = Setting{ID: s.ID, Name: fingerprint.SettingName(s.ID), Value: s.Value}
	}
	for _, p := range h.Priorities {
		out.Priorities = append(out.Priorities, Priority{
			StreamID: p.StreamID, Exclusive: p.Exclusive, DependsOn: p.DependsOn, Weight: p.Weight,
		})
	}
	if p := h.HeaderPriority; p != nil {
		out.HeaderPriority = &Priority{
			StreamID: p.StreamID, Exclusive: p.Exclusive, DependsOn: p.DependsOn, Weight: p.Weight,
		}
	}
	for i, f := range h.Headers {
		out.Headers[i] = HeaderField{Name: f.Name, Value: f.Value}
	}
	return out
}

// Hello re-parses the authoritative bytes.
//
// Comparison goes through here rather than through the rendered lists so that a
// mistake in the rendering cannot make two different handshakes compare equal.
func (c *Capture) Hello() (*fingerprint.ClientHello, error) {
	if len(c.RawClientHello) == 0 {
		return nil, fmt.Errorf("capture: no ClientHello recorded")
	}
	return fingerprint.ParseClientHello(c.RawClientHello)
}

// Fingerprint converts the rendered HTTP/2 view back into the comparable form.
func (h *HTTP2) Fingerprint() *fingerprint.HTTP2 {
	if h == nil {
		return nil
	}
	out := &fingerprint.HTTP2{
		WindowUpdate: h.WindowUpdate,
		Settings:     make([]fingerprint.Setting, len(h.Settings)),
		Headers:      make([]fingerprint.HeaderField, len(h.Headers)),
	}
	for i, s := range h.Settings {
		out.Settings[i] = fingerprint.Setting{ID: s.ID, Value: s.Value}
	}
	for _, p := range h.Priorities {
		out.Priorities = append(out.Priorities, fingerprint.Priority{
			StreamID: p.StreamID, Exclusive: p.Exclusive, DependsOn: p.DependsOn, Weight: p.Weight,
		})
	}
	if p := h.HeaderPriority; p != nil {
		out.HeaderPriority = &fingerprint.Priority{
			StreamID: p.StreamID, Exclusive: p.Exclusive, DependsOn: p.DependsOn, Weight: p.Weight,
		}
	}
	for i, f := range h.Headers {
		out.Headers[i] = fingerprint.HeaderField{Name: f.Name, Value: f.Value}
	}
	return out
}

// UserAgent returns the user-agent the request carried, which is the one that
// has to agree with the TLS handshake.
func (c *Capture) UserAgent() string {
	if c.HTTP2 != nil {
		for _, h := range c.HTTP2.Headers {
			if h.Name == "user-agent" {
				return h.Value
			}
		}
	}
	if c.Navigator != nil {
		return c.Navigator.UserAgent
	}
	return ""
}

func value(v uint16, name func(uint16) string) Value {
	return Value{Code: v, Name: name(v)}
}

func values(vs []uint16, name func(uint16) string) []Value {
	out := make([]Value, len(vs))
	for i, v := range vs {
		out[i] = value(v, name)
	}
	return out
}

// Certificate compression has its own tiny registry, not worth a table in the
// fingerprint package.
func certCompressionName(v uint16) string {
	switch v {
	case 1:
		return "zlib"
	case 2:
		return "brotli"
	case 3:
		return "zstd"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
