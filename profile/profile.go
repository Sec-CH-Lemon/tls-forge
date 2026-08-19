// Package profile describes one browser build completely enough to impersonate
// it: the ClientHello, the HTTP/2 preamble, and the headers with their order.
//
// A profile is data, not code. It serialises to JSON, so a profile measured on
// one machine can be committed, reviewed, shipped and used on another — which
// is the difference between "we support Chrome 151" and "we supported Chrome
// 151 on the day someone hand-wrote this table".
//
// The authoritative field is ClientHello: a real browser's ClientHello, captured
// off the wire. utls turns those bytes back into a live handshake, regenerating
// everything that must be fresh per connection — GREASE values, key shares, the
// ECH payload — so the result matches the browser without being a recording of
// one connection.
package profile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// Profile is a complete browser identity.
type Profile struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent,omitempty"`

	// ClientHello is a captured ClientHello record, the whole TLS fingerprint.
	// When empty, Base names a stock profile to borrow instead.
	ClientHello []byte `json:"client_hello,omitempty"`

	// Base names a profile from the tls-client catalogue, used when no captured
	// ClientHello is present. It is also what a hand-written profile builds on.
	Base string `json:"base,omitempty"`

	HTTP2   HTTP2   `json:"http2"`
	Headers []Field `json:"headers,omitempty"`

	// Google is the block this browser adds for a Google origin and shows
	// nobody else. Nil for a browser that adds no such block — every one that is
	// not Google Chrome — and for a profile captured before this was measured.
	Google *Google `json:"google_headers,omitempty"`

	// Notes is free text carried into the JSON so a committed profile can say
	// where it came from — which browser build, measured when, on what OS.
	Notes string `json:"notes,omitempty"`

	// source is the file this was read from, for a command that wants to tell
	// somebody which profile it is wearing. Unexported, so it can never reach
	// the JSON and be mistaken for part of the profile: where a file is says
	// nothing about the browser it records.
	source string
}

// Source is the file this profile was read from, or empty for one that ships
// inside the binary or came from the catalogue.
func (p *Profile) Source() string { return p.source }

// Google is the headers a browser adds when the destination is Google's, and
// where in its ordinary order they go.
//
// Only the extra headers, not the whole list they appear in. The two are the
// same list otherwise — measured, by capturing both and comparing them field by
// field — so carrying the whole thing would repeat thirteen headers to say five,
// in a file whose job is to be read by somebody deciding whether to commit it.
//
// After is what keeps that from being a reconstruction. The block's position is
// as measured as its contents: it arrived between `accept` and `sec-fetch-site`,
// so `after: accept` is the observation, and splicing it back there reproduces
// the order that was seen rather than one that seemed reasonable. An empty After
// means the block came first.
type Google struct {
	After   string  `json:"after,omitempty"`
	Headers []Field `json:"headers"`
}

// Into splices the block into a header list at the place it was measured.
//
// After is expected to name a header the list has — a capture only ever writes
// one that does, because it read it off the list it is describing. A block whose
// anchor has since been edited away goes on the end rather than nowhere: headers
// in the wrong order are visible in a capture, headers silently not sent are
// not.
func (g *Google) Into(base []Field) []Field {
	if g == nil || len(g.Headers) == 0 {
		return base
	}
	out := make([]Field, 0, len(base)+len(g.Headers))
	if g.After == "" {
		out = append(out, g.Headers...)
	}
	for _, f := range base {
		out = append(out, f)
		if f.Name == g.After {
			out = append(out, g.Headers...)
		}
	}
	if len(out) == len(base) {
		out = append(out, g.Headers...)
	}
	return out
}

// Field is one header. A slice of these rather than a map, because order is
// fingerprinted and a map has none.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTP2 is the connection preamble a client sends before its first request.
type HTTP2 struct {
	Settings          []Setting  `json:"settings"`
	ConnectionFlow    uint32     `json:"connection_flow"`
	PseudoHeaderOrder []string   `json:"pseudo_header_order"`
	Priorities        []Priority `json:"priorities,omitempty"`
	HeaderPriority    *Priority  `json:"header_priority,omitempty"`
	StreamID          uint32     `json:"stream_id,omitempty"`
}

// Setting is one HTTP/2 setting. Order matters, so this is a list.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// Priority is an HTTP/2 priority, either standalone or carried on HEADERS.
//
// Weight is the value as it appears ON THE WIRE, which is one less than the
// weight people quote: Chrome's "weight 256" is a 255 here. Storing the wire
// value keeps the round-trip through a capture exact.
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}

// ErrNoHandshake reports a profile that names neither a captured ClientHello nor
// a base profile, and so cannot produce a handshake.
var ErrNoHandshake = fmt.Errorf("profile: neither client_hello nor base is set")

// Spec builds a fresh ClientHelloSpec.
//
// Fresh on every call, deliberately. utls extensions are pointers with mutable
// state, and a spec shared between connections is a spec whose key share is
// reused — which is both a bug and a fingerprint, since no browser reuses one.
func (p *Profile) Spec() (tls.ClientHelloSpec, error) {
	if len(p.ClientHello) > 0 {
		// AllowBluntMimicry is deliberately OFF. With it, an extension utls does
		// not understand is replayed as a fixed blob — which for Chrome means the
		// ECH GREASE payload, a per-connection random value, would become a
		// constant. That is worse than not impersonating at all: every request
		// this library made would carry the same unique marker. Better to fail
		// loudly and add real support for the extension.
		fingerprinter := &tls.Fingerprinter{}
		spec, err := fingerprinter.RawClientHello(p.ClientHello)
		if err != nil {
			return tls.ClientHelloSpec{}, fmt.Errorf("profile %q: %w", p.Name, err)
		}
		return *spec, nil
	}
	if p.Base != "" {
		base, ok := profiles.MappedTLSClients[p.Base]
		if !ok {
			return tls.ClientHelloSpec{}, fmt.Errorf("profile %q: unknown base %q", p.Name, p.Base)
		}
		baseID := base.GetClientHelloId()
		return baseID.ToSpec()
	}
	return tls.ClientHelloSpec{}, fmt.Errorf("profile %q: %w", p.Name, ErrNoHandshake)
}

// ClientProfile converts to the form the transport consumes.
func (p *Profile) ClientProfile() (profiles.ClientProfile, error) {
	// A profile that only names a base IS that base. Rebuilding it from parts
	// would be a second, drifting copy of settings this library does not own.
	if p.isBareBase() {
		base, ok := profiles.MappedTLSClients[p.Base]
		if !ok {
			return profiles.ClientProfile{}, fmt.Errorf("profile %q: unknown base %q", p.Name, p.Base)
		}
		return base, nil
	}

	// Built once here so a broken profile is reported when the client is
	// created, not on the first request. The factory itself rebuilds per
	// connection.
	if _, err := p.Spec(); err != nil {
		return profiles.ClientProfile{}, err
	}

	id := tls.ClientHelloID{
		Client:      p.Name,
		Version:     "0",
		SpecFactory: p.Spec,
	}

	settings := make(map[http2.SettingID]uint32, len(p.HTTP2.Settings))
	order := make([]http2.SettingID, 0, len(p.HTTP2.Settings))
	for _, s := range p.HTTP2.Settings {
		settings[http2.SettingID(s.ID)] = s.Value
		order = append(order, http2.SettingID(s.ID))
	}

	priorities := make([]http2.Priority, 0, len(p.HTTP2.Priorities))
	for _, pr := range p.HTTP2.Priorities {
		priorities = append(priorities, http2.Priority{
			StreamID:      pr.StreamID,
			PriorityParam: pr.param(),
		})
	}

	var headerPriority *http2.PriorityParam
	if p.HTTP2.HeaderPriority != nil {
		param := p.HTTP2.HeaderPriority.param()
		headerPriority = &param
	}

	streamID := p.HTTP2.StreamID
	if streamID == 0 {
		streamID = 1
	}

	return profiles.NewClientProfile(
		id, settings, order, p.HTTP2.PseudoHeaderOrder, p.HTTP2.ConnectionFlow,
		priorities, headerPriority, streamID,
		false, nil, nil, 0, nil, false,
	), nil
}

func (p *Profile) isBareBase() bool {
	return p.Base != "" && len(p.ClientHello) == 0 && len(p.HTTP2.Settings) == 0
}

func (p Priority) param() http2.PriorityParam {
	return http2.PriorityParam{
		StreamDep: p.DependsOn,
		Exclusive: p.Exclusive,
		Weight:    p.Weight,
	}
}

// HeaderOrder is the header names in profile order, which is what the transport
// needs to reproduce the browser's ordering.
func (p *Profile) HeaderOrder() []string {
	out := make([]string, len(p.Headers))
	for i, f := range p.Headers {
		out[i] = f.Name
	}
	return out
}

// Header returns a default header's value.
func (p *Profile) Header(name string) (string, bool) {
	for _, f := range p.Headers {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

// Load reads a profile from JSON.
func Load(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile: name is required")
	}
	return &p, nil
}

// Save writes a profile as indented JSON, the form meant to be committed and
// reviewed. Indented and newline-terminated so a profile update shows up in a
// diff as the fields that changed rather than as one very long line.
func (p *Profile) Save() ([]byte, error) { return encodeJSON(p) }

func encodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
