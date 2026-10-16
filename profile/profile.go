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
// ECH payload, and for Chromium the length of that payload — so the result
// matches the browser without being a recording of one connection.
package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"golang.org/x/net/http/httpguts"
)

// Schema is the version of the profile format this tls-forge writes, and the
// newest it reads.
//
// A profile that says its schema is read strictly: a field the format does not
// have is an error, so that a name spelt wrong is found when the profile is
// read, not on the wire. One with a newer schema is refused rather than read
// in part. One that says none was written before the format had a version,
// and is read as it always was: what it holds that the format does not is
// passed over. Saving writes the schema, so a profile read that way is strict
// from then on.
const Schema = 1

// Profile is a complete browser identity.
type Profile struct {
	// Schema is the version of the format the profile was written in: see
	// the constant. Save writes the current one.
	Schema int `json:"schema,omitempty"`

	Name      string `json:"name"`
	UserAgent string `json:"user_agent,omitempty"`

	// ClientHello is a captured ClientHello record, the whole TLS fingerprint.
	// When empty, Base names a stock profile to borrow instead.
	ClientHello []byte `json:"client_hello,omitempty"`

	// Base names a profile from the tls-client catalogue, used when no captured
	// ClientHello is present. It is also what a hand-written profile builds on.
	Base string `json:"base,omitempty"`

	HTTP1   *HTTP1  `json:"http1,omitempty"`
	HTTP2   HTTP2   `json:"http2"`
	Headers []Field `json:"headers,omitempty"`

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

// Clone returns an independent copy of the profile.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	out := *p
	out.ClientHello = append([]byte(nil), p.ClientHello...)
	out.Headers = append([]Field(nil), p.Headers...)
	out.HTTP2.Settings = append([]Setting(nil), p.HTTP2.Settings...)
	out.HTTP2.PseudoHeaderOrder = append([]string(nil), p.HTTP2.PseudoHeaderOrder...)
	out.HTTP2.Priorities = append([]Priority(nil), p.HTTP2.Priorities...)
	if p.HTTP2.HeaderPriority != nil {
		priority := *p.HTTP2.HeaderPriority
		out.HTTP2.HeaderPriority = &priority
	}
	if p.HTTP1 != nil {
		http1 := *p.HTTP1
		http1.HeaderOrder = append([]string(nil), p.HTTP1.HeaderOrder...)
		http1.Headers = append([]Field(nil), p.HTTP1.Headers...)
		out.HTTP1 = &http1
	}
	return &out
}

// ShufflesExtensions reports whether this browser family randomises the TLS
// extension order on each connection. Chromium browsers do; Firefox and Safari
// do not. The user agent is a fallback for custom captured profile names.
//
// Nothing on an iPhone or an iPad does, whatever it is called: every browser
// there connects through Apple's own stack, so Chrome on iOS sends Safari's
// handshake, in Safari's order.
func (p *Profile) ShufflesExtensions() bool { return p.chromium() }

// chromium reports a profile of a Chromium browser with Chromium's own TLS
// stack, BoringSSL: by its name, its base or, for a custom captured profile,
// its user agent. Not one on an iPhone or an iPad, whatever it is called.
func (p *Profile) chromium() bool {
	identity := strings.ToLower(p.Name + " " + p.Base + " " + p.UserAgent)
	if _, platform := Split(p.Name); platform == "ios" {
		return false
	}
	for _, marker := range []string{"iphone", "ipad", "ipod"} {
		if strings.Contains(identity, marker) {
			return false
		}
	}
	for _, marker := range []string{"chrome", "chromium", "brave", "opera", " opr/"} {
		if strings.Contains(identity, marker) {
			return true
		}
	}
	return false
}

// Field is one header. A slice of these rather than a map, because order is
// fingerprinted and a map has none.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTP1 is the part of a request fingerprint HTTP/2 cannot describe.
// HeaderOrder preserves wire spelling as well as order. Headers contains
// protocol-only values, or values that differ from the shared Headers block.
type HTTP1 struct {
	HeaderOrder []string `json:"header_order"`
	Headers     []Field  `json:"headers,omitempty"`
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

// chromeECHPayloadLengths are the lengths a Chromium browser draws the payload
// of its GREASE encrypted_client_hello from, afresh for every connection and
// each as likely, before the AEAD's 16-byte tag: BoringSSL's guess at the size
// of an inner hello, 32 times 4 to 7 (ssl_setup_ech_grease). Chrome 155 was
// measured sending all four, as often as one another, over 301 connections:
// testdata/chrome155-ech.json.
var chromeECHPayloadLengths = []uint16{128, 160, 192, 224}

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
		// Let the fingerprinter expose unknown extensions, then admit only the
		// exact forms which are safe to reproduce as fixed bytes. Blindly allowing
		// them would freeze values such as an unrecognised GREASE payload into a
		// stable per-client marker.
		fingerprinter := &tls.Fingerprinter{AllowBluntMimicry: true}
		spec, err := fingerprinter.RawClientHello(p.ClientHello)
		if err != nil {
			return tls.ClientHelloSpec{}, fmt.Errorf("profile %q: %w", p.Name, err)
		}
		for _, extension := range spec.Extensions {
			switch extension := extension.(type) {
			case *tls.GREASEEncryptedClientHelloExtension:
				// The fingerprinter keeps the one length the capture drew,
				// and a length that never changes marks this client apart
				// from the browser, which draws one on every connection.
				if p.chromium() {
					extension.CandidatePayloadLens = slices.Clone(chromeECHPayloadLengths)
				}
			case *tls.GenericExtension:
				if extension.Id != fingerprint.ExtTrustAnchors {
					return tls.ClientHelloSpec{}, fmt.Errorf(
						"profile %q: unsupported extension %d", p.Name, extension.Id)
				}
				payload, err := processTrustAnchors.payload(extension.Data)
				if err != nil {
					return tls.ClientHelloSpec{}, fmt.Errorf(
						"profile %q: malformed trust_anchors: %w", p.Name, err)
				}
				extension.Data = payload
			}
		}
		return withResumption(*spec), nil
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

// withResumption gives a spec that offers psk_key_exchange_modes the
// pre_shared_key it resumes a session with, as its last extension: where a
// browser puts it, after the GREASE extension Chrome ends its list with, and
// where its shuffle does not move it. No capture has one, a first connection
// being what is captured, and utls leaves it out of every hello with no session
// to resume, so a first connection is still the capture and the next one to a
// site that issued a ticket is the browser coming back. A spec that has one
// already is left as it is.
func withResumption(spec tls.ClientHelloSpec) tls.ClientHelloSpec {
	offers := false
	for _, extension := range spec.Extensions {
		switch extension.(type) {
		case *tls.PSKKeyExchangeModesExtension:
			offers = true
		case tls.PreSharedKeyExtension:
			return spec
		}
	}
	if offers {
		spec.Extensions = append(spec.Extensions, &tls.UtlsPreSharedKeyExtension{})
	}
	return spec
}

// ClientProfile converts to the form the transport consumes.
func (p *Profile) ClientProfile() (profiles.ClientProfile, error) {
	if err := p.validateHTTP1(); err != nil {
		return profiles.ClientProfile{}, err
	}
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
	if err := p.validatePseudoHeaderOrder(); err != nil {
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

func (p *Profile) validatePseudoHeaderOrder() error {
	want := map[string]bool{
		":method": true, ":authority": true, ":scheme": true, ":path": true,
	}
	if len(p.HTTP2.PseudoHeaderOrder) != len(want) {
		return fmt.Errorf("profile %q: pseudo_header_order must contain :method, :authority, :scheme and :path exactly once", p.Name)
	}
	seen := make(map[string]bool, len(want))
	for _, name := range p.HTTP2.PseudoHeaderOrder {
		if !want[name] || seen[name] {
			return fmt.Errorf("profile %q: invalid pseudo_header_order %v", p.Name, p.HTTP2.PseudoHeaderOrder)
		}
		seen[name] = true
	}
	return nil
}

func (p *Profile) validateHTTP1() error {
	if p.HTTP1 == nil {
		return nil
	}
	if len(p.HTTP1.HeaderOrder) == 0 {
		return fmt.Errorf("profile %q: http1.header_order must not be empty", p.Name)
	}
	seen := make(map[string]bool, len(p.HTTP1.HeaderOrder))
	for _, wireName := range p.HTTP1.HeaderOrder {
		name := strings.ToLower(strings.TrimSpace(wireName))
		if !httpguts.ValidHeaderFieldName(wireName) || seen[name] {
			return fmt.Errorf("profile %q: invalid http1.header_order %v", p.Name, p.HTTP1.HeaderOrder)
		}
		seen[name] = true
	}
	if !strings.EqualFold(p.HTTP1.HeaderOrder[0], "host") {
		return fmt.Errorf("profile %q: http1.header_order must put Host first", p.Name)
	}
	for _, field := range p.HTTP1.Headers {
		name := strings.ToLower(strings.TrimSpace(field.Name))
		if !httpguts.ValidHeaderFieldName(field.Name) || name == "host" || !seen[name] {
			return fmt.Errorf("profile %q: invalid http1 header %q", p.Name, field.Name)
		}
	}
	return nil
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

// Load reads a profile from JSON, as its schema says: see Schema.
func Load(data []byte) (*Profile, error) {
	var written struct {
		Schema *int `json:"schema"`
	}
	if err := json.Unmarshal(data, &written); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	var p Profile
	switch {
	case written.Schema == nil:
		// Written before the format had a version.
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("profile: %w", err)
		}
	case *written.Schema == Schema:
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&p); err != nil {
			return nil, fmt.Errorf("profile: schema %d: %w", Schema, err)
		}
	case *written.Schema > Schema:
		return nil, fmt.Errorf("profile: schema %d is newer than this tls-forge reads, %d: upgrade tls-forge",
			*written.Schema, Schema)
	default:
		return nil, fmt.Errorf("profile: schema %d is not one; schemas begin at 1", *written.Schema)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile: name is required")
	}
	if !p.isBareBase() {
		if err := p.validatePseudoHeaderOrder(); err != nil {
			return nil, err
		}
	}
	if err := p.validateHTTP1(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Save writes a profile as indented JSON, the form meant to be committed and
// reviewed. Indented and newline-terminated so a profile update shows up in a
// diff as the fields that changed rather than as one very long line. It is
// written in the current schema, whichever it was read in.
func (p *Profile) Save() ([]byte, error) {
	current := *p
	current.Schema = Schema
	return encodeJSON(&current)
}

func encodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
