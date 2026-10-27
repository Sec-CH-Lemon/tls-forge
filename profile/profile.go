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
	"github.com/igor-lemon/utls/behavior"
	rand "math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Sec-CH-Lemon/tls-forge/fingerprint"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/fhttp/http2/hpack"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
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
//
// Schema 2 added client_hints. A profile of schema 1 is read as strictly, and
// has none: no tls-forge that wrote 1 knew of them. Schema 3 adds explicit
// behavior policy; its browser name and user agent are metadata only.
// Schema 4 adds engine_major, independent of the browser version and schema.
const Schema = 4

// ClientHintOrder is every client hint Chrome 155 sends when a server asks
// for it with Accept-CH, in the order it sends them, as measured
// (testdata/chrome155-requests.json): the device's and the network's, some
// under two names, the user agent's, and the user's preferences. Three of the
// user agent's, sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform, go with
// every request, and are a profile's headers; a profile's ClientHints are the
// values of the rest.
var ClientHintOrder = behavior.Legacy().Strings("headers.client_hint_order")

// Profile is a complete browser identity.
type Profile struct {
	// Schema is the version of the format the profile was written in: see
	// the constant. Save writes the current one.
	Schema int `json:"schema,omitempty"`

	// EngineMajor is required for execution and independent of format/browser versions.
	EngineMajor *int `json:"engine_major"`

	// Behavior contains explicit versioned network policies, independent of Name and UserAgent.
	Behavior behavior.Policy `json:"behavior"`

	Name      string `json:"name"`
	UserAgent string `json:"user_agent,omitempty"`

	// ClientHello is a captured ClientHello record, the whole TLS fingerprint.
	// When empty, Base names a stock profile to borrow instead.
	ClientHello []byte `json:"client_hello,omitempty"`

	// Base names a profile from the tls-client catalogue, used when no captured
	// ClientHello is present. It is also what a hand-written profile builds on.
	Base string `json:"base,omitempty"`

	// PerConnection says what the browser draws afresh for every connection.
	// Without it, that is guessed from the profile's name and user agent, as
	// it was before profiles said it.
	PerConnection *PerConnection `json:"per_connection,omitempty"`

	HTTP1   *HTTP1  `json:"http1,omitempty"`
	HTTP2   HTTP2   `json:"http2"`
	Headers []Field `json:"headers,omitempty"`

	// ClientHints are the values of the client hints the browser sends when a
	// server asks for them, by name in lower case, as the browser sends them:
	// the user agent's beyond the three it always sends, and the device's, the
	// network's and the user's preferences where they were measured. A hint
	// the profile has no value for is not sent, asked for or not.
	ClientHints []Field `json:"client_hints,omitempty"`

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
	if p.EngineMajor != nil {
		out.EngineMajor = Major(*p.EngineMajor)
	}
	out.Behavior = p.Behavior.Clone()
	out.ClientHello = append([]byte(nil), p.ClientHello...)
	if p.PerConnection != nil {
		perConnection := *p.PerConnection
		perConnection.ECHPayloadLengths = slices.Clone(p.PerConnection.ECHPayloadLengths)
		out.PerConnection = &perConnection
	}
	out.Headers = append([]Field(nil), p.Headers...)
	out.ClientHints = append([]Field(nil), p.ClientHints...)
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

// PerConnection is what a browser's TLS stack draws afresh for every
// connection, said outright: FromCapture says it of the browser it captures,
// and a profile written by hand can say it of the browser it describes.
type PerConnection struct {
	// ShufflesExtensions draws the order of the extensions for every
	// connection, as Chromium has since version 110.
	ShufflesExtensions bool `json:"shuffles_extensions,omitempty"`
	// ECHPayloadLengths are the lengths the payload of the GREASE
	// encrypted_client_hello is drawn from, each as likely, before the
	// AEAD's 16-byte tag. None keeps the length the hello was captured with.
	ECHPayloadLengths []uint16 `json:"ech_payload_lengths,omitempty"`
}

// chromiumPerConnection is what Chromium draws for every connection, on every
// platform but iOS: BoringSSL's.
func chromiumPerConnection() *PerConnection {
	return &PerConnection{ShufflesExtensions: true, ECHPayloadLengths: slices.Clone(chromeECHPayloadLengths)}
}

// maxECHPayloadLength is the longest payload length that leaves room in the
// extension for the AEAD's tag.
const maxECHPayloadLength = 1<<16 - 1 - 16

// ShufflesExtensions reports whether this browser randomises the TLS extension
// order on each connection, as PerConnection says. A profile that does not say
// is guessed at by its family: Chromium browsers do; Firefox and Safari do
// not; the user agent is a fallback for custom captured profile names.
//
// Nothing on an iPhone or an iPad does, whatever it is called: every browser
// there connects through Apple's own stack, so Chrome on iOS sends Safari's
// handshake, in Safari's order.
func (p *Profile) ShufflesExtensions() bool {
	if p.PerConnection != nil {
		return p.PerConnection.ShufflesExtensions
	}
	return p.Schema < 3 && p.chromium()
}

// echPayloadLengths are what the GREASE ECH payload is drawn from, as
// PerConnection says or, when it does not, as Chromium draws it for a
// Chromium profile; nil keeps the captured length.
func (p *Profile) echPayloadLengths() []uint16 {
	if p.PerConnection != nil {
		return p.PerConnection.ECHPayloadLengths
	}
	if p.Schema < 3 && p.chromium() {
		return chromeECHPayloadLengths
	}
	return nil
}

// Chromium reports a profile of a Chromium browser: Chrome, Chromium, Edge,
// Brave, Opera and the like, on any platform but iOS, where every browser is
// Safari underneath. What tls-forge has measured of how a browser sends each
// kind of request, it measured on Chrome, and applies to these alone.
func (p *Profile) Chromium() bool { return p.RuntimeBehavior().Flag("headers.browser_context") }

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
var chromeECHPayloadLengths = func() []uint16 {
	var out []uint16
	for _, n := range behavior.Legacy().Numbers("tls.ech_payload_lengths") {
		out = append(out, uint16(n))
	}
	return out
}()

// ErrNoHandshake reports a profile that names neither a captured ClientHello nor
// a base profile, and so cannot produce a handshake.
var ErrNoHandshake = fmt.Errorf("profile: neither client_hello nor base is set")

// Spec builds a fresh ClientHelloSpec.
//
// Fresh on every call, deliberately. utls extensions are pointers with mutable
// state, and a spec shared between connections is a spec whose key share is
// reused — which is both a bug and a fingerprint, since no browser reuses one.
func (p *Profile) Spec() (tls.ClientHelloSpec, error) {
	if err := p.Validate(); err != nil {
		return tls.ClientHelloSpec{}, err
	}
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
				// uTLS's fingerprinter fills EncapsulatedKey with arbitrary
				// random bytes. A non-empty value bypasses its init's HPKE
				// X25519 key generation, unlike BoringSSL's GREASE ECH.
				// Leave it unset so uTLS generates and serializes a fresh
				// X25519 public key when it builds this connection's hello.
				extension.EncapsulatedKey = nil
				// The fingerprinter keeps the one length the capture drew,
				// and a length that never changes marks this client apart
				// from the browser, which draws one on every connection.
				if lengths := p.echPayloadLengths(); len(lengths) > 0 {
					extension.CandidatePayloadLens = slices.Clone(lengths)
				}
			case *tls.GenericExtension:
				if extension.Id != fingerprint.ExtTrustAnchors {
					return tls.ClientHelloSpec{}, fmt.Errorf(
						"profile %q: unsupported extension %d", p.Name, extension.Id)
				}
				payload, err := processTrustAnchors.payload(extension.Data, p.RuntimeBehavior().Text("tls.trust_anchor_order"))
				if err != nil {
					return tls.ClientHelloSpec{}, fmt.Errorf(
						"profile %q: malformed trust_anchors: %w", p.Name, err)
				}
				extension.Data = payload
			}
		}
		if p.RuntimeBehavior().Flag("tls.resumption") {
			*spec = withResumption(*spec)
		}
		return settingsForALPN(*spec), nil
	}
	if p.Base != "" {
		base, ok := profiles.MappedTLSClients[p.Base]
		if !ok {
			return tls.ClientHelloSpec{}, fmt.Errorf("profile %q: unknown base %q", p.Name, p.Base)
		}
		// A catalogue entry is a spec of its own or one of utls's presets,
		// which utls reads the way it does when it opens a connection.
		baseID := base.GetClientHelloId()
		spec, err := baseID.ToSpec()
		if err != nil {
			return tls.UTLSIdToSpec(baseID)
		}
		return spec, nil
	}
	return tls.ClientHelloSpec{}, fmt.Errorf("profile %q: %w", p.Name, ErrNoHandshake)
}

// extensionShuffle draws an order of n things, as rand.Shuffle does: a test
// makes it its own.
var extensionShuffle = rand.Shuffle

// shuffledSpec is the spec of a connection with the extensions that move in
// an order drawn for it (shuffleExtensions).
func (p *Profile) shuffledSpec() (tls.ClientHelloSpec, error) {
	spec, err := p.Spec()
	if err == nil {
		shuffleExtensions(spec.Extensions, extensionShuffle)
	}
	return spec, err
}

// shuffleExtensions puts the extensions that move in the order shuffle draws,
// every order as likely as any other, and leaves GREASE, padding and
// pre_shared_key where they are: as BoringSSL draws a permutation of every
// extension it knows for each connection (ssl_setup_extension_permutation),
// and writes those a hello has in it. Measured on Chrome 155: two launches of
// 200 hellos, each held to every order being as likely as any other
// (testdata/chrome155-hellos.json). The transport's own shuffle passes over a
// swap with any extension that stays, which kept every other in the place the
// capture has it about twice as often as Chrome does.
func shuffleExtensions(extensions []tls.TLSExtension, shuffle func(int, func(int, int))) {
	var moving []int
	for i, extension := range extensions {
		switch extension.(type) {
		case *tls.UtlsGREASEExtension, *tls.UtlsPaddingExtension, tls.PreSharedKeyExtension:
		default:
			moving = append(moving, i)
		}
	}
	shuffle(len(moving), func(i, j int) {
		a, b := moving[i], moving[j]
		extensions[a], extensions[b] = extensions[b], extensions[a]
	})
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

// ClientProfile converts to the form the transport consumes, the order of the
// TLS extensions drawn for every connection when the browser draws one
// (ShufflesExtensions).
func (p *Profile) ClientProfile() (profiles.ClientProfile, error) {
	return p.ClientProfileShuffled(p.ShufflesExtensions())
}

// ClientProfileShuffled is ClientProfile with the order of the extensions of
// every connection's ClientHello drawn for it when shuffle is true, every
// order of those that move as likely as any other, as Chromium draws one
// (shuffleExtensions), and the capture's when it is false. A bare base is the
// transport's own, and so is drawing its order (BareBase).
func (p *Profile) ClientProfileShuffled(shuffle bool) (profiles.ClientProfile, error) {
	if err := p.Validate(); err != nil {
		return profiles.ClientProfile{}, err
	}
	// A profile that only names a base IS that base. Rebuilding it from parts
	// would be a second, drifting copy of settings this library does not own.
	if p.BareBase() {
		// Validate resolved this exact pinned catalogue identity.
		return p.applyTransportBehavior(profiles.MappedTLSClients[p.Base]), nil
	}

	// Built once here so a broken profile is reported when the client is
	// created, not on the first request. The factory itself rebuilds per
	// connection.
	if _, err := p.Spec(); err != nil {
		return profiles.ClientProfile{}, err
	}
	factory := p.Spec
	if shuffle {
		factory = p.shuffledSpec
	}
	id := tls.ClientHelloID{
		Client:      p.Name,
		Version:     "0",
		SpecFactory: factory,
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

	pol := p.RuntimeBehavior()
	var h3Settings map[uint64]uint64
	var h3Order []uint64
	if pol.Has("h3.settings") {
		h3Settings = map[uint64]uint64{}
		for _, s := range pol.Settings("h3.settings") {
			h3Settings[s.ID] = s.Value
			h3Order = append(h3Order, s.ID)
		}
	}
	return p.applyTransportBehavior(profiles.NewClientProfile(
		id, settings, order, p.HTTP2.PseudoHeaderOrder, p.HTTP2.ConnectionFlow,
		priorities, headerPriority, streamID, false, h3Settings, h3Order, uint32(pol.Uint("h3.priority_frame_type")),
		pol.Strings("h3.pseudo_header_order"), pol.Flag("h3.grease_frames"))), nil
}

func (p *Profile) applyTransportBehavior(built profiles.ClientProfile) profiles.ClientProfile {
	pol := p.RuntimeBehavior()
	if pol.Has("h3.settings") {
		settings := map[uint64]uint64{}
		var order []uint64
		for _, s := range pol.Settings("h3.settings") {
			settings[s.ID] = s.Value
			order = append(order, s.ID)
		}
		built = built.WithHTTP3Parameters(settings, order, pol.Strings("h3.pseudo_header_order"), uint32(pol.Uint("h3.priority_frame_type")), pol.Flag("h3.grease_frames"))
	}
	built = built.WithConnectionFlowSet(!p.BareBase()).WithBehavior(pol).WithHeaderRepresentation(headerRepresentation(pol)).
		WithMaxEncoderHeaderTableSize(uint32(pol.Uint("h2.encoder_table_bytes"))).
		WithMaxHeaderFramePayload(uint32(pol.Uint("h2.header_frame_payload"))).
		WithMaxDataFramePayload(uint32(pol.Uint("h2.data_frame_payload"))).
		WithDynamicRecordSizingDisabled(pol.Flag("tls.full_size_records")).
		WithMaxMergedHeadAndBody(pol.Int("h1.merged_head_body_bytes")).
		WithWindowUpdateDelay(time.Duration(pol.Uint("h2.window_update_delay_ms")) * time.Millisecond).
		WithStrictMaxConcurrentStreams(pol.Flag("h2.strict_max_streams")).WithFalseStart(pol.Flag("tls.false_start"))
	return built
}
func headerRepresentation(pol behavior.Policy) func(hpack.HeaderField) hpack.Representation {
	if !pol.Has("h2.hpack_unindexed_prefixes") {
		return nil
	}
	prefixes, exceptions := pol.Strings("h2.hpack_unindexed_prefixes"), pol.Strings("h2.hpack_indexed_exceptions")
	return func(f hpack.HeaderField) hpack.Representation {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name, prefix) && !slices.Contains(exceptions, f.Name) {
				return hpack.Representation{WithoutIndexing: true, FirstStaticName: pol.Flag("h2.hpack_first_static_name")}
			}
		}
		return hpack.Representation{IndexTooLarge: pol.Flag("h2.hpack_index_oversized")}
	}
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

// BareBase reports a profile that only names a base of the transport's
// catalogue, and is that base: no handshake and no HTTP/2 settings of its own.
func (p *Profile) BareBase() bool {
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
func Load(data []byte) (*Profile, error) { return decodeProfile(data, true) }
func decodeProfile(data []byte, execute bool) (*Profile, error) {
	if execute {
		if err := checkMajorJSON(data); err != nil {
			return nil, err
		}
		if err := validateProfileJSON(data); err != nil {
			return nil, err
		}
	}
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
	case *written.Schema >= 1 && *written.Schema <= Schema:
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&p); err != nil {
			return nil, fmt.Errorf("profile: schema %d: %w", *written.Schema, err)
		}
		if *written.Schema == 1 && len(p.ClientHints) > 0 {
			return nil, fmt.Errorf("profile: schema 1 has no client_hints: they are schema %d's", Schema)
		}
	case *written.Schema > Schema:
		return nil, fmt.Errorf("profile: schema %d is newer than this tls-forge reads, %d: upgrade tls-forge",
			*written.Schema, Schema)
	default:
		return nil, fmt.Errorf("profile: schema %d is not one; schemas begin at 1", *written.Schema)
	}
	if execute {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	} else {
		if err := p.validateBehaviorFor(false); err != nil {
			return nil, err
		}
		if err := p.validateFields(); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

// validateFields is shared by execution and offline format inspection.
// It does not retag an archive or grant permission to execute its HTTP policy.
func (p *Profile) validateFields() error {
	if p.Name == "" {
		return fmt.Errorf("profile: name is required")
	}
	if p.PerConnection != nil {
		for _, length := range p.PerConnection.ECHPayloadLengths {
			if length == 0 || length > maxECHPayloadLength {
				return fmt.Errorf("profile %q: an ECH payload of %d bytes is not one: it is 1 to %d",
					p.Name, length, maxECHPayloadLength)
			}
		}
	}
	if !p.BareBase() {
		if err := p.validatePseudoHeaderOrder(); err != nil {
			return err
		}
	}
	if err := p.validateHTTP1(); err != nil {
		return err
	}
	if err := p.validateClientHints(); err != nil {
		return err
	}
	return nil
}

// validateClientHints refuses a hint Chrome does not send when asked, one it
// sends unasked (the profile's headers say those), one said twice, and a value
// that is no header value.
func (p *Profile) validateClientHints() error {
	seen := map[string]bool{}
	for _, hint := range p.ClientHints {
		switch {
		case !slices.Contains(p.HintOrder(), hint.Name) || slices.Contains(p.RuntimeBehavior().Strings("headers.default_client_hints"), hint.Name):
			return fmt.Errorf("profile %q: %q is no client hint a server asks for: client_hints are %s, "+
				"in lower case", p.Name, hint.Name, strings.Join(p.AskedHints(), ", "))
		case seen[hint.Name]:
			return fmt.Errorf("profile %q: client hint %s is said twice", p.Name, hint.Name)
		case hint.Value == "" || !httpguts.ValidHeaderFieldValue(hint.Value):
			return fmt.Errorf("profile %q: client hint %s has no value a header can carry: %q", p.Name,
				hint.Name, hint.Value)
		}
		seen[hint.Name] = true
	}
	return nil
}

// AskedClientHints are the client hints Chrome sends only to a server that
// asks for them, in the order it sends them: those a profile's client_hints
// may say.
func AskedClientHints() []string { return slices.Clone(defaultHints().asked) }

// DefaultHintOrder is the process-default capture helper's data snapshot.
// Active clients always use their own Profile.HintOrder, not this cache.
func DefaultHintOrder() []string { return slices.Clone(defaultHints().order) }

// DefaultUnaskedHints are the hints of DefaultHintOrder that go to every
// server unasked, from the same snapshot.
func DefaultUnaskedHints() []string { return slices.Clone(defaultHints().unasked) }

type hintDefaults struct{ order, unasked, asked []string }

var hintDefaultsOnce sync.Once
var hintDefaultsValue hintDefaults

func defaultHints() *hintDefaults {
	hintDefaultsOnce.Do(func() {
		pol := behavior.Legacy()
		if p, err := Get("chrome"); err == nil {
			pol = p.RuntimeBehavior()
		}
		hintDefaultsValue.order = pol.Strings("headers.client_hint_order")
		hintDefaultsValue.unasked = pol.Strings("headers.default_client_hints")
		for _, name := range hintDefaultsValue.order {
			if !slices.Contains(hintDefaultsValue.unasked, name) {
				hintDefaultsValue.asked = append(hintDefaultsValue.asked, name)
			}
		}
	})
	return &hintDefaultsValue
}

// Save writes a profile as indented JSON, the form meant to be committed and
// reviewed. Indented and newline-terminated so a profile update shows up in a
// diff as the fields that changed rather than as one very long line. It is
// written in the current schema, whichever it was read in.
func (p *Profile) Save() ([]byte, error) {
	current := *p
	if current.PerConnection == nil {
		current.PerConnection = &PerConnection{ShufflesExtensions: p.ShufflesExtensions(), ECHPayloadLengths: slices.Clone(p.echPayloadLengths())}
	}
	current.Behavior = p.RuntimeBehavior().Clone()
	delete(current.Behavior, "tls.ech_payload_lengths")
	if current.Behavior == nil {
		current.Behavior = behavior.Policy{}
	}
	current.Schema = Schema
	if err := current.validateBehaviorFor(false); err != nil {
		return nil, err
	}
	return encodeJSON(&current)
}

func encodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
