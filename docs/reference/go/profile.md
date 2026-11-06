# Go package `profile`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/profile"
```

Package profile reads and validates JSON for a selected browser build's network behaviour: TLS, HTTP/1.1, HTTP/2, supported HTTP/3 choices and request policy.

A profile is data, not code. Its captured fields and explicit policy can be committed, reviewed and used on another machine with the exact engine major for which it was validated. Historical captures do not automatically establish current browser equivalence on a different platform or path.

Captured ClientHello bytes are one input to a live handshake. The engine regenerates per-connection keys and other dynamic fields according to the selected profile rather than replaying a captured connection.

## Constants

### Schema { .tf-symbol }

```go linenums="0"
const Schema = 4
```

Schema is the version of the profile format this tls-forge writes, and the newest it reads.

A profile that says its schema is read strictly: a field the format does not have is an error, so that a name spelt wrong is found when the profile is read, not on the wire. One with a newer schema is refused rather than read in part. One that says none was written before the format had a version, and is read as it always was: what it holds that the format does not is passed over. Saving writes the schema, so a profile read that way is strict from then on.

Schema 2 added client\_hints. A profile of schema 1 is read as strictly, and has none: no tls-forge that wrote 1 knew of them. Schema 3 adds explicit behavior policy; its browser name and user agent are metadata only. Schema 4 adds engine\_major, independent of the browser version and schema.

## Variables

### ClientHintOrder { .tf-symbol }

```go linenums="0"
var ClientHintOrder = behavior.Legacy().Strings("headers.client_hint_order")
```

ClientHintOrder is every client hint Chrome 155 sends when a server asks for it with Accept-CH, in the order it sends them, as measured (testdata/chrome155-requests.json): the device's and the network's, some under two names, the user agent's, and the user's preferences. Three of the user agent's, sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform, go with every request, and are a profile's headers; a profile's ClientHints are the values of the rest.

### Default { .tf-symbol }

```go linenums="0"
var Default = NewRegistry()
```

Default is the registry the package-level functions use.

### ErrNoHandshake { .tf-symbol }

```go linenums="0"
var ErrNoHandshake = fmt.Errorf("profile: neither client_hello, tls_spec nor base is set")
```

ErrNoHandshake reports a profile that names neither a captured ClientHello nor a base profile, and so cannot produce a handshake.

## Functions

### AskedClientHints() { .tf-symbol }

```go linenums="0"
func AskedClientHints() []string
```

AskedClientHints are the client hints Chrome sends only to a server that asks for them, in the order it sends them: those a profile's client\_hints may say.

### DefaultDir() { .tf-symbol }

```go linenums="0"
func DefaultDir() string
```

DefaultDir is where profiles measured on this machine are kept.

Under the user's config directory rather than beside the binary, because a profile is this machine's measurement of this machine's browser: it does not belong to an install that a package manager may replace, and it should survive one.

TLSFORGE\_PROFILES moves it, which is how a run in a container or a test says where to look without touching a real one.

### DefaultHintOrder() { .tf-symbol }

```go linenums="0"
func DefaultHintOrder() []string
```

DefaultHintOrder is the process-default capture helper's data snapshot. Active clients always use their own Profile.HintOrder, not this cache.

### DefaultUnaskedHints() { .tf-symbol }

```go linenums="0"
func DefaultUnaskedHints() []string
```

DefaultUnaskedHints are the hints of DefaultHintOrder that go to every server unasked, from the same snapshot.

### FilePath() { .tf-symbol }

```go linenums="0"
func FilePath(name, platform string) (string, error)
```

FilePath is the directory layout shared by capture and registry lookup. Both components are identifiers; neither can supply a path or traversal.

### HostPlatform() { .tf-symbol }

```go linenums="0"
func HostPlatform() string
```

HostPlatform is this machine, spelled the way a profile file is named.

### LegacyBehavior() { .tf-symbol }

```go linenums="0"
func LegacyBehavior() behavior.Policy
```

LegacyBehavior is for migration and standalone compatibility helpers only.

### Major() { .tf-symbol }

```go linenums="0"
func Major(n int) *int
```

Major declares compatibility explicitly when constructing a profile in Go.

### Names() { .tf-symbol }

```go linenums="0"
func Names() []string
```

Names lists the default registry's profiles.

### Register() { .tf-symbol }

```go linenums="0"
func Register(p *Profile) error
```

Register adds a profile to the default registry.

### Ships() { .tf-symbol }

```go linenums="0"
func Ships(name string) bool
```

Ships reports a profile tls-forge ships by the name it is filed under, chrome\_155\_macos: one kept under that name in the directory of profiles answers for it from then on, the directory being read first (Get).

### Split() { .tf-symbol }

```go linenums="0"
func Split(name string) (version, platform string)
```

Split separates a name into the version and the platform it names, if it names one. Only a platform this project knows counts: "chrome\_151" is a version whose last word happens to be a number, not a platform called 151. The phones' are among them, for a browser measured on one rather than here.

### ValidName() { .tf-symbol }

```go linenums="0"
func ValidName(name string) bool
```

ValidName reports an identifier safe for a profile file, never a path.

## Types

### CaptureProvenance { .tf-symbol }

```go linenums="0"
type CaptureProvenance struct {
	Schema           int                    `json:"provenance_schema"`
	ProfileSHA256    string                 `json:"profile_sha256"`
	CaptureSHA256    string                 `json:"capture_canonical_sha256"`
	BasisName        string                 `json:"basis_name"`
	BasisSHA256      string                 `json:"basis_sha256"`
	Browser          *capture.Navigator     `json:"browser,omitempty"`
	BrowserMode      string                 `json:"browser_mode"`
	Fields           map[string]FieldOrigin `json:"fields"`
	DrawObservations *Drawn                 `json:"draw_observations,omitempty"`
	Acceptance       string                 `json:"acceptance"`
}
```

CaptureProvenance is separate from the runnable browser profile. Its hashes bind the final profile, the full policy basis and the original capture. Capturing a field does not establish its invariance or browser acceptance.

#### ProvenanceForCapture() { .tf-member }

```go linenums="0"
func ProvenanceForCapture(candidate, basis *Profile, c *capture.Capture, mode string) (*CaptureProvenance, error)
```

ProvenanceForCapture binds a completed candidate after any explicit caller edits. It does not select policy, mutate inputs or mark inherited data measured.

### Drawn { .tf-symbol }

```go linenums="0"
type Drawn struct {
	// Hellos is how many it was measured from.
	Hellos int
	// Order says the order of the extensions moved from one hello to
	// another, those both carry compared.
	Order bool
	// ECH are the lengths of the GREASE ECH payloads seen on the wire, each
	// once, ascending; none without one.
	ECH []int
	// Sometimes are the extensions some of them carried and others did not,
	// ascending: what a profile cannot draw.
	Sometimes []uint16
}
```

Drawn is what a browser drew anew for each connection, measured from the hellos of a capture: the measured one and those of the other connections its page opened (echo.WithManual).

#### DrawnOf() { .tf-member }

```go linenums="0"
func DrawnOf(c *capture.Capture) (*Drawn, error)
```

DrawnOf measures what the browser of a capture drew for each connection, or nil for a capture with too few hellos to tell. GREASE, padding and pre\_shared\_key are set aside: what is drawn for each, the length of the hello and a ticket decide.

### Field { .tf-symbol }

```go linenums="0"
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
```

Field is one header. A slice of these rather than a map, because order is fingerprinted and a map has none.

### FieldOrigin { .tf-symbol }

```go linenums="0"
type FieldOrigin struct {
	Class  string `json:"class"`
	Source string `json:"source"`
}
```

FieldOrigin describes provenance, not executable policy or a browser verdict.

### Group { .tf-symbol }

```go linenums="0"
type Group struct {
	// Name is what to ask for to get this machine's platform.
	Name     string
	Variants []Variant
	// Local says this machine has something under this name, which is then the
	// copy that answers.
	Local bool
}
```

Group is one measured profile and the platforms it was measured on.

A version measured on three platforms is one profile with three spellings rather than three profiles: the handshake is the same on all of them, and only the user-agent and the platform hint differ.

### HTTP1 { .tf-symbol }

```go linenums="0"
type HTTP1 struct {
	HeaderOrder []string `json:"header_order"`
	Headers     []Field  `json:"headers,omitempty"`
}
```

HTTP1 is the part of a request fingerprint HTTP/2 cannot describe. HeaderOrder preserves wire spelling as well as order. Headers contains protocol-only values, or values that differ from the shared Headers block.

### HTTP2 { .tf-symbol }

```go linenums="0"
type HTTP2 struct {
	Settings          []Setting  `json:"settings"`
	ConnectionFlow    uint32     `json:"connection_flow"`
	PseudoHeaderOrder []string   `json:"pseudo_header_order"`
	Priorities        []Priority `json:"priorities,omitempty"`
	HeaderPriority    *Priority  `json:"header_priority,omitempty"`
	StreamID          uint32     `json:"stream_id,omitempty"`
}
```

HTTP2 is the connection preamble a client sends before its first request.

### NetworkHintsPolicy { .tf-symbol }

```go linenums="0"
type NetworkHintsPolicy struct {
	Mode   string                 `json:"mode"`
	Policy *networkquality.Policy `json:"policy,omitempty"`
}
```

NetworkHintsPolicy makes literal network persona data distinct from an actual estimator. Estimated mode has no captured production hint values; its policy describes selection, measurement, generation and lifecycle mechanisms.

#### NetworkHintsPolicy.UnmarshalJSON() { .tf-member }

```go linenums="0"
func (p *NetworkHintsPolicy) UnmarshalJSON(raw []byte) error
```

UnmarshalJSON rejects missing, duplicate, unknown, case-folded or null choices.

### PerConnection { .tf-symbol }

```go linenums="0"
type PerConnection struct {
	// ShufflesExtensions draws the order of the extensions for every
	// connection, as Chromium has since version 110.
	ShufflesExtensions bool `json:"shuffles_extensions,omitempty"`
	// ECHPayloadLengths are the lengths the payload of the GREASE
	// encrypted_client_hello is drawn from, each as likely, before the
	// AEAD's 16-byte tag. None keeps the length the hello was captured with.
	ECHPayloadLengths []uint16 `json:"ech_payload_lengths,omitempty"`
}
```

PerConnection is what a browser's TLS stack draws afresh for every connection, said outright: FromCapture says it of the browser it captures, and a profile written by hand can say it of the browser it describes.

### Priority { .tf-symbol }

```go linenums="0"
type Priority struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}
```

Priority is an HTTP/2 priority, either standalone or carried on HEADERS.

Weight is the value as it appears ON THE WIRE, which is one less than the weight people quote: Chrome's "weight 256" is a 255 here. Storing the wire value keeps the round-trip through a capture exact.

### Profile { .tf-symbol }

```go linenums="0"
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

	// TLSSpec describes a handshake without captured bytes. It is exclusive
	// with ClientHello and Base, and always rebuilds live connection state.
	TLSSpec     *TLSSpec     `json:"tls_spec,omitempty"`
	QUICTLSSpec *QUICTLSSpec `json:"quic_tls_spec,omitempty"`

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

	// NetworkHints explicitly selects literal persona or a data-owned estimator.
	NetworkHints *NetworkHintsPolicy `json:"network_hints,omitempty"`

	// Notes is free text carried into the JSON so a committed profile can say
	// where it came from — which browser build, measured when, on what OS.
	Notes string `json:"notes,omitempty"`

	// Has unexported fields.
}
```

Profile is a complete browser identity.

#### CaptureBasis() { .tf-member }

```go linenums="0"
func CaptureBasis(family, platform string) (*Profile, error)
```

CaptureBasis returns the newest shipped full profile for a measured family and platform. Local aliases and Go catalogue presets are not implicit bases. Browser identity selects explicit data here, never runtime engine behavior.

#### FromCapture() { .tf-member }

```go linenums="0"
func FromCapture(name string, c *capture.Capture, basis ...*Profile) (*Profile, error)
```

FromCapture turns a browser measurement into a reusable profile.

Exactly one explicit, executable policy basis is required. Only observed fields replace it; unmeasured generation, protocol and lifecycle policies remain inherited data. Names, User-Agent and brands never select policy here. The variadic signature keeps old callers source-compatible, but omission is an error rather than an implicit legacy/browser preset.

#### Get() { .tf-member }

```go linenums="0"
func Get(name string) (*Profile, error)
```

Get resolves a name against the default registry.

#### Inspect() { .tf-member }

```go linenums="0"
func Inspect(data []byte) (*Profile, error)
```

Inspect decodes an archived profile for offline inspection. It does not grant permission to execute, nor add or change engine\_major. Execution uses Load/New.

#### Load() { .tf-member }

```go linenums="0"
func Load(data []byte) (*Profile, error)
```

Load reads a profile from JSON, as its schema says: see Schema.

#### Profile.AskedHints() { .tf-member }

```go linenums="0"
func (p *Profile) AskedHints() []string
```

AskedHints are the hints of HintOrder that go only to a server that asks for them: all but the profile's headers.default\_client\_hints.

#### Profile.BareBase() { .tf-member }

```go linenums="0"
func (p *Profile) BareBase() bool
```

BareBase reports a profile that only names a base of the transport's catalogue, and is that base: no handshake and no HTTP/2 settings of its own.

#### Profile.Catalogue() { .tf-member }

```go linenums="0"
func (p *Profile) Catalogue() bool
```

Catalogue reports that this object was read from the embedded export/import catalogue. It describes provenance, never selects transport behavior. File Load does not invent that origin; Clone preserves it.

#### Profile.Chromium() { .tf-member }

```go linenums="0"
func (p *Profile) Chromium() bool
```

Chromium reports a profile of a Chromium browser: Chrome, Chromium, Edge, Brave, Opera and the like, on any platform but iOS, where every browser is Safari underneath. What tls-forge has measured of how a browser sends each kind of request, it measured on Chrome, and applies to these alone.

#### Profile.ClientProfile() { .tf-member }

```go linenums="0"
func (p *Profile) ClientProfile() (profiles.ClientProfile, error)
```

ClientProfile converts to the form the transport consumes, the order of the TLS extensions drawn for every connection when the browser draws one (ShufflesExtensions).

#### Profile.ClientProfileShuffled() { .tf-member }

```go linenums="0"
func (p *Profile) ClientProfileShuffled(shuffle bool) (profiles.ClientProfile, error)
```

ClientProfileShuffled is ClientProfile with the order of the extensions of every connection's ClientHello drawn for it when shuffle is true, every order of those that move as likely as any other, as Chromium draws one (shuffleExtensions), and the declared order when false. A bare base resolves the same materialized JSON descriptor as an ordinary catalogue lookup.

#### Profile.Clone() { .tf-member }

```go linenums="0"
func (p *Profile) Clone() *Profile
```

Clone returns an independent copy of the profile.

#### Profile.Header() { .tf-member }

```go linenums="0"
func (p *Profile) Header(name string) (string, bool)
```

Header returns a default header's value.

#### Profile.HeaderOrder() { .tf-member }

```go linenums="0"
func (p *Profile) HeaderOrder() []string
```

HeaderOrder is the header names in profile order, which is what the transport needs to reproduce the browser's ordering.

#### Profile.HintOrder() { .tf-member }

```go linenums="0"
func (p *Profile) HintOrder() []string
```

HintOrder is the order the profile sends its client hints in, as its behavior's headers.client\_hint\_order says.

#### Profile.Migrate() { .tf-member }

```go linenums="0"
func (p *Profile) Migrate(name string) (*Profile, error)
```

Migrate explicitly creates a separately identified current-engine candidate. It preserves the source and capture provenance. The caller must perform the relevant browser/wire acceptance; this operation is not an equivalence claim.

#### Profile.RuntimeBehavior() { .tf-member }

```go linenums="0"
func (p *Profile) RuntimeBehavior() behavior.Policy
```

RuntimeBehavior is the explicit data consumed by all network layers. Schema 0-2 compatibility is materialized on load/save, never for schema 3.

#### Profile.Save() { .tf-member }

```go linenums="0"
func (p *Profile) Save() ([]byte, error)
```

Save writes a profile as indented JSON, the form meant to be committed and reviewed. Indented and newline-terminated so a profile update shows up in a diff as the fields that changed rather than as one very long line. It is written in the current schema, whichever it was read in.

#### Profile.ShufflesExtensions() { .tf-member }

```go linenums="0"
func (p *Profile) ShufflesExtensions() bool
```

ShufflesExtensions reports whether this browser randomises the TLS extension order on each connection, as PerConnection says. A profile that does not say is guessed at by its family: Chromium browsers do; Firefox and Safari do not; the user agent is a fallback for custom captured profile names.

Nothing on an iPhone or an iPad does, whatever it is called: every browser there connects through Apple's own stack, so Chrome on iOS sends Safari's handshake, in Safari's order.

#### Profile.Source() { .tf-member }

```go linenums="0"
func (p *Profile) Source() string
```

Source is the file this profile was read from, or empty for one that ships inside the binary or came from the catalogue.

#### Profile.Spec() { .tf-member }

```go linenums="0"
func (p *Profile) Spec() (tls.ClientHelloSpec, error)
```

Spec builds a fresh ClientHelloSpec.

Fresh on every call, deliberately. utls extensions are pointers with mutable state, and a spec shared between connections is a spec whose key share is reused — which is both a bug and a fingerprint, since no browser reuses one.

#### Profile.Validate() { .tf-member }

```go linenums="0"
func (p *Profile) Validate() error
```

Validate accepts an executable identity before any request-related I/O. Inspect and Save preserve representable archives without this permission. Engine compatibility remains an independent, mandatory first gate.

#### Profile.ValidateEngine() { .tf-member }

```go linenums="0"
func (p *Profile) ValidateEngine() error
```

ValidateEngine checks the actual compiled execution contract, not Schema or Name.

### QUICTLSSpec { .tf-symbol }

```go linenums="0"
type QUICTLSSpec struct {
	Hello                  *TLSSpec `json:"hello"`
	CipherOrder            string   `json:"cipher_order"`
	CipherSuitesWithoutAES []uint16 `json:"cipher_suites_without_aes"`
}
```

QUICTLSSpec independently describes QUIC TLS. CipherSuites in Hello is the fixed vector or the hardware-AES branch; neither branch is a browser constant.

#### QUICTLSSpec.UnmarshalJSON() { .tf-member }

```go linenums="0"
func (q *QUICTLSSpec) UnmarshalJSON(data []byte) error
```

UnmarshalJSON requires an exact, complete declarative QUIC TLS descriptor.

### Registry { .tf-symbol }

```go linenums="0"
type Registry struct {
	// Has unexported fields.
}
```

Registry resolves a profile name.

Four sources, in order: profiles registered at runtime, profiles kept in this machine's own directory, profiles measured and committed here, and the tls-client catalogue. The order matters: someone who captures their own Chrome and keeps it under "chrome\_151" should get theirs, not the one that shipped, because theirs is the browser a server will be comparing against.

#### NewRegistry() { .tf-member }

```go linenums="0"
func NewRegistry() *Registry
```

NewRegistry returns a registry over the built-in sources and this machine's own profile directory.

#### Registry.Dir() { .tf-member }

```go linenums="0"
func (r *Registry) Dir() string
```

Dir is where this registry looks for profiles kept on this machine.

#### Registry.Get() { .tf-member }

```go linenums="0"
func (r *Registry) Get(name string) (*Profile, error)
```

Get resolves a name to a profile.

#### Registry.HasHandshake() { .tf-member }

```go linenums="0"
func (r *Registry) HasHandshake(name string) bool
```

HasHandshake reports whether a name resolves to a profile built from a real captured ClientHello rather than to a catalogue entry. It is what lets a caller tell "this is my browser" from "this is close to some browser".

#### Registry.KeptHere() { .tf-member }

```go linenums="0"
func (r *Registry) KeptHere() []string
```

KeptHere lists the profiles in this machine's own directory, which are the ones that win over anything shipped.

#### Registry.Measured() { .tf-member }

```go linenums="0"
func (r *Registry) Measured() []Group
```

Measured lists the profiles taken from a real browser, grouped by version.

Both sources at once, not one instead of the other: a machine that has measured Chrome 151 on its own platform still resolves the shipped profile for the others, and a listing that showed only the local one would be saying less than is true.

#### Registry.Names() { .tf-member }

```go linenums="0"
func (r *Registry) Names() []string
```

Names lists every profile that can be resolved, measured ones first.

#### Registry.Register() { .tf-member }

```go linenums="0"
func (r *Registry) Register(p *Profile) error
```

Register adds or replaces a profile.

#### Registry.SetDir() { .tf-member }

```go linenums="0"
func (r *Registry) SetDir(dir string)
```

SetDir points the registry at another directory.

### Resumption { .tf-symbol }

```go linenums="0"
type Resumption struct {
	// Measured says the capture has a resumed hello.
	Measured bool
	// Added are the extensions the resumed hello carries and the cold one
	// does not, pre_shared_key aside; Missing those it lacks. Ascending.
	Added, Missing []uint16
	// NotLast says pre_shared_key was not its last extension.
	NotLast bool
	// Identities is how many tickets it offered.
	Identities int
}
```

Resumption is how the browser of a capture resumed a session, against the hello it sent cold: tls-forge resumes as Chrome does, with the cold hello and pre\_shared\_key last, one ticket offered (withResumption).

#### ResumptionOf() { .tf-member }

```go linenums="0"
func ResumptionOf(c *capture.Capture) (Resumption, error)
```

ResumptionOf is how the browser of a capture resumed a session, against its cold hello; not Measured for a capture with no resumed hello.

#### Resumption.AsTLSForge() { .tf-member }

```go linenums="0"
func (r Resumption) AsTLSForge() bool
```

AsTLSForge says the browser resumed as tls-forge resumes.

### Setting { .tf-symbol }

```go linenums="0"
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}
```

Setting is one HTTP/2 setting. Order matters, so this is a list.

### TLSExtension { .tf-symbol }

```go linenums="0"
type TLSExtension struct {
	Type       string          `json:"type"`
	Parameters json.RawMessage `json:"parameters"`
}
```

TLSExtension selects a supported protocol primitive and its data. Parameters are strictly typed by that primitive, including for programmatic profiles.

### TLSSpec { .tf-symbol }

```go linenums="0"
type TLSSpec struct {
	MinVersion         uint16         `json:"min_version"`
	MaxVersion         uint16         `json:"max_version"`
	CipherSuites       []uint16       `json:"cipher_suites"`
	CompressionMethods []uint8        `json:"compression_methods"`
	SessionID          string         `json:"session_id"`
	GREASE             string         `json:"grease"`
	ExtensionOrder     string         `json:"extension_order"`
	Extensions         []TLSExtension `json:"extensions"`
}
```

TLSSpec is declarative input, not a recorded handshake. Generated and session values have named sources; a profile cannot supply keys, randoms or binders.

#### TLSSpec.UnmarshalJSON() { .tf-member }

```go linenums="0"
func (s *TLSSpec) UnmarshalJSON(data []byte) error
```

UnmarshalJSON requires the complete, unambiguous declarative representation.

### Variant { .tf-symbol }

```go linenums="0"
type Variant struct {
	Platform string
	// Local says this one came from this machine's directory, which is the copy
	// that will be used.
	Local bool
}
```

Variant is one platform a version was measured on.
