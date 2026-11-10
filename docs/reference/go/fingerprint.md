# Go package `fingerprint`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/fingerprint"
```

Package fingerprint turns the bytes a TLS client actually put on the wire into the hashes a fingerprinting service would compute from them.

It exists so that "does our handshake match the browser's?" can be answered locally, from the raw ClientHello, instead of by asking a third-party service and trusting its answer. That matters for three reasons: the tests can be hermetic, the comparison keeps working when the service is down or changes its output, and a mismatch can be reported as a structural diff — this extension, that signature algorithm — rather than as two hashes that differ for reasons nobody can see.

## Constants

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### ExtServerName, ExtStatusRequest, ExtSupportedGroups, … { .tf-symbol }

<div class="tf-ref__docs" markdown>

Extension numbers this package reads by name. The full registry is large and mostly irrelevant here; these are the ones that feed a fingerprint.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
const (
	ExtServerName           uint16 = 0
	ExtStatusRequest        uint16 = 5
	ExtSupportedGroups      uint16 = 10
	ExtECPointFormats       uint16 = 11
	ExtSignatureAlgorithms  uint16 = 13
	ExtALPN                 uint16 = 16
	ExtSCT                  uint16 = 18
	ExtPadding              uint16 = 21
	ExtExtendedMasterSecret uint16 = 23
	ExtCompressCertificate  uint16 = 27
	ExtSessionTicket        uint16 = 35
	ExtPreSharedKey         uint16 = 41
	ExtSupportedVersions    uint16 = 43
	ExtPSKKeyExchangeModes  uint16 = 45
	ExtKeyShare             uint16 = 51
	ExtTrustAnchors         uint16 = 51764
	ExtEncryptedClientHello uint16 = 65037
	ExtRenegotiationInfo    uint16 = 65281

	// ExtALPS is application_settings, ALPS, under the codepoint BoringSSL
	// gives it now, 17613 (0x44cd), which Chrome 155 sends; ExtALPSOld is the
	// one it had first, 17513 (0x4469), which older Chrome sends. The names
	// are BoringSSL's.
	ExtALPS    uint16 = 17613
	ExtALPSOld uint16 = 17513

	// ExtApplicationSettings is 17513, the codepoint BoringSSL calls
	// application_settings_old: this name says the other.
	//
	// Deprecated: use ExtALPSOld, of the same value.
	ExtApplicationSettings uint16 = 17513
	// ExtApplicationSettingsOld is 17613, the codepoint BoringSSL calls
	// application_settings, which Chrome sends now: this name says the other.
	//
	// Deprecated: use ExtALPS, of the same value.
	ExtApplicationSettingsOld uint16 = 17613
)
```

</div>

</div>

## Variables

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### ErrNoRequest { .tf-symbol }

<div class="tf-ref__docs" markdown>

ErrNoRequest reports frames that end before a request's header block does.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
var ErrNoRequest = errors.New("fingerprint: the frames end before a request's header block does")
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### ErrNotClientHello { .tf-symbol }

<div class="tf-ref__docs" markdown>

ErrNotClientHello reports bytes that are syntactically fine as far as they go but are not the message this package parses — a ServerHello, an alert, or plain HTTP sent to a TLS port.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
var ErrNotClientHello = errors.New("fingerprint: not a ClientHello")
```

</div>

</div>

## Functions

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### CipherName() { .tf-symbol }

<div class="tf-ref__docs" markdown>

CipherName names a cipher suite.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func CipherName(v uint16) string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### ExtensionName() { .tf-symbol }

<div class="tf-ref__docs" markdown>

ExtensionName names a TLS extension, GREASE included.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func ExtensionName(v uint16) string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### GroupName() { .tf-symbol }

<div class="tf-ref__docs" markdown>

GroupName names a supported group (named curve).

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func GroupName(v uint16) string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### IsGREASE() { .tf-symbol }

<div class="tf-ref__docs" markdown>

IsGREASE reports whether a value is one of the sixteen reserved GREASE values, which all have the form 0xNaNa: both bytes equal, low nibble 0xa.

GREASE is the random noise TLS clients sprinkle through their ClientHello to keep middleboxes honest (RFC 8701). Chrome picks fresh values on every single connection, so anything derived from them differs from the same browser to itself — which is why every fingerprint in this package drops them before hashing. Forgetting to do that is the classic way to produce a "fingerprint" that never matches twice.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func IsGREASE(v uint16) bool
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### SettingName() { .tf-symbol }

<div class="tf-ref__docs" markdown>

SettingName names an HTTP/2 setting.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func SettingName(v uint16) string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### SignatureName() { .tf-symbol }

<div class="tf-ref__docs" markdown>

SignatureName names a signature scheme.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func SignatureName(v uint16) string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### VersionName() { .tf-symbol }

<div class="tf-ref__docs" markdown>

VersionName names a TLS version.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func VersionName(v uint16) string
```

</div>

</div>

## Types

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### ClientHello { .tf-symbol }

<div class="tf-ref__docs" markdown>

ClientHello is a parsed TLS ClientHello, in wire order.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type ClientHello struct {
	// Raw is the exact record-layer prefix this hello was parsed from, with
	// whatever followed it on the wire trimmed off. A recorder that saved "the
	// bytes it happened to have read" would store a different number of bytes
	// depending on how the kernel split the stream; this is reproducible, which
	// makes it safe to write into a capture file and re-parse later.
	Raw []byte

	// RecordVersion is the version the record layer was written with, which
	// is not the hello's: TLS 1.3 asks for 0x0301 there on a first hello.
	// Records is how many records the hello came in, which says where the
	// client cut it; a browser's fits in one, however long.
	RecordVersion uint16
	Records       int

	LegacyVersion      uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         []Extension
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ParseClientHello() { .tf-member }

<div class="tf-ref__docs" markdown>

ParseClientHello reads a ClientHello out of raw TLS record-layer bytes — the first thing a server reads off an accepted connection.

It takes records rather than a bare handshake message because that is the shape the bytes arrive in, and because a ClientHello may be split across several records. Chrome's is close to 2 KB once the post-quantum key share is in it, which is still one record; other clients fragment, and a parser that assumed one record would report those as malformed.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func ParseClientHello(records []byte) (*ClientHello, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.ALPN() { .tf-member }

<div class="tf-ref__docs" markdown>

ALPN returns the advertised application protocols, in order.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) ALPN() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.ApplicationSettings() { .tf-member }

<div class="tf-ref__docs" markdown>

ApplicationSettings returns the ALPS protocol list. Chrome sends this extension under two different numbers depending on version, and which one it picks is itself a version signal, so both are read, the current one first.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) ApplicationSettings() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.CertCompressionAlgorithms() { .tf-member }

<div class="tf-ref__docs" markdown>

CertCompressionAlgorithms returns the certificate compression algorithms.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) CertCompressionAlgorithms() []uint16
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.ECPointFormats() { .tf-member }

<div class="tf-ref__docs" markdown>

ECPointFormats returns the elliptic curve point formats. JA3 hashes them.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) ECPointFormats() []uint8
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.EncryptedClientHello() { .tf-member }

<div class="tf-ref__docs" markdown>

EncryptedClientHello returns the encrypted\_client\_hello extension of an outer ClientHello, or false for a hello without one, or with one that is an inner hello's or does not parse.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) EncryptedClientHello() (ECH, bool)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.Extension() { .tf-member }

<div class="tf-ref__docs" markdown>

Extension returns the body of the first extension of the given type.

"First" rather than "only" because a duplicate extension is malformed but not unparseable, and the fingerprint of a malformed hello is still worth having: refusing to describe it would hide exactly the client worth looking at.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) Extension(typ uint16) ([]byte, bool)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.ExtensionTypes() { .tf-member }

<div class="tf-ref__docs" markdown>

ExtensionTypes lists the extension numbers in the order they were sent.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) ExtensionTypes() []uint16
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.JA3() { .tf-member }

<div class="tf-ref__docs" markdown>

JA3 returns the JA3 string: version, ciphers, extensions, curves and point formats, decimal, GREASE removed.

A warning that belongs next to the function rather than in a document: JA3 is not usable for Chrome. Chrome shuffles its extension order on every connection, and JA3 hashes that order, so the same browser produces a different JA3 for every request it makes. It is implemented here because plenty of services still log it. A stable JA3 across a finite set of connections is not enough to identify or rule out Chrome; never compare two JA3s and conclude anything from their differing.

Use JA4, which sorts before hashing for exactly this reason.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) JA3() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.JA3Hash() { .tf-member }

<div class="tf-ref__docs" markdown>

JA3Hash returns the MD5 of the JA3 string, which is the form services log.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) JA3Hash() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.JA4() { .tf-member }

<div class="tf-ref__docs" markdown>

JA4 returns the FoxIO JA4 TLS fingerprint, e.g.

```text linenums="0"
t13d1516h2_8daaf6152771_806a8c22fdea
```

Unlike JA3 it sorts the cipher and extension lists before hashing, so it is stable for a browser that shuffles its extension order — which is every modern Chrome. This is the fingerprint to compare.

One property worth knowing before comparing anything: a client's JA4 changes when the connection is RESUMED, because resumption adds pre\_shared\_key to the extension set. Real Chrome 151 sends t13d1516h2\_…\_806a8c22fdea cold and t13d1517h2\_…\_a87ad97598a9 on a resumed connection. Both are that browser. Compare like with like.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) JA4() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.JA4Raw() { .tf-member }

<div class="tf-ref__docs" markdown>

JA4Raw returns the un-hashed form, `ja4_r`, whose whole point is that a mismatch can be read: two JA4s that differ tell you nothing about why, two JA4Raws differ at a cipher or an extension you can name.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) JA4Raw() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.KeyShareGroups() { .tf-member }

<div class="tf-ref__docs" markdown>

KeyShareGroups returns the groups the client actually sent a key share for, which is a subset of SupportedGroups and a fingerprint in its own right: a client that offers X25519MLKEM768 but only ships an X25519 share is not the browser it claims to be.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) KeyShareGroups() []uint16
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.KeyShares() { .tf-member }

<div class="tf-ref__docs" markdown>

KeyShares returns the entries of key\_share in the order sent, GREASE included, as far as they parse.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) KeyShares() []KeyShare
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.PSKKeyExchangeModes() { .tf-member }

<div class="tf-ref__docs" markdown>

PSKKeyExchangeModes returns the offered PSK modes.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) PSKKeyExchangeModes() []uint8
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.PreSharedKey() { .tf-member }

<div class="tf-ref__docs" markdown>

PreSharedKey returns the shape of pre\_shared\_key, or false for a hello without one, or with one that does not parse.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) PreSharedKey() (PSK, bool)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.ServerName() { .tf-member }

<div class="tf-ref__docs" markdown>

ServerName returns the SNI hostname.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) ServerName() (string, bool)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.SignatureAlgorithms() { .tf-member }

<div class="tf-ref__docs" markdown>

SignatureAlgorithms returns the signature schemes, in the order sent.

Order is load-bearing: JA4 hashes this list unsorted, precisely because it is a preference list and clients disagree about the preference.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) SignatureAlgorithms() []uint16
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.SupportedGroups() { .tf-member }

<div class="tf-ref__docs" markdown>

SupportedGroups returns the named groups (curves), GREASE included.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) SupportedGroups() []uint16
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.SupportedVersions() { .tf-member }

<div class="tf-ref__docs" markdown>

SupportedVersions returns the versions from the supported\_versions extension, GREASE included, in the order sent.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) SupportedVersions() []uint16
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ClientHello.TrustAnchors() { .tf-member }

<div class="tf-ref__docs" markdown>

TrustAnchors returns the IDs of trust\_anchors in the order sent, each as the relative object identifier it is, dotted (44947.2.1), or in hex when it is not one. Chrome 154 and later send them sorted by their bytes; an older Chrome drew their order once for each process it ran. The IDs say which root store sent them.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c *ClientHello) TrustAnchors() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Difference { .tf-symbol }

<div class="tf-ref__docs" markdown>

Difference is one way in which a candidate handshake failed to be the reference handshake.

It carries both sides and, where a list is involved, which entries are missing and which are extra — because "the JA4 differs" is a fact nobody can act on, while "you are not sending mldsa44" is a fix.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Difference struct {
	Field     string
	Reference string
	Candidate string
	Missing   []string
	Extra     []string
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Difference.String() { .tf-member }

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (d Difference) String() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### ECH { .tf-symbol }

<div class="tf-ref__docs" markdown>

ECH is what a server can read of the encrypted\_client\_hello extension of a hello to it when it published no ECH configuration, which is every server a browser has not been told about: GREASE, the shape of a real one with random contents, so that servers cannot come to depend on its absence. Its cipher suite, the length of its encapsulated key and the length of its payload.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type ECH struct {
	KDF, AEAD     uint16
	ConfigID      uint8
	EncLength     int
	PayloadLength int
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Extension { .tf-symbol }

<div class="tf-ref__docs" markdown>

Extension is one entry of the ClientHello's extension block, kept in the order the client sent it and with its body intact.

The body is kept because the extension TYPE alone is not the whole story: two clients can both send supported\_groups and disagree about every group in it. The structural diff reads the bodies.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Extension struct {
	Type uint16
	Data []byte
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Field { .tf-symbol }

<div class="tf-ref__docs" markdown>

Field is one property a fingerprint is compared on, with the values from one side of the comparison.

The list exists so that the fields are named once. Comparing and displaying want the same set, and a second copy of it in the command line would drift: a field added here would quietly stop being shown, or a field shown there would quietly stop being compared.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Field struct {
	Name   string
	Values []string

	// Set compares membership rather than sequence: where the browser itself
	// varies the order, as the extension list, or the trust anchors of a
	// Chrome before 154, which drew their order for each process.
	Set bool

	// Scalar is a single value rather than a list, so a mismatch has no
	// meaningful "missing" and "extra".
	Scalar bool

	// Varies says why a value says nothing of the client, for one shown for
	// both sides and never compared: a value the browser draws afresh for
	// every connection, such as the length of its ECH payload, where it would
	// not match itself, or one the page asked for decides. Empty for a value
	// compared. Either side's makes the field one.
	Varies string

	// Missing is a value the measurement does not hold: one made before it
	// was recorded, or one that could not be read. Missing on either side, a
	// field is not checked: neither a match nor a difference.
	Missing bool
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HTTP1Fields() { .tf-member }

<div class="tf-ref__docs" markdown>

HTTP1Fields is everything in an HTTP/1.1 request fingerprint.

Host's position and spelling are fingerprinted, but its value belongs to the destination and differs between two measurements by construction, as does the target of the request line.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func HTTP1Fields(h *HTTP1) []Field
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HTTP2Fields() { .tf-member }

<div class="tf-ref__docs" markdown>

HTTP2Fields is everything the connection preamble and first request are compared on.

Header values are included. A profile is a complete browser identity, and a Chrome ClientHello paired with a HeadlessChrome user-agent is exactly the kind of cross-layer contradiction this comparison exists to expose. The values of :path and :authority are not: the two measurements ask for different pages, and a browser opened by hand reaches the server by a name of its own.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func HTTP2Fields(h *HTTP2) []Field
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### TLSFields() { .tf-member }

<div class="tf-ref__docs" markdown>

TLSFields is everything a ClientHello is compared on, in a fixed order: the manifest of the comparison.

What the browser draws for every connection is not compared as it is, since the browser would not match itself; its shape is, which does not change:

- Extension ORDER. Chrome shuffles it on every connection. The extension SET is compared instead, which is what JA4 hashes, and the order of the trust anchors, drawn once for each browser process, likewise.
- GREASE values (RFC 8701). Where they go, how long they are, what a short body holds and which are one value is compared as grease.
- The random, the session id, the keys, ECH's config id, key and payload, and the tickets and binders of pre\_shared\_key: their lengths are compared, the bytes are not. Of the keys, what a server can check is compared too: that each is a public key of its kind, and that keys of one kind are each their own (keys).
- The length of the ECH payload, which Chrome draws from four for every connection: shown, not compared itself (Varies); whether it is one of the four is (ech\_grease).
- The contents of server\_name, which are the site's, and of padding, whose length follows from the rest. Whether server\_name holds one host\_name, and whether each extension a field reads reads whole, is compared as framing.

A key of a group no rule reads, and an ECH key of a length no KEM has, are reported as not checked when both sides send one.

Other fields in this manifest are compared exactly for the supplied pair of captures. This does not establish that they are invariant across launches, request contexts or connection states. An extension both sides send that none of this describes, with contents that differ, is reported by CompareTLS as not checked.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func TLSFields(hello *ClientHello) []Field
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Field.Matches() { .tf-member }

<div class="tf-ref__docs" markdown>

Matches reports whether two fields agree, by the rule that field is compared with.

Display has to ask this rather than compare the rendered strings, or a Set field whose order differs would be shown as a difference while the verdict below it said everything matched. The two answers have to come from one rule.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f Field) Matches(other Field) bool
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Field.Render() { .tf-member }

<div class="tf-ref__docs" markdown>

Render is the value as a person reads it.

A Set field renders sorted. Its order is not compared because the browser varies it, so printing the order it happened to arrive in would invite the reader to compare something that is not being compared.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f Field) Render() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Frame { .tf-symbol }

<div class="tf-ref__docs" markdown>

Frame is one HTTP/2 frame as it went: its type, flags, stream and length.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Frame struct {
	Type   uint8
	Flags  uint8
	Stream uint32
	Length int
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Frame.Ack() { .tf-member }

<div class="tf-ref__docs" markdown>

Ack reports a SETTINGS or PING frame that acknowledges the server's: when it goes depends on when the server's arrived, not on the client.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f Frame) Ack() bool
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Frame.String() { .tf-member }

<div class="tf-ref__docs" markdown>

String is a frame as a person reads it: its type, its stream, and its flags by name, any the type does not define in hex.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f Frame) String() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### HTTP1 { .tf-symbol }

<div class="tf-ref__docs" markdown>

HTTP1 is the request line, without its target, and the ordered header block as they appeared on the wire.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type HTTP1 struct {
	Method  string
	Proto   string
	Headers []HeaderField
	// Layout is how the request was written where a server reads it alike
	// (capture.HTTP1.Layout); nil when it was not recorded.
	Layout []string
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### HTTP2 { .tf-symbol }

<div class="tf-ref__docs" markdown>

HTTP2 is everything a server sees a client do on a fresh HTTP/2 connection before the first response is written.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type HTTP2 struct {
	Settings     []Setting
	WindowUpdate uint32
	Priorities   []Priority
	Headers      []HeaderField

	// HeaderPriority is the priority carried ON the HEADERS frame, which is a
	// different thing from a standalone PRIORITY frame and is set by a different
	// knob in every library that lets you set it at all. Chrome sends one
	// (exclusive, depends on stream 0, weight 255 on the wire); most HTTP
	// clients send none.
	HeaderPriority *Priority

	// Raw is what the client sent from the end of its preface to the end of
	// its first request's header block, as it went: ParsePreamble reads it.
	// Empty when it was not recorded.
	Raw []byte
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HTTP2.Akamai() { .tf-member }

<div class="tf-ref__docs" markdown>

Akamai returns the Akamai HTTP/2 fingerprint, e.g.

```text linenums="0"
1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

The four fields are the SETTINGS in order, the connection-level WINDOW\_UPDATE increment, the PRIORITY frames, and the order of the pseudo-headers. A PRIORITY frame is stream:exclusive:depends-on:weight, the weight as RFC 9113 counts it, the frame's byte and one, as Akamai's paper and tls.peet.ws write it: Firefox's 200 on the wire is 201 (3:0:0:201). It complements the TLS fingerprint rather than duplicating it: a client can copy a ClientHello byte for byte and still give itself away one layer up by sending :path before :scheme.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (h *HTTP2) Akamai() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HTTP2.Header() { .tf-member }

<div class="tf-ref__docs" markdown>

Header returns the first value sent for a name, matched case-insensitively.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (h *HTTP2) Header(name string) (string, bool)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HTTP2.HeaderOrder() { .tf-member }

<div class="tf-ref__docs" markdown>

HeaderOrder returns the ordinary header names in the order sent.

This is a fingerprint in its own right and one of the easiest to get wrong, because most HTTP libraries store headers in a map and emit them sorted or at random. A client whose TLS is perfect and whose headers arrive alphabetically has announced itself.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (h *HTTP2) HeaderOrder() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HTTP2.PseudoHeaderOrder() { .tf-member }

<div class="tf-ref__docs" markdown>

PseudoHeaderOrder returns the pseudo-headers as single letters in the order sent: m, a, s, p for :method, :authority, :scheme, :path.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (h *HTTP2) PseudoHeaderOrder() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### HeaderBlocks { .tf-symbol }

<div class="tf-ref__docs" markdown>

HeaderBlocks reads the header blocks a client wrote on one connection, in the order it wrote them: each against the dynamic table the blocks before it left (RFC 7541, section 2.3.2), which it keeps as the server's decoder does. After a block it cannot read it is out of step with the client's table, and reads no more.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type HeaderBlocks struct {
	// Has unexported fields.
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### NewHeaderBlocks() { .tf-member }

<div class="tf-ref__docs" markdown>

NewHeaderBlocks reads the header blocks of a connection whose server let the client's dynamic table be tableSize bytes: the client writes its first against a table of 4096, and may say another size, up to tableSize, at the start of any block.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func NewHeaderBlocks(tableSize uint32) *HeaderBlocks
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### HeaderBlocks.Next() { .tf-member }

<div class="tf-ref__docs" markdown>

Next reads the connection's next header block, as Representations reads one: how each field was written, then which field each is.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (h *HeaderBlocks) Next(block []byte) ([]Representation, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### HeaderField { .tf-symbol }

<div class="tf-ref__docs" markdown>

HeaderField is one HPACK-decoded header, in wire order, pseudo-headers included.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type HeaderField struct {
	Name  string
	Value string
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### KeyShare { .tf-symbol }

<div class="tf-ref__docs" markdown>

KeyShare is one entry of key\_share: its group, and how long its key is. The key itself is fresh for every connection, and only its length says anything about the client: 1216 bytes for X25519MLKEM768, 32 for X25519, one for a GREASE group's.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type KeyShare struct {
	Group  uint16
	Length int
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### PSK { .tf-symbol }

<div class="tf-ref__docs" markdown>

PSK is what a server can read of pre\_shared\_key without its keys: how many identities it offers, and how long each binder is. The identities are tickets the server issued, and the binders are fresh for every hello.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type PSK struct {
	Identities int
	Binders    []int
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Preamble { .tf-symbol }

<div class="tf-ref__docs" markdown>

Preamble is what a client sent from the end of its preface to the end of the header block of its first request.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Preamble struct {
	// Raw is the bytes it was read from, without whatever followed.
	Raw    []byte
	Frames []Frame
	// Block is the first request's header block, its fragments joined, without
	// padding or priority.
	Block []byte
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### ParsePreamble() { .tf-member }

<div class="tf-ref__docs" markdown>

ParsePreamble reads frames up to the end of the first header block. Bytes past it are not read, and are not in Raw.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func ParsePreamble(raw []byte) (*Preamble, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Priority { .tf-symbol }

<div class="tf-ref__docs" markdown>

Priority is a standalone PRIORITY frame. Chrome stopped sending these when it moved to the `priority` header, so their PRESENCE is a signal in itself.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Priority struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Report { .tf-symbol }

<div class="tf-ref__docs" markdown>

Report is the outcome of comparing a candidate against a reference.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Report struct {
	Differences []Difference

	// Unchecked is what both sides have and no rule says how to compare: an
	// extension nobody has described, whose contents differ. It is neither a
	// match nor a difference, and a report with any is not a match.
	Unchecked []Difference `json:",omitempty"`
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### CompareHTTP1() { .tf-member }

<div class="tf-ref__docs" markdown>

CompareHTTP1 diffs HTTP/1.1 request header order, casing and values.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func CompareHTTP1(reference, candidate *HTTP1) Report
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### CompareHTTP2() { .tf-member }

<div class="tf-ref__docs" markdown>

CompareHTTP2 diffs the connection preamble and the request headers.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func CompareHTTP2(reference, candidate *HTTP2) Report
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### CompareTLS() { .tf-member }

<div class="tf-ref__docs" markdown>

CompareTLS diffs a candidate ClientHello against a reference one, usually a real browser's. TLSFields says what is compared, and what is not.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func CompareTLS(reference, candidate *ClientHello) Report
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Report.OK() { .tf-member }

<div class="tf-ref__docs" markdown>

OK reports a candidate that matches the reference on every field compared, with nothing left that could not be: of the two captures compared alone.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (r Report) OK() bool
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Report.String() { .tf-member }

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (r Report) String() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Representation { .tf-symbol }

<div class="tf-ref__docs" markdown>

Representation is how one field of a header block was written: whole, from a table, or as a literal with or without indexing or never to be indexed, its name from a table or written out; each string written out Huffman-coded or not. A table size update is one too, of no field.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Representation struct {
	// Field is the field's name, decoded; empty for a size update.
	Field string
	// Kind is "indexed", "with indexing", "without indexing", "never indexed"
	// or "size update".
	Kind string
	// Index is the table index of the field, or of its name, 0 for a name
	// written out, or the size a size update sets.
	Index uint64
	// NameHuffman and ValueHuffman say which strings were Huffman-coded.
	NameHuffman, ValueHuffman bool
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Representations() { .tf-member }

<div class="tf-ref__docs" markdown>

Representations reads a header block, written for a table of tableSize bytes, field by field: first how each was written, then, decoding the block, which field each is.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func Representations(block []byte, tableSize uint32) ([]Representation, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Representation.Named() { .tf-member }

<div class="tf-ref__docs" markdown>

Named is a representation as a person reads it, after its field's name; a size update, of no field, alone.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (r Representation) Named() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Representation.String() { .tf-member }

<div class="tf-ref__docs" markdown>

String is a representation as a person reads it, without its field's name.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (r Representation) String() string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Rule { .tf-symbol }

<div class="tf-ref__docs" markdown>

Rule is how a comparison holds a client to a browser on one field: what of it is compared, and what is left alone and why. The rules together are the manifest, which a comparison's result carries, so that a match can be read for what it covers.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Rule struct {
	Layer string `json:"layer"`
	Field string `json:"field"`
	How   string `json:"how"`
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Manifest() { .tf-member }

<div class="tf-ref__docs" markdown>

Manifest is the rules a comparison holds a client to, field by field, in the order the fields are compared.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func Manifest() []Rule
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Setting { .tf-symbol }

<div class="tf-ref__docs" markdown>

Setting is one entry of an HTTP/2 SETTINGS frame, kept in the order it was sent. Two clients can send the same settings in a different order, and the order is fingerprinted, so a map would throw away the signal.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Setting struct {
	ID    uint16
	Value uint32
}
```

</div>

</div>
