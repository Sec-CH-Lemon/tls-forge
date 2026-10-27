package tlsforge

import (
	"errors"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/internal/redact"
	"github.com/igor-lemon/utls/behavior"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Chrome sends a request for a URL as its URL parser makes it, which for http
// and https is the WHATWG URL Standard's, measured on Chrome 155 for every case
// of testdata/chrome155-urls.json: without the C0 controls and spaces around
// it, nor any tab or newline in it; the scheme and the host in lower case, the
// host percent-decoded, mapped and made ASCII as IDNA (UTS 46) has it, or read
// as an IPv4 address in any of its forms, or as an IPv6 one, and written back
// as each is written; no port where it is the scheme's; a slash for a
// backslash; dot segments resolved, percent-encoded ones too; what a path or a
// query may not hold percent-encoded, as UTF-8, and what is percent-encoded
// already left as it is; no fragment. For a URL it cannot parse, or one on a
// port it keeps away from, it sends nothing.

// CanonicalURL is raw as tls-forge sends a request for it, as Chrome does: the
// http or https URL Chrome's URL parser makes of it, its credentials kept,
// which no request sends before a server asks for them. The error says why
// there is none: raw is not an http or https URL, Chrome sends nothing to its
// port, or its path holds a percent sign that escapes nothing, which Chrome
// sends as it is and tls-forge cannot yet. It unwraps to the reason alone,
// said as of the URL.
func CanonicalURL(raw string) (string, error) {
	p, err := sendableURL(raw, nil)
	if err != nil {
		return "", fmt.Errorf("tlsforge: %q %w", redact.URL(raw), redact.Err(err))
	}
	return p.String(), nil
}

// requestURL is raw as a request for it is sent, relative to base when raw is
// a Location, nil when it is not; or why no request is.
func requestURL(raw string, base *url.URL, policies ...behavior.Policy) (*url.URL, error) {
	p, err := sendableURL(raw, base, policies...)
	if err != nil {
		return nil, err
	}
	return p.url(), nil
}

// sendableURL is raw parsed as Chrome parses it, relative to base, when a
// request for it can be sent as Chrome sends one; or why it cannot.
func sendableURL(raw string, base *url.URL, policies ...behavior.Policy) (*parsedURL, error) {
	p, err := parseURL(raw, base)
	if err == nil {
		err = p.refused(policies...)
	}
	if err == nil {
		err = p.uncarried()
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// parsedURL is an http or https URL in the parts Chrome serializes it from:
// its credentials and path percent-encoded, its host canonical, no port where
// it is the scheme's, its query percent-encoded, and whether it has one, empty
// or not.
type parsedURL struct {
	scheme             string
	username, password string
	host, port         string
	path               string
	query              string
	hasQuery           bool
}

// String is the URL as Chrome serializes it.
func (p *parsedURL) String() string {
	var b strings.Builder
	b.WriteString(p.scheme)
	b.WriteString("://")
	if p.username != "" || p.password != "" {
		b.WriteString(p.username)
		if p.password != "" {
			b.WriteByte(':')
			b.WriteString(p.password)
		}
		b.WriteByte('@')
	}
	b.WriteString(p.host)
	if p.port != "" {
		b.WriteByte(':')
		b.WriteString(p.port)
	}
	b.WriteString(p.path)
	if p.hasQuery {
		b.WriteByte('?')
		b.WriteString(p.query)
	}
	return b.String()
}

// url is the URL as a url.URL that a request goes out for as it is: its path
// carried as it is written, which RequestURI says when it unescapes, and its
// query as it is.
func (p *parsedURL) url() *url.URL {
	u := &url.URL{Scheme: p.scheme, Host: p.host, Path: lenientUnescape(p.path), RawPath: p.path, RawQuery: p.query,
		ForceQuery: p.hasQuery && p.query == ""}
	if p.port != "" {
		u.Host += ":" + p.port
	}
	if (&url.URL{Path: u.Path}).EscapedPath() == p.path {
		// As url.Parse leaves a path that escaping writes as it was.
		u.RawPath = ""
	}
	switch username := lenientUnescape(p.username); {
	case p.password != "":
		u.User = url.UserPassword(username, lenientUnescape(p.password))
	case username != "":
		u.User = url.User(username)
	}
	return u
}

// specialPorts are the ports the schemes Chrome sends requests for mean.
var specialPorts = map[string]string{"http": "80", "https": "443"}

// errNotHTTP and errNoHost say what is wrong with a URL of no other scheme, or
// with no host.
var (
	errNotHTTP = errors.New("is not an http or https URL")
	errNoHost  = errors.New("names no host")
)

// parseURL is raw parsed as the WHATWG URL Standard parses an http or https
// URL, relative to base when it names no scheme of its own; base is nil for
// none.
func parseURL(raw string, base *url.URL) (*parsedURL, error) {
	input := trimURL(raw)
	scheme, rest, named := urlScheme(input)
	switch {
	case !named && base == nil:
		return nil, errors.New("is not a URL: it names no scheme, and there is nothing it is relative to")
	case !named:
		return relativeURL(input, base)
	case scheme != "http" && scheme != "https":
		return nil, errNotHTTP
	case base != nil && scheme == base.Scheme:
		// http:foo, after an http URL, is relative to it.
		return relativeURL(rest, base)
	}
	p := &parsedURL{scheme: scheme}
	return p, p.authority(strings.TrimLeft(rest, `/\`))
}

// trimURL is raw without the C0 controls and spaces around it, nor any tab or
// newline in it.
func trimURL(raw string) string {
	raw = strings.TrimFunc(raw, func(r rune) bool { return r <= ' ' })
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, raw)
}

// urlScheme is the scheme input begins with, in lower case, and what follows
// its colon; or none.
func urlScheme(input string) (scheme, rest string, named bool) {
	for i := 0; i < len(input); i++ {
		switch c := input[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
		case i > 0 && c == ':':
			return strings.ToLower(input[:i]), input[i+1:], true
		default:
			return "", "", false
		}
	}
	return "", "", false
}

// slashes reports input beginning with two slashes, either way round, which
// begin an authority.
func slashes(input string) bool {
	return len(input) >= 2 && (input[0] == '/' || input[0] == '\\') && (input[1] == '/' || input[1] == '\\')
}

// relativeURL is input, which names no scheme of its own, resolved against
// base, which is canonical.
func relativeURL(input string, base *url.URL) (*parsedURL, error) {
	b := parsedBase(base)
	p := &parsedURL{scheme: b.scheme}
	if slashes(input) {
		// Another authority.
		return p, p.authority(strings.TrimLeft(input, `/\`))
	}
	p.host, p.port = b.host, b.port
	switch {
	case input == "", input[0] == '#':
		p.path, p.query, p.hasQuery = b.path, b.query, b.hasQuery
	case input[0] == '?':
		p.path = b.path
		p.setQuery(input[1:])
	case input[0] == '/', input[0] == '\\':
		p.setPathAndQuery(input, nil)
	default:
		// Relative to the directory of base's path.
		segments := strings.Split(b.path, "/")[1:]
		p.setPathAndQuery("/"+input, segments[:len(segments)-1])
	}
	return p, nil
}

// parsedBase is base, a canonical URL a Location is relative to, in parts. Its
// credentials are left out: a request is sent for none, and who follows a
// Location keeps them.
func parsedBase(base *url.URL) *parsedURL {
	b := &parsedURL{scheme: base.Scheme, host: base.Hostname(), path: base.EscapedPath(), query: base.RawQuery,
		hasQuery: base.ForceQuery || base.RawQuery != ""}
	if strings.Contains(b.host, ":") {
		b.host = "[" + b.host + "]"
	}
	if port := base.Port(); port != specialPorts[base.Scheme] {
		b.port = port
	}
	return b
}

// authority reads s, a URL from its authority on: the authority, then its
// path, query and fragment.
func (p *parsedURL) authority(s string) error {
	end := strings.IndexAny(s, `/\?#`)
	if end < 0 {
		end = len(s)
	}
	authority, rest := s[:end], s[end:]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		username, password, _ := strings.Cut(authority[:at], ":")
		p.username, p.password = escapeURL(username, userinfoEncoded), escapeURL(password, userinfoEncoded)
		authority = authority[at+1:]
	}
	host, port, err := splitHostPort(authority)
	if err != nil {
		return err
	}
	if p.host, err = parseHost(host); err != nil {
		return err
	}
	if p.port, err = canonicalPort(port, specialPorts[p.scheme]); err != nil {
		return err
	}
	p.setPathAndQuery(rest, nil)
	return nil
}

// splitHostPort is an authority's host and port, a bracketed IPv6 address kept
// whole, brackets and all.
func splitHostPort(authority string) (host, port string, err error) {
	if !strings.HasPrefix(authority, "[") {
		host, port, _ = strings.Cut(authority, ":")
		return host, port, nil
	}
	end := strings.IndexByte(authority, ']')
	if end < 0 {
		return "", "", errors.New("is not a URL: its IPv6 address has no closing bracket")
	}
	host, after := authority[:end+1], authority[end+1:]
	if port, ok := strings.CutPrefix(after, ":"); ok {
		return host, port, nil
	}
	if after != "" {
		return "", "", fmt.Errorf("is not a URL: %q follows its IPv6 address", after)
	}
	return host, "", nil
}

// canonicalPort is port as Chrome writes it: none for the one the scheme
// means, def, nor for none; an error for one that is not a number up to 65535.
func canonicalPort(port, def string) (string, error) {
	if port == "" {
		return "", nil
	}
	if strings.Trim(port, "0123456789") != "" {
		return "", fmt.Errorf("is not a URL: its port %q is not a number", port)
	}
	// All digits: Atoi fails only for a number past any int, and then says
	// the largest.
	n, _ := strconv.Atoi(port)
	if n > math.MaxUint16 {
		return "", fmt.Errorf("is not a URL: its port %s is past 65535", port)
	}
	if s := strconv.Itoa(n); s != def {
		return s, nil
	}
	return "", nil
}

// setPathAndQuery reads s, the rest of a URL from its path on, after the path
// segments it is relative to: its path, dot segments resolved, then its query,
// and no fragment.
func (p *parsedURL) setPathAndQuery(s string, segments []string) {
	s, _, _ = strings.Cut(s, "#")
	s, query, hasQuery := strings.Cut(s, "?")
	if s != "" && (s[0] == '/' || s[0] == '\\') {
		// The path's first slash begins it, as each later one ends a segment.
		s = s[1:]
	}
	for {
		end := strings.IndexAny(s, `/\`)
		segment := s
		if end >= 0 {
			segment = s[:end]
		}
		switch {
		case doubleDot(segment):
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
			if end < 0 {
				segments = append(segments, "")
			}
		case singleDot(segment):
			if end < 0 {
				segments = append(segments, "")
			}
		default:
			segments = append(segments, escapeURL(segment, pathEncoded))
		}
		if end < 0 {
			break
		}
		s = s[end+1:]
	}
	p.path = "/" + strings.Join(segments, "/")
	if hasQuery {
		p.setQuery(query)
	}
}

// setQuery takes query, up to any fragment, as the query of an http or https
// URL is written.
func (p *parsedURL) setQuery(query string) {
	query, _, _ = strings.Cut(query, "#")
	p.query, p.hasQuery = escapeURL(query, queryEncoded), true
}

// singleDot and doubleDot report the path segments . and .., written as they
// may be.
func singleDot(segment string) bool { return segment == "." || strings.EqualFold(segment, "%2e") }

func doubleDot(segment string) bool {
	switch strings.ToLower(segment) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

// The bytes that each part of a URL has percent-encoded, past the C0 controls,
// DEL and every byte past ASCII, which all of them have: a path's as Chrome
// encodes one (the WHATWG path set, and |), an http or https URL's query's (the
// special-query set), and its credentials' (the userinfo set). # and ? end a
// path and # a query, so neither is ever in one.
const (
	pathEncoded     = " \"<>^`{|}"
	queryEncoded    = " \"<>'"
	userinfoEncoded = " \"#<>?`{}/:;=@[\\]^|"
)

const upperHex = "0123456789ABCDEF"

// escapeURL is s with its controls, the bytes of set and every byte past ASCII
// percent-encoded in upper case; a percent sign is left as it is, and so is
// what it escapes.
func escapeURL(s, set string) string {
	escaped := func(c byte) bool { return c < 0x20 || c >= 0x7f || strings.IndexByte(set, c) >= 0 }
	first := 0
	for first < len(s) && !escaped(s[first]) {
		first++
	}
	if first == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	b.WriteString(s[:first])
	for i := first; i < len(s); i++ {
		if c := s[i]; escaped(c) {
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&15])
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// lenientUnescape is s with every percent sign followed by two hexadecimal
// digits replaced by the byte they say, and any other left as it is.
func lenientUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if escapes(s, i) {
			b.WriteByte(hexDigit(s[i+1])<<4 | hexDigit(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// strayPercent is the first percent sign in s that escapes nothing, with what
// follows it of the two characters it would escape; or nothing.
func strayPercent(s string) string {
	for i := strings.IndexByte(s, '%'); i >= 0; {
		if !escapes(s, i) {
			return s[i:min(i+3, len(s))]
		}
		next := strings.IndexByte(s[i+3:], '%')
		if next < 0 {
			break
		}
		i += 3 + next
	}
	return ""
}

// escapes reports a percent sign at i in s followed by two hexadecimal digits.
func escapes(s string, i int) bool {
	return s[i] == '%' && i+2 < len(s) && hexDigit(s[i+1]) < 16 && hexDigit(s[i+2]) < 16
}

// hexDigit is what the hexadecimal digit c says, or 255 for no digit.
func hexDigit(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

// refused is why Chrome sends nothing for a URL on its port, or nil: it keeps
// away from the ports of services that are not the web's.
func (p *parsedURL) refused(policies ...behavior.Policy) error {
	if p.port == "" {
		return nil
	}
	n, _ := strconv.Atoi(p.port)
	if slices.Contains(policyArgument(policies).Numbers("url.blocked_ports"), uint64(n)) {
		return fmt.Errorf("is on port %d, which Chrome sends nothing to (ERR_UNSAFE_PORT)", n)
	}
	return nil
}

// blockedPorts are the ports Chrome sends nothing to, in order: Chromium's
// kRestrictedPorts, the Fetch standard's bad ports but 4190 and 6679, which
// Chrome 155 sends to (measured), and port 0.
var blockedPorts = func() []int {
	var out []int
	for _, n := range legacyPolicy().Numbers("url.blocked_ports") {
		out = append(out, int(n))
	}
	return out
}()

// uncarried is why tls-forge cannot send a request for a URL as Chrome does,
// or nil: a percent sign in its path that escapes nothing, which Chrome sends
// as it is and a url.URL escapes once more.
func (p *parsedURL) uncarried() error {
	if stray := strayPercent(p.path); stray != "" {
		return fmt.Errorf("has %q in its path, a percent sign that escapes nothing, which Chrome sends as it is "+
			"and tls-forge cannot yet", stray)
	}
	return nil
}

// hostProfile makes a host name ASCII as the WHATWG URL Standard does: UTS
// 46, nontransitional, the Bidi rule and joiners checked, neither hyphens nor
// STD3 rules nor DNS lengths, a label in Punycode checked.
var hostProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.BidiRule(), idna.CheckJoiners(true),
	idna.CheckHyphens(false), idna.StrictDomainName(false), idna.VerifyDNSLength(false))

// parseHost is host as Chrome writes it: an IPv6 address bracketed and
// canonical, an IPv4 one in any of its forms dotted and decimal, or a name
// percent-decoded, mapped and made ASCII; an error for one it cannot be.
func parseHost(host string) (string, error) {
	switch {
	case host == "":
		return "", errNoHost
	case host[0] == '[':
		return canonicalIPv6(host[1 : len(host)-1])
	case asciiName(host):
		return ipv4OrName(strings.ToLower(host))
	}
	decoded, err := url.PathUnescape(host)
	if err != nil {
		return "", fmt.Errorf("is not a URL: its host %q holds a percent sign that escapes nothing", host)
	}
	ascii, err := hostProfile.ToASCII(decoded)
	switch {
	case err != nil:
		return "", fmt.Errorf("is not a URL: its host %q is no name: %w", host, err)
	case ascii == "":
		return "", fmt.Errorf("is not a URL: its host %q is no name", host)
	}
	if i := strings.IndexFunc(ascii, forbiddenInHost); i >= 0 {
		return "", fmt.Errorf("is not a URL: its host %q holds %q, which no host may", host, ascii[i:i+1])
	}
	return ipv4OrName(ascii)
}

// asciiName reports a host of ASCII letters, digits, hyphens, underscores and
// dots, no label of it Punycode, which IDNA writes in lower case and leaves
// as it is otherwise.
func asciiName(host string) bool {
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	lower := strings.ToLower(host)
	return !strings.HasPrefix(lower, "xn--") && !strings.Contains(lower, ".xn--")
}

// forbiddenInHost reports a character no host may hold: the WHATWG URL
// Standard's forbidden domain code points.
func forbiddenInHost(r rune) bool {
	return r <= ' ' || r == 0x7f || strings.ContainsRune("#%/:<>?@[\\]^|", r)
}

// ipv4OrName is host, an ASCII name: an IPv4 address when its last label is a
// number, else as it is.
func ipv4OrName(host string) (string, error) {
	if endsInNumber(host) {
		return canonicalIPv4(host)
	}
	return host, nil
}

// endsInNumber reports a host whose last label, a dot at its end aside, is a
// number, which makes it an IPv4 address or nothing.
func endsInNumber(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) > 1 && labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	last := labels[len(labels)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := ipv4Number(last)
	return ok
}

// canonicalIPv4 is host, an IPv4 address in any of the forms the WHATWG URL
// Standard reads (up to four parts, each decimal, octal or hexadecimal, the
// last filling what is left), dotted and decimal.
func canonicalIPv4(host string) (string, error) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return "", fmt.Errorf("is not a URL: its host %q is an IPv4 address of more than four parts", host)
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := ipv4Number(part)
		if !ok {
			return "", fmt.Errorf("is not a URL: its host %q is an IPv4 address with %q in it", host, part)
		}
		if i < len(parts)-1 && n > 255 {
			return "", fmt.Errorf("is not a URL: its host %q is an IPv4 address with %q, past 255, in it", host, part)
		}
		numbers[i] = n
	}
	last := numbers[len(numbers)-1]
	if last >= uint64(1)<<(8*(5-len(numbers))) {
		return "", fmt.Errorf("is not a URL: its host %q is an IPv4 address past 255.255.255.255", host)
	}
	address := uint32(last)
	for i, n := range numbers[:len(numbers)-1] {
		address += uint32(n) << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)}).String(), nil
}

// ipv4Number is what a part of an IPv4 address, in lower case as a host is by
// then, says: hexadecimal after 0x, octal after another 0, decimal otherwise,
// as large as it is up to the largest uint64; or that it is no number.
func ipv4Number(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	base := uint64(10)
	switch {
	case len(part) >= 2 && part[0] == '0' && part[1] == 'x':
		base, part = 16, part[2:]
	case len(part) >= 2 && part[0] == '0':
		base, part = 8, part[1:]
	}
	var n uint64
	for i := 0; i < len(part); i++ {
		d := uint64(hexDigit(part[i]))
		if d >= base {
			return 0, false
		}
		if n > (math.MaxUint64-d)/base {
			n = math.MaxUint64
			continue
		}
		n = n*base + d
	}
	return n, true
}

// canonicalIPv6 is address, an IPv6 address, as the WHATWG URL Standard
// writes one, bracketed: its first longest run of two or more zero pieces
// compressed, the others in lower-case hexadecimal, and no IPv4 address in it.
func canonicalIPv6(address string) (string, error) {
	a, err := netip.ParseAddr(address)
	if err != nil || !a.Is6() || a.Zone() != "" {
		return "", fmt.Errorf("is not a URL: its host [%s] is no IPv6 address", address)
	}
	b := a.As16()
	var pieces [8]uint16
	for i := range pieces {
		pieces[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	start, length := -1, 1
	for i := 0; i < len(pieces); {
		if pieces[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(pieces) && pieces[j] == 0 {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		i = j
	}
	var out strings.Builder
	out.WriteByte('[')
	for i := 0; i < len(pieces); i++ {
		if i == start {
			out.WriteString("::")
			i += length - 1
			continue
		}
		if i > 0 && i != start+length {
			out.WriteByte(':')
		}
		out.WriteString(strconv.FormatUint(uint64(pieces[i]), 16))
	}
	out.WriteByte(']')
	return out.String(), nil
}
