package tlsforge

import (
	"net/textproto"
	"net/url"
	"strings"

	fhttp "github.com/igor-lemon/fhttp"
)

// RawSetCookieHeaders is the transport jar's opt-in parser hook. Chrome cookie
// bytes are less restrictive than Go Cookie.Name/Value; scope, Secure, prefix,
// credentials, SameSite and lifetime checks still run through SetCookies.
func (j *keptJar) RawSetCookieHeaders(u *url.URL, h fhttp.Header) bool {
	if !j.chrome {
		return false
	}
	var cookies []*fhttp.Cookie
	for _, line := range fieldValues(h, "set-cookie") {
		pair, attrs, _ := strings.Cut(line, ";")
		pair = textproto.TrimString(pair)
		if pair == "" || strings.IndexFunc(pair, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		name, value, equals := strings.Cut(pair, "=")
		if !equals {
			name, value = "", pair
		}
		name, value = textproto.TrimString(name), textproto.TrimString(value)
		if name == "" && value == "" {
			continue
		}
		// Reuse the attribute parser independently of its stricter cookie-pair
		// grammar. The raw name/value (including quotes) are kept for transmission.
		parsed := (&fhttp.Response{Header: fhttp.Header{"Set-Cookie": []string{"netfp=placeholder;" + attrs}}}).Cookies()
		if len(parsed) != 1 {
			continue
		}
		c := parsed[0]
		c.Name, c.Value, c.Raw = name, value, line
		c.Quoted = false
		cookies = append(cookies, c)
	}
	j.SetCookies(u, cookies)
	return true
}

// RawCookieHeader preserves measured cookie bytes rather than making a quoted
// Go Cookie.String value. Only values admitted by the response parser or the
// caller's explicit seed API enter this path; controls cannot inject a field.
func (j *keptJar) RawCookieHeader(u *url.URL) (string, bool) {
	if !j.chrome {
		return "", false
	}
	var pairs []string
	for _, c := range j.Cookies(u) {
		if strings.ContainsAny(c.Name+c.Value, "\r\n\x00;") {
			continue
		}
		if c.Name == "" {
			pairs = append(pairs, c.Value)
		} else {
			pairs = append(pairs, c.Name+"="+c.Value)
		}
	}
	return strings.Join(pairs, "; "), true
}
