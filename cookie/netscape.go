package cookie

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The Netscape cookie file, better known as cookies.txt.
//
// The one format everything agrees on: curl writes it with -c and reads it with
// -b, wget and yt-dlp use it, and every "export cookies" browser extension
// offers it. A warmed session handed over as one of these will be understood by
// whatever is on the other end, which is not true of any JSON shape.
//
// Seven tab-separated fields:
//
//	domain  includeSubdomains  path  secure  expires  name  value
//
// with two conventions that are not obvious. An expiry of 0 means a session
// cookie. And a domain prefixed `#HttpOnly_` marks the cookie HttpOnly, which
// reads like a comment and is not one; a parser that skips every line beginning
// with `#` silently drops exactly the cookies that matter most.

const httpOnlyPrefix = "#HttpOnly_"

// looksNetscape reports whether this is a cookies.txt rather than JSON.
//
// By content, not by the file's name. The two are not near each other: JSON
// starts with a brace or a bracket and this never does, so there is nothing
// here to guess at.
func looksNetscape(body string) bool {
	trimmed := strings.TrimLeft(body, " \t\r\n")
	return trimmed != "" && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[")
}

// loadNetscape reads a cookies.txt into one set.
//
// One set, because the format has no way to say otherwise: it is a jar written
// down, and a jar is one session.
func loadNetscape(body string) (*File, error) {
	set := Set{ID: "1", Note: "read from a Netscape cookie file"}
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimRight(scanner.Text(), "\r\n")
		if strings.TrimSpace(text) == "" {
			continue
		}

		httpOnly := strings.HasPrefix(text, httpOnlyPrefix)
		if httpOnly {
			text = strings.TrimPrefix(text, httpOnlyPrefix)
		} else if strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}

		fields := strings.Split(text, "\t")
		if len(fields) < 7 {
			return nil, fmt.Errorf("cookie: line %d has %d fields, want 7 separated by tabs",
				line, len(fields))
		}
		expires, err := strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cookie: line %d: %q is not an expiry", line, fields[4])
		}
		if fields[5] == "" {
			return nil, fmt.Errorf("cookie: line %d has no name", line)
		}

		c := Cookie{
			Name:     fields[5],
			Value:    fields[6],
			Domain:   fields[0],
			Path:     fields[2],
			Secure:   strings.EqualFold(strings.TrimSpace(fields[3]), "TRUE"),
			HTTPOnly: httpOnly,
		}
		// Zero is how this format spells a session cookie, and a session cookie
		// has no date rather than one in 1970.
		if expires > 0 {
			c.Expires = time.Unix(expires, 0).UTC()
		}
		set.Cookies = append(set.Cookies, c)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cookie: %w", err)
	}
	if len(set.Cookies) == 0 {
		return nil, fmt.Errorf("cookie: the file holds no cookies")
	}
	return &File{Version: currentVersion, Sets: []Set{set}}, nil
}

// EncodeNetscape writes a set as a cookies.txt, for handing to curl or to
// anything else that reads them.
//
// One set, because the format cannot hold two: it is a jar, and a jar is one
// identity. The caller chooses which.
func (s Set) EncodeNetscape() []byte {
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	b.WriteString("# Written by tls-forge. Every line is seven tab-separated fields.\n\n")

	for _, c := range s.Cookies {
		domain := c.Domain
		if c.HTTPOnly {
			domain = httpOnlyPrefix + domain
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		var expires int64
		if !c.Expires.IsZero() {
			expires = c.Expires.Unix()
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			domain,
			upper(strings.HasPrefix(c.Domain, ".")),
			path,
			upper(c.Secure),
			expires,
			c.Name,
			c.Value,
		)
	}
	return []byte(b.String())
}

func upper(yes bool) string {
	if yes {
		return "TRUE"
	}
	return "FALSE"
}
