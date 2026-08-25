// Package cookie is the file a warmed session is kept in.
//
// Warming a session costs something: a browser, a challenge, sometimes a
// person. Once it is warm it is worth keeping, and worth reusing across runs
// and machines, which means it has to be written down in a shape that survives
// the trip.
//
// A file holds SETS rather than cookies, because a session is the unit that was
// warmed. Twenty sessions in one file are twenty identities to spread a run
// over, not one pile of cookies to mix.
package cookie

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Cookie is one cookie as a browser holds it.
//
// More than a name and a value, because a warmed session is not portable
// without the rest: the domain decides what it is sent to, Secure and HttpOnly
// are part of what the server set, and an expiry that has passed is a cookie
// that will be ignored.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain,omitempty"`
	Path     string    `json:"path,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HTTPOnly bool      `json:"http_only,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
}

// MarshalJSON leaves out an expiry that was never set.
//
// encoding/json's omitempty has no opinion about a struct, so a session cookie
// would otherwise be written down as expiring in the year one, which is both
// noise and a lie.
func (c Cookie) MarshalJSON() ([]byte, error) {
	type plain Cookie
	if c.Expires.IsZero() {
		return json.Marshal(struct {
			plain
			Expires *time.Time `json:"expires,omitempty"`
		}{plain: plain(c)})
	}
	return json.Marshal(plain(c))
}

// Expired reports whether this cookie is past its date. A cookie with no date
// is a session cookie and never expires on its own.
func (c Cookie) Expired(at time.Time) bool {
	return !c.Expires.IsZero() && !c.Expires.After(at)
}

// browserCookie is the same thing spelled the way a browser extension exports
// it. Accepted on the way in, because that is where a warmed session usually
// comes from, and nobody should have to rewrite one to use it.
type browserCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`

	Domain string `json:"domain"`
	Path   string `json:"path"`
	Secure bool   `json:"secure"`

	// Two spellings of the same flag, and two of the same date: the underscored
	// ones are this file's own, the others are what a browser writes.
	HTTPOnlySnake bool `json:"http_only"`
	HTTPOnlyCamel bool `json:"httpOnly"`

	Expires        *time.Time `json:"expires"`
	ExpirationDate *float64   `json:"expirationDate"`
}

func (b browserCookie) cookie() Cookie {
	c := Cookie{
		Name:     b.Name,
		Value:    b.Value,
		Domain:   b.Domain,
		Path:     b.Path,
		Secure:   b.Secure,
		HTTPOnly: b.HTTPOnlySnake || b.HTTPOnlyCamel,
	}
	switch {
	case b.Expires != nil:
		c.Expires = *b.Expires
	case b.ExpirationDate != nil:
		// Seconds since the epoch, with a fraction, which is how a browser
		// writes an expiry.
		seconds, fraction := int64(*b.ExpirationDate), *b.ExpirationDate-float64(int64(*b.ExpirationDate))
		c.Expires = time.Unix(seconds, int64(fraction*float64(time.Second))).UTC()
	}
	return c
}

// Set is one warmed session.
type Set struct {
	// ID names it, so a run can ask for this one.
	ID string `json:"id"`
	// Note is for whoever opens the file in six months.
	Note    string    `json:"note,omitempty"`
	Warmed  time.Time `json:"warmed,omitempty"`
	Cookies []Cookie  `json:"cookies"`
}

// MarshalJSON leaves out a warming date that was never set, for the reason
// Cookie.MarshalJSON does.
func (s Set) MarshalJSON() ([]byte, error) {
	type plain Set
	if s.Warmed.IsZero() {
		return json.Marshal(struct {
			plain
			Warmed *time.Time `json:"warmed,omitempty"`
		}{plain: plain(s)})
	}
	return json.Marshal(plain(s))
}

// Live is the set with its expired cookies left out.
func (s Set) Live(at time.Time) Set {
	kept := make([]Cookie, 0, len(s.Cookies))
	for _, c := range s.Cookies {
		if !c.Expired(at) {
			kept = append(kept, c)
		}
	}
	s.Cookies = kept
	return s
}

// File is what a cookies.json holds.
type File struct {
	// Version is written so a later format can be told from this one. Nothing
	// is rejected for it: a file from the future is more likely to be readable
	// than not, and refusing to try is not the reader's call to make.
	Version int   `json:"version"`
	Sets    []Set `json:"sets"`
}

const currentVersion = 1

// Load reads a cookie file.
//
// Three shapes are accepted, because a warmed session arrives from wherever it
// was warmed: this file's own object, a bare array of sets, and a bare array of
// cookies, which is what a browser extension exports and becomes one set.
func Load(data []byte) (*File, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("cookie: the file is empty")
	}

	// A cookies.txt before anything else: it is the one format everything
	// agrees on, and it looks nothing like JSON.
	if looksNetscape(trimmed) {
		return loadNetscape(trimmed)
	}

	if strings.HasPrefix(trimmed, "{") {
		var file File
		if err := decodeStrict(trimmed, &file); err != nil {
			return nil, fmt.Errorf("cookie: %w", err)
		}
		return validate(named(&file))
	}

	// An array: of sets when an entry has a `cookies` member, otherwise of
	// cookies. Inspecting the member rather than its length keeps an empty set a
	// set, and keeps an empty array an empty file instead of inventing one set.
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &entries); err == nil {
		for _, entry := range entries {
			if _, isSet := entry["cookies"]; !isSet {
				continue
			}
			var sets []Set
			if err := decodeStrict(trimmed, &sets); err != nil {
				return nil, fmt.Errorf("cookie: %w", err)
			}
			return validate(named(&File{Version: currentVersion, Sets: sets}))
		}
		if len(entries) == 0 {
			return &File{Version: currentVersion}, nil
		}
	}

	var flat []browserCookie
	if err := json.Unmarshal([]byte(trimmed), &flat); err != nil {
		return nil, fmt.Errorf("cookie: %w", err)
	}
	one := Set{ID: "1"}
	for _, b := range flat {
		if b.Name == "" {
			return nil, fmt.Errorf("cookie: a cookie in the list has no name")
		}
		one.Cookies = append(one.Cookies, b.cookie())
	}
	return validate(&File{Version: currentVersion, Sets: []Set{one}})
}

func decodeStrict(data string, value any) error {
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("more than one JSON value")
		}
		return err
	}
	return nil
}

func validate(file *File) (*File, error) {
	ids := map[string]bool{}
	for _, set := range file.Sets {
		if ids[set.ID] {
			return nil, fmt.Errorf("cookie: more than one set has id %q", set.ID)
		}
		ids[set.ID] = true
		for _, cookie := range set.Cookies {
			if cookie.Name == "" {
				return nil, fmt.Errorf("cookie: set %q has a cookie with no name", set.ID)
			}
		}
	}
	return file, nil
}

// named gives every set an id, so a set can always be asked for by one.
func named(f *File) *File {
	if f.Version == 0 {
		f.Version = currentVersion
	}
	for i := range f.Sets {
		if f.Sets[i].ID == "" {
			f.Sets[i].ID = fmt.Sprintf("%d", i+1)
		}
	}
	return f
}

// Add puts a set in the file under an id nothing else is using.
//
// Unique because --cookie-set takes one: two sets answering to the same name
// make the flag a coin toss. The stamp a caller offers is only a starting
// point, since two runs can finish inside one second.
func (f *File) Add(set Set) {
	taken := map[string]bool{}
	for _, existing := range f.Sets {
		taken[existing.ID] = true
	}
	if set.ID == "" {
		set.ID = "1"
	}
	unique := set.ID
	for n := 2; taken[unique]; n++ {
		unique = fmt.Sprintf("%s-%d", set.ID, n)
	}
	set.ID = unique
	f.Sets = append(f.Sets, set)
}

// Encode writes the file back out.
//
// No error to return: encoding/json fails on types this format does not have
// and cannot grow without someone noticing, and a signature that promises a
// failure nobody can produce is a branch no test can reach.
func (f *File) Encode() []byte {
	if f.Version == 0 {
		f.Version = currentVersion
	}
	data, _ := json.MarshalIndent(f, "", "  ")
	return append(data, '\n')
}

// IDs are the sets in the file, in order.
func (f *File) IDs() []string {
	ids := make([]string, 0, len(f.Sets))
	for _, s := range f.Sets {
		ids = append(ids, s.ID)
	}
	return ids
}

// Pick chooses a set: the one named, or one at random when no name is given.
//
// Random rather than the first, because a file of warmed sessions exists to be
// spread over. Deterministic when there is only one, which is the common case
// and should not need a seed to be repeatable.
func (f *File) Pick(id string, pick *rand.Rand) (Set, error) {
	if len(f.Sets) == 0 {
		return Set{}, fmt.Errorf("cookie: the file holds no sets")
	}
	if id == "" {
		if len(f.Sets) == 1 {
			return f.Sets[0], nil
		}
		return f.Sets[pick.Intn(len(f.Sets))], nil
	}
	for _, s := range f.Sets {
		if s.ID == id {
			return s, nil
		}
	}
	known := f.IDs()
	sort.Strings(known)
	return Set{}, fmt.Errorf("cookie: no set called %q; the file has %s",
		id, strings.Join(known, ", "))
}

// Parse reads a cookie given on a command line, as `name=value`.
//
// Only the two halves, because that is all a command line can carry without
// becoming its own format. Anything needing a domain or an expiry belongs in a
// file.
func Parse(pair string) (Cookie, error) {
	name, value, found := strings.Cut(pair, "=")
	name = strings.TrimSpace(name)
	if !found || name == "" {
		return Cookie{}, fmt.Errorf("cookie: expected \"name=value\", got %q", pair)
	}
	return Cookie{Name: name, Value: strings.TrimSpace(value)}, nil
}
