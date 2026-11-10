# Go package `cookie`

Generated from current exported declarations and Go doc comments. See the [package index](../go-api.md).

```go linenums="0"
import "github.com/Sec-CH-Lemon/tls-forge/cookie"
```

Package cookie is the file a warmed session is kept in.

Warming a session costs something: a browser, a challenge, sometimes a person. Once it is warm it is worth keeping, and worth reusing across runs and machines, which means it has to be written down in a shape that survives the trip.

A file holds SETS rather than cookies, because a session is the unit that was warmed. Twenty sessions in one file are twenty identities to spread a run over, not one pile of cookies to mix.

## Types

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Cookie { .tf-symbol }

<div class="tf-ref__docs" markdown>

Cookie is one cookie as a browser holds it.

More than a name and a value, because a warmed session is not portable without the rest: the domain decides what it is sent to, and whether to its subdomains as well, Secure, HttpOnly and SameSite are part of what the server set, and an expiry that has passed is a cookie that will be ignored, while no expiry at all is a session cookie.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
	// HostOnly says the cookie goes to the host of Domain alone, as one set
	// without a Domain attribute does. Without it a cookie is its domain's,
	// and goes to every subdomain too.
	HostOnly bool      `json:"host_only,omitempty"`
	Path     string    `json:"path,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HTTPOnly bool      `json:"http_only,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	// SameSite is "strict", "lax", "none", or empty when the server named none.
	SameSite string `json:"same_site,omitempty"`
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Parse() { .tf-member }

<div class="tf-ref__docs" markdown>

Parse reads a cookie given on a command line, as `name=value`.

Only the two halves, because that is all a command line can carry without becoming its own format. Anything needing a domain or an expiry belongs in a file.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func Parse(pair string) (Cookie, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Cookie.Expired() { .tf-member }

<div class="tf-ref__docs" markdown>

Expired reports whether this cookie is past its date. A cookie with no date is a session cookie and never expires on its own.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c Cookie) Expired(at time.Time) bool
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Cookie.MarshalJSON() { .tf-member }

<div class="tf-ref__docs" markdown>

MarshalJSON leaves out an expiry that was never set.

encoding/json's omitempty has no opinion about a struct, so a session cookie would otherwise be written down as expiring in the year one, which is both noise and a lie.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (c Cookie) MarshalJSON() ([]byte, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### File { .tf-symbol }

<div class="tf-ref__docs" markdown>

File is what a cookies.json holds.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type File struct {
	// Version is written so a later format can be told from this one. Nothing
	// is rejected for it: a file from the future is more likely to be readable
	// than not, and refusing to try is not the reader's call to make.
	//
	// Version 1 did not keep which cookies were their host's alone: every
	// cookie in it is its domain's, as it was read then, and Unscoped says so.
	Version int   `json:"version"`
	Sets    []Set `json:"sets"`
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Load() { .tf-member }

<div class="tf-ref__docs" markdown>

Load reads a cookie file.

Three shapes are accepted, because a warmed session arrives from wherever it was warmed: this file's own object, a bare array of sets, and a bare array of cookies, which is what a browser extension exports and becomes one set.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func Load(data []byte) (*File, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### File.Add() { .tf-member }

<div class="tf-ref__docs" markdown>

Add puts a set in the file under an id nothing else is using.

Unique because --cookie-set takes one: two sets answering to the same name make the flag a coin toss. The stamp a caller offers is only a starting point, since two runs can finish inside one second.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f *File) Add(set Set)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### File.Encode() { .tf-member }

<div class="tf-ref__docs" markdown>

Encode writes the file back out, in this version of the format, which reads the sets of an older one as that one did.

It fails rather than write less than it was given. A date this format cannot hold, one after the year 9999 that a caller put in a Cookie, made it return an empty document without a word, which a caller then wrote over a file of good sessions: a caller writing the result over a file writes nothing when this fails.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f *File) Encode() ([]byte, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### File.IDs() { .tf-member }

<div class="tf-ref__docs" markdown>

IDs are the sets in the file, in order.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f *File) IDs() []string
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### File.Pick() { .tf-member }

<div class="tf-ref__docs" markdown>

Pick chooses a set: the one named, or one at random when no name is given.

Random rather than the first, because a file of warmed sessions exists to be spread over. Deterministic when there is only one, which is the common case and should not need a seed to be repeatable.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f *File) Pick(id string, pick *rand.Rand) (Set, error)
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### File.Unscoped() { .tf-member }

<div class="tf-ref__docs" markdown>

Unscoped says the file was written before a cookie's scope was kept, so that a cookie its host's alone when it was set reads as its domain's and is sent to subdomains too. Written again, it keeps the scope of what is in it.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (f *File) Unscoped() bool
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

### Set { .tf-symbol }

<div class="tf-ref__docs" markdown>

Set is one warmed session.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
type Set struct {
	// ID names it, so a run can ask for this one.
	ID string `json:"id"`
	// Note is for whoever opens the file in six months.
	Note    string    `json:"note,omitempty"`
	Warmed  time.Time `json:"warmed,omitempty"`
	Cookies []Cookie  `json:"cookies"`
}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Set.EncodeNetscape() { .tf-member }

<div class="tf-ref__docs" markdown>

EncodeNetscape writes a set as a cookies.txt, for handing to curl or to anything else that reads them.

One set, because the format cannot hold two: it is a jar, and a jar is one identity. The caller chooses which.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s Set) EncodeNetscape() []byte
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Set.Live() { .tf-member }

<div class="tf-ref__docs" markdown>

Live is the set with its expired cookies left out.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s Set) Live(at time.Time) Set
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

#### Set.MarshalJSON() { .tf-member }

<div class="tf-ref__docs" markdown>

MarshalJSON leaves out a warming date that was never set, for the reason Cookie.MarshalJSON does.

</div>

</div>

<div class="tf-ref__code" markdown>

```go linenums="0"
func (s Set) MarshalJSON() ([]byte, error)
```

</div>

</div>
