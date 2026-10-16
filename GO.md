# TLS Forge for Go

The Go package is the native API behind the `tls-forge` CLI. With a current
measured profile it sends requests with a captured browser TLS ClientHello,
HTTP/1.1 wire casing and header order, HTTP/2 settings, pseudo-header order,
regular header order and browser headers. Older profiles remain compatible and
use the documented HTTP/1.1 fallback.

This document covers the public client API and the optional measurement, proxy,
echo, profile, capture, cookie, daemon and fingerprint packages.

## Requirements and installation

Go 1.26.9 or newer is required.

```bash
go get github.com/Sec-CH-Lemon/tls-forge
```

The import name is `tlsforge`, without the hyphen:

```go
import tlsforge "github.com/Sec-CH-Lemon/tls-forge"
```

No browser is needed to make requests. A Chromium-based browser is needed only
when calling the measurement APIs that launch one.

## Basic client

```go
package main

import (
	"fmt"
	"log"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

func main() {
	client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	response, err := client.Get("https://tls.browserleaks.com/json")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(response.Status)
	fmt.Println(response.Text())
}
```

`tlsforge.New()` without options uses `tlsforge.DefaultProfile`, currently
`chrome`. Unlike the CLI, the Go package does not automatically switch to a
locally installed profile; select `local` explicitly when that is desired.

`Client.Close()` releases idle connections and is final. Calls made after close
return an error; construct another client to create another identity.

A client resumes TLS sessions as its browser does. A measured profile's
handshake is the browser's first contact, and its spec ends with the
`pre_shared_key` the browser resumes with, which is sent only when there is a
session to resume: a client's new connection to a site that issued a ticket
resumes it, with that extension last, after the second GREASE one, and a JA4 of
one extension more, the same as Chrome's. `Client.CloseIdleConnections()`
closes the connections a client holds open between requests, so that the next
request opens a new one, which then resumes; the client stays open.

`Client.Fresh()` is a client of the same session, with the same profile, header
fields, cookie jar and warmed cookies, and connections and a TLS session cache
of its own. What it sends shares no connection with the client or any other
fresh one, and resumes none of their TLS sessions, which would tell a server
the two connections were one visitor. Through a proxy that hands every
connection an address, each fresh client comes out of an address of its own
while the session stays one. Close each when it is done with; that leaves the
client, and the session they share, as they were.

```go
fresh, err := client.Fresh()
if err != nil {
	return err
}
defer fresh.Close()
res, err := fresh.Get("https://example.com/")
```

## Client options

Every option below is passed to `tlsforge.New(options...)`.

| Option | Meaning |
|---|---|
| `WithProfile(name)` | Resolve a built-in, locally installed or runtime-registered profile by name. A profile file path is also accepted by the default registry. |
| `WithProfileValue(profile)` | Use a previously loaded `*profile.Profile` directly. |
| `WithProxy(url)` | Route requests through `http://`, `https://`, `socks5://` or `socks5h://`; credentials may be included in the URL. |
| `WithProxyHeader(h)` | Header fields to add to the `CONNECT` that opens every tunnel through an HTTP or HTTPS proxy, for a proxy that says more when asked, such as SOAX with `Respond-With`. They reach the proxy and no further. |
| `WithTimeout(duration)` | Set the transport request timeout. The default is `tlsforge.Timeout` (`30s`). Values must be positive and fit into a signed 32-bit millisecond value. |
| `WithMaxResponseBody(bytes)` | Limit the decompressed response retained in memory. The default is `tlsforge.DefaultMaxResponseBody` (64 MiB). Values must be positive and bounded. |
| `WithHeaders(header)` | Layer ordered default headers over the profile for every request. Existing names keep their profile position. |
| `WithCookies(cookies)` | Seed the client's jar with a warmed session. Cookies are matched to each request URL before being inserted. |
| `WithoutCookieJar()` | Disable cookie storage. Use this when another layer, such as an intercepting proxy, owns the `Cookie` header. |
| `WithCookieJar(jar)` | Supply an `fhttp.CookieJar`, for example to share or persist a jar. |
| `WithoutRedirects()` | Return the first 3xx response instead of following it. Redirects are followed by default as Chrome follows them ([Redirects](#redirects)): nineteen in a row, and the twentieth fails the request with `the 20th redirect was not followed`. |
| `WithoutSessionResumption()` | Keep no TLS session to resume, so that every connection is the cold handshake of a first contact. Without it a profile whose browser resumes does as the browser does; see below. |
| `WithInsecureSkipVerify()` | Disable upstream certificate verification. Intended for controlled local test endpoints. |
| `WithFixedExtensionOrder()` | Force a stable TLS extension order. Firefox and Safari profiles already select this behaviour automatically. |
| `WithRandomExtensionOrder()` | Force per-connection TLS extension shuffling. Chromium profiles select it automatically; the override is useful for custom Chromium profiles whose identity cannot be inferred. |
| `WithTransportOption(options...)` | Pass advanced `tls-client` transport options through when the wrapper does not expose them directly. |
| `WithLogger(logger)` | Write down what the client does, as it does it, to a `*slog.Logger`; see [Logging](#logging). |

Example:

```go
client, err := tlsforge.New(
	tlsforge.WithProfile("chrome_151"),
	tlsforge.WithProxy("http://user:pass@proxy.example:8080"),
	tlsforge.WithTimeout(20*time.Second),
	tlsforge.WithMaxResponseBody(8<<20),
	tlsforge.WithHeaders(tlsforge.NewHeader(
		"Accept-Language", "en-GB,en;q=0.9",
	)),
)
```

The extension-order options are explicit overrides. Normally the profile should
choose: Chromium shuffles its extension order, while Firefox and Safari keep it
stable.

## Requests

`Get(url)` is shorthand for `Do(&tlsforge.Request{URL: url})`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

response, err := client.Do(&tlsforge.Request{
	Context: ctx,
	Method:  "POST",
	URL:     "https://example.com/api",
	Header: tlsforge.NewHeader(
		"Content-Type", "application/json",
		"Referer", "https://example.com/",
	),
	Body: []byte(`{"hello":"world"}`),
	Cookies: []tlsforge.Cookie{
		{Name: "session", Value: "abc", Secure: true},
	},
})
```

| `Request` field | Meaning |
|---|---|
| `Context` | Cancels this request. `nil` means `context.Background()`. |
| `Method` | HTTP method. An empty value means `GET`. |
| `URL` | Required absolute request URL. |
| `Header` | Ordered headers layered over the profile. Existing names keep their original position; new names are appended. |
| `Body` | Raw request bytes. |
| `Cookies` | Cookies added to the jar before this request. |
| `Trace` | Optional hooks told each step the request takes on the wire; see [Tracing a request](#tracing-a-request). |
| `Logger` | A `*slog.Logger` this request is logged to instead of the client's, so that what it is for goes with every record of it; see [Logging](#logging). |
| `Browser` | A `*BrowserContext`: what in a browser the request stands for, a navigation, a form, `fetch()` or an XHR, sent as Chrome sends that; see [Browser contexts](#browser-contexts). `nil` sends it as a navigation typed into the address bar, as always. |

Use `Request.Context` for caller-driven cancellation and `WithTimeout` for the
transport deadline. A request ends when either limit is reached.

Do not construct a `Cookie` header manually unless replacing the jar's complete
output is intentional. `Request.Cookies` adds values to the jar, preserving
cookies received earlier in the session.

## Browser contexts

A request on its own goes out as a navigation typed into the address bar: the
profile's headers, with whatever the caller adds. Chrome sends other requests
differently. A form's POST has `Cache-Control`, `Origin` and its own order;
`fetch()` sends `Accept: */*`, `Sec-Fetch-Mode: cors` and a lower HTTP/2
priority; every request from a page carries `Referer` as the page's referrer
policy says, `Sec-Fetch-Site` as it stands to the page, and only the cookies
SameSite lets through. `Request.Browser` says which request this is, and it
goes out as Chrome 155 was measured sending it
(`testdata/chrome155-requests.json`).

```go
page := "https://shop.example/item/7"
response, err := client.Do(&tlsforge.Request{
	Method: "POST",
	URL:    "https://shop.example/api/cart",
	Header: tlsforge.NewHeader("Content-Type", "application/json"),
	Body:   []byte(`{"item":7}`),
	Browser: &tlsforge.BrowserContext{
		Kind:      tlsforge.KindFetch,
		Initiator: page,
	},
})
```

| `BrowserContext` field | Meaning |
|---|---|
| `Kind` | `KindNavigation`, `KindForm`, `KindFetch` or `KindXHR`. Required. |
| `Initiator` | The URL of the page that sends the request. Empty for a navigation is one typed into the address bar (`Sec-Fetch-Site: none`, `Sec-Fetch-User: ?1`, no `Referer`); a form, `fetch()` and an XHR need one. |
| `ReferrerPolicy` | The page's referrer policy. Empty is Chrome's default, `strict-origin-when-cross-origin`. |
| `Mode` | `fetch()`'s mode: `cors` (default), `no-cors` or `same-origin`. |
| `Credentials` | `fetch()`'s credentials: `same-origin` (default), `include` or `omit`; an XHR's `same-origin` or `include` (`withCredentials`). |

`client.Validate(req)` says what of this `Do` would refuse, without sending
anything: a command checks a whole list with it before it starts.

Each kind sends what a page can: a navigation sends no headers of the caller's
and no body; a form sends `GET`, or `POST` with a body and a `Content-Type` of
`application/x-www-form-urlencoded` (the default), `multipart/form-data;
boundary=...` or `text/plain`; `fetch()` and an XHR send the caller's headers
where Chrome puts a script's, but none a script cannot set (`Cookie`, `Origin`,
`Referer`, `Sec-*`, `User-Agent` and the rest of the Fetch standard's list).
Anything else is an error before anything is sent: a context with no kind, an
unknown policy or mode, a form or a script with no initiator, a request in
`same-origin` mode to another origin, one in `no-cors` mode with a method or
header CORS would ask about, and a `fetch()` of a URL with credentials in it. A method is sent as `fetch()` sends it: the
six it knows (`GET`, `POST` and the rest) in capitals, whatever case they were
given in. A context needs a profile of a Chromium
browser with headers to send: one of another browser, or a bare entry of the
transport's catalogue, is refused.

The cookies go as Chrome sends them. To another site, a navigation carries
cookies of `SameSite=None` and `Lax`, and those that named none; a form's POST
carries `None`, and those that named none only for two minutes after they were
set; `fetch()` and an XHR carry `None` alone, and none at all under
credentials `omit`, or under `same-origin` to another origin. To its own site
a request carries every cookie the jar holds for it.

A request CORS answers, `fetch()` or an XHR in `cors` mode to another origin,
goes as Chrome sends it. One with a method or a header CORS asks about goes
after a preflight, an `OPTIONS` that asks whether it may, with Chrome's
headers and no cookies; when the answer does not allow it (a status that is
not 2xx, a redirect, an `Access-Control-Allow-Origin` that is not the page's,
credentials not allowed, a method or header not listed), nothing more is sent
and `Do` returns an error that wraps `tlsforge.ErrCORS`. What a preflight
allowed is kept for as long as its `Access-Control-Max-Age` says (five
seconds when it says nothing, two hours at most, as in Chrome), for the
session: every client made `Fresh` from one shares it, another session has
its own. The answer to the request itself has to name the page's origin, or
`*` when no credentials went, and to allow credentials when they did; one
that does not is an error wrapping `ErrCORS`, and is not returned. What comes
back is returned whole: a page would see only the headers CORS exposes, and
nothing of a `no-cors` answer.

`fetch()` and an XHR go out on connections of their own: Chrome gives their
HTTP/2 `HEADERS` frame weight 220 where it gives a page 256, and the transport
puts one weight on every request it sends. They resume TLS sessions among
themselves, not with a client's other requests.

What a context does not do yet: the order of several headers a script set
(Chrome's renderer keeps them in a hash table where each name has its place,
so the order changes with the set of names; one goes where Chrome was
measured to put it), frames, and a form submitted by the user's click
(`Sec-Fetch-User`).

### Redirects

A redirect is followed as Chrome 155 was measured following one
(`testdata/chrome155-requests.json`), by every request:

- 301 and 302 make a `GET` of a `POST` alone, and 303 of every method but
  `HEAD`; each drops the body for good, with the headers that describe it.
  307 and 308 keep the method and the body. Go's transport made a `GET` of
  every method on the first three, and sent a dropped body again after a 307.
- A hop carries no `Referer` the request was not given. Go's transport sent
  the redirecting URL, query and all, to wherever it redirected. A request
  without a context keeps the `Referer` it was given on every hop.
- From a hop to another origin on, `Authorization` is gone and an `Origin`
  says `null`.
- Credentials a `Location` names are not sent: Chrome sends them only when
  the server asks for them.
- A Chromium profile's client hints go after `Sec-Fetch-Dest` once a request
  is redirected.
- Nineteen redirects are followed. The twentieth is not, and the request
  fails with `the 20th redirect was not followed`: on a chain that does not
  end, Chrome made twenty requests.

In a browser context each hop is worked out again from the hops before it:

- `Sec-Fetch-Site` goes by every URL asked, so a chain through another site
  is `cross-site` to its end, back home too. A navigation typed into the
  address bar is `none`, with `Sec-Fetch-User: ?1`, wherever it goes.
  SameSite goes by the page and the hop's URL alone, as Chrome's does.
- The `Referer` is worked out from the one before under the page's policy,
  so it only narrows, or under the policy a redirect's `Referrer-Policy`
  sets: the last name in it that is a policy, in any case.
- `Origin` says `null` once the request has gone across origins: for a
  request CORS answers, from an origin that is not the page's. A script's
  request that a redirect gives an `Origin` sends it after `Sec-Fetch-*`.
- CORS has to allow a redirect itself, and a hop that needs a preflight is
  asked about again at the URL it goes to, with its own `Sec-Fetch-Site`.
  `fetch()` in `same-origin` mode follows no redirect to another origin.
  To a URL with credentials in it, `fetch()` follows none but to the page's
  own origin with the page's own credentials, and a request in `cors` mode
  none across origins. Each of these is an error wrapping
  `tlsforge.ErrCORS`, with nothing more sent.

## Responses and errors

The response body is already decoded and read into memory, subject to the
configured maximum, which counts the decoded bytes. A body is decoded as Chrome
decodes it: from gzip, x-gzip, deflate (zlib, or the raw deflate some servers
send under that name), br and zstd, in the reverse of the order they were
applied. A body in a coding Chrome does not know either, one of a `206`'s
ranges, an empty one and the answer to a `HEAD` are left as they came, with
their `Content-Encoding`.

| `Response` field or method | Meaning |
|---|---|
| `Status` | HTTP status code |
| `URL` | Final URL after redirects |
| `Header` | Lower-cased header names mapped to every field value. They describe `Body`: once it is decoded, `content-encoding` and `content-length`, which described the bytes on the wire, are left out |
| `Body` | Decoded `[]byte` body |
| `Encoding` | The codings `Body` was decoded from, as a `Content-Encoding` field lists them (`gzip`, `gzip, br`), or empty when it is the bytes as they came |
| `Cookies` | `name=value` pairs the jar holds for the final URL |
| `Text()` | Body converted to `string` |
| `OK()` | `true` for status codes from 200 through 299 |

Repeated response headers remain separate:

```go
for _, value := range response.Header["set-cookie"] {
	fmt.Println(value)
}
```

When the decompressed body exceeds the configured limit, the error wraps
`tlsforge.ErrResponseTooLarge`:

```go
if errors.Is(err, tlsforge.ErrResponseTooLarge) {
	// Increase the limit only when retaining a larger body is intentional.
}
```

Other request, DNS, proxy, TLS, context and parsing failures are returned as
wrapped errors with a `tlsforge:` prefix. What an error from `New`, `Fresh` or
`Do` says has the password of the client's proxy taken out, and that of any
other URL it quotes, since it is printed by whoever gets it: a proxy URL that
cannot be read is otherwise quoted back whole. What it wraps is underneath,
for `errors.Is` and `errors.As`. The same is true of what `proxy.Options.OnError`
is given, and of the body of the 502 the proxy answers a failed request with.

## Tracing a request

A response says how a request ended. `Request.Trace` reports how it got there:
whether a name was looked up or a connection was already open, which address
answered, what the handshake settled on, and the header fields in the order
they were written.

```go
response, err := client.Do(&tlsforge.Request{
	URL: "https://example.com/",
	Trace: &tlsforge.Trace{
		GotConn: func(conn tlsforge.ConnInfo) {
			log.Printf("%s %s reused=%v via %s",
				conn.TLSVersion, conn.ALPN, conn.Reused, conn.RemoteAddr)
		},
		WroteRequest: func(sent tlsforge.Header, err error) {
			log.Printf("wrote %v", sent.Names())
		},
		Redirect: func(status int, location string) {
			log.Printf("%d -> %s", status, location)
		},
	},
})
```

| `Trace` hook | Called |
|---|---|
| `DNSStart(host)`, `DNSDone(addrs, err)` | Around a name lookup. A literal address or a reused connection has neither, and nor has a connection HTTP/2 dials apart from the request, as it does every one after a client's first to a host; [Logging](#logging) has those. |
| `ConnectStart(network, addr)`, `ConnectDone(network, addr, err)` | Around each TCP dial, which goes to the proxy when one is configured. A host with several addresses is dialled more than once, and the dials can overlap. |
| `GotConn(conn)` | When a connection is ready to carry the request, after its TLS handshake if it has one. |
| `WroteRequest(sent, err)` | When the request has been written. `sent` holds the fields in wire order with their wire spelling, including HTTP/2 pseudo-headers and the `Cookie` header added from the jar. |
| `FirstByte()` | When the first byte of the response arrives. |
| `Redirect(status, location)` | When a redirect is about to be followed. |

| `ConnInfo` field | Meaning |
|---|---|
| `Reused` | The connection had already carried a request, so nothing was looked up, dialled or negotiated for this one. |
| `RemoteAddr` | The other end of the socket; the proxy's address when a proxy is in use. |
| `TLSVersion`, `CipherSuite` | Names of what the handshake negotiated, such as `TLS 1.3` and `TLS_AES_128_GCM_SHA256`. Empty over plain HTTP. |
| `ALPN` | Negotiated protocol, `h2` or `http/1.1`. Empty over plain HTTP or when the server negotiated none. |
| `Resumed` | The handshake resumed an earlier TLS session. |
| `Tunnel` | Through an HTTP or HTTPS proxy, the number of the tunnel the connection goes through: the same for every request that goes out on it, so two requests with the same number came out of the same place. 0 without such a proxy. |
| `ProxyHeader` | Through an HTTP or HTTPS proxy, the header fields of its answer to the `CONNECT` that opened the tunnel, in lower case. Some proxies say there where the tunnel comes out, such as `X-Exit-IP`, which nothing else a request can see does. Nil without such a proxy and through SOCKS. |

Every hook is optional. Hooks run on the goroutines doing the work, so they can
be called concurrently and must not block; one can also arrive after `Do` has
returned, when a dial that lost a race finishes late. A redirected request calls
the hooks again for each hop. Header values are passed as sent, credentials
included, so redact them before logging.

The `tls-forge fetch --trace` flag is built on these hooks.

## Logging

`WithLogger` has a client write down what it does, as it does it: every step
of every request, from the lookup of a name to the end of the answer's body,
and the connections they go out on, through a proxy or not. It is for the
request that went wrong and is looked into afterwards, so each step is a record
of its own, and a request that failed says which step it was in.

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: tlsforge.LevelTrace,
}))
client, err := tlsforge.New(tlsforge.WithLogger(logger))
if err != nil {
	return err
}
defer client.Close()

response, err := client.Do(&tlsforge.Request{
	URL:    "https://example.com/",
	Logger: logger.With("job", 42),
})
```

| Level | What is logged |
|---|---|
| `slog.LevelInfo` | The client and its profile; a record for each request and each answer. |
| `slog.LevelWarn` | A request that failed: the step it gave up in as `phase` (`prepare`, `dns`, `connect`, `proxy`, `tls`, `send`, `wait`, `receive`, `body` or `redirect`), whether it was a timeout, and the error. A lookup that failed, a proxy that would not open a tunnel, with up to 1 KiB of what it said, a handshake with an HTTPS proxy that failed, and the redirect that is not followed, the twentieth. |
| `slog.LevelDebug` | Every step: each lookup with the addresses found, each TCP dial, the `CONNECT` to a proxy and its answer with the tunnel's number, the connection by its two ends with what its handshake settled on and the server's certificate, a connection reused, the header fields as written, pseudo-headers included, the first byte, the answer's header fields, each redirect, and when a client is made, made `Fresh`, closes its idle connections and is closed. The profile's JA4, HTTP/2 preface and header order when a client is made. |
| `tlsforge.LevelTrace` | The ClientHello of every new connection, with its JA4, JA4_r, JA3, every list in it and the length of its GREASE ECH payload as `ech_payload_bytes`, and every certificate of the server's chain. |

Every record carries `client`, the client's number in the process, and
`request`, the request's number on the client. A request with a `Logger` of its
own is logged there instead, with `client` added and without `request`, so that
a caller can say what the request is for. A record that ends a step says how
long the step took as `took`.

HTTP/2 dials every connection after a client's first to a host apart from the
request that needs it, so its lookup and dial are not the request's: they are
logged with the client's logger and `background=true`, and the request's
`connected` record names the same connection as `conn` and the same tunnel as
`tunnel`. A client given `WithTransportOption` dials the transport's own way,
since one of those options may be a dialer or a proxy; such dials then go
unlogged.

A log is made to be passed on, so it leaves out what a session is worth: a
proxy's password, cookie values, `Authorization` and `Proxy-Authorization`
credentials and the values of headers whose names contain `token`, `secret`,
`password` or `key` are written as `***`. Without `WithLogger`, or a request's
`Logger`, nothing is logged and nothing is spent on it.

## Ordered headers

Outgoing headers use `tlsforge.Header`, an ordered slice rather than a map.
Header order is part of the HTTP fingerprint.

```go
headers := tlsforge.NewHeader(
	"Referer", "https://example.com/",
	"X-Trace", "one",
)
headers.Set("Accept-Language", "en-US,en;q=0.9")
headers.Del("X-Trace")
```

| Method | Meaning |
|---|---|
| `NewHeader(name, value, ...)` | Build a header list from alternating pairs. A final unmatched item is ignored. Names are lower-cased. |
| `Get(name)` | Return the first value, case-insensitively. |
| `Values(name)` | Return every value for a name in wire order. |
| `Has(name)` | Report whether the name exists, including with an empty value. |
| `Set(name, value)` | Replace a value in place or append a new field. |
| `Add(name, value)` | Append another value without replacing an existing field. |
| `Del(name)` | Remove all fields with this name. |
| `Names()` | Return names in wire order. |
| `Clone()` | Return an independent copy. |
| `Merge(overrides)` | Apply overrides while preserving positions from the base list. |

`client.Headers()` returns a copy of the effective default request headers.

## Cookies and sessions

The default jar uses the public suffix list and applies normal domain, path,
secure and expiry rules. A cookie lives at most 400 days, as in Chrome: a later
`Expires` or a longer `Max-Age` is cut to that.

```go
client, err := tlsforge.New(tlsforge.WithCookies([]tlsforge.Cookie{
	{
		Name:     "session",
		Value:    "abc",
		Domain:   ".example.com",
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	},
}))
```

| `Cookie` field | Meaning |
|---|---|
| `Name`, `Value` | Cookie pair |
| `Domain` | Parent or host domain. Empty means the request host. |
| `HostOnly` | The cookie goes to the host of `Domain` alone, as one set without a `Domain` attribute does, and not to its subdomains. Seeded, it is filed for that host only. |
| `Path` | Cookie path. Empty defaults to `/` when seeded. |
| `Secure` | Send only over HTTPS. |
| `HTTPOnly` | Preserve the HttpOnly attribute in exported session data. |
| `Expires` | Expiration time; zero represents a session cookie. |
| `SameSite` | `strict`, `lax`, `none`, or empty when the server named none. Kept and written down; not enforced when a request is sent. |

`client.CookiesFor(url)` returns the cookies the jar would send to a URL, and
`client.Cookies(url)` is the same method by its older name. `client.AllCookies()`
returns every cookie the jar holds, for every host, sorted by domain, path and
name: that is what a session is written down from, so a cookie set by a
redirect's host is kept as well as those of the URLs asked for. Each comes with
its scope, a session cookie with no expiry and the `SameSite` the server set.
All three return `nil` when the jar is disabled. A jar supplied with
`WithCookieJar` is wrapped to keep what a jar does not say of a cookie, so
`AllCookies` lists the cookies set through this client; a jar that does not
report where it filed a cookie, as `tls_client.NewCookieJar` does not, is
listed as holding none.

The `cookie` subpackage reads and writes project JSON session files, flat
browser-export JSON and Netscape cookies.txt data, keeping each cookie's scope
(`host_only`, the browser export's `hostOnly`, the Netscape include-subdomains
column), its lifetime (a browser export's `session`) and its `SameSite`. A file
of version 1, written before the scope was kept, reads every cookie as its
domain's, as it did then; `File.Unscoped` says so, and the file is written back
as version 2:

```go
data, err := os.ReadFile("cookies.json")
file, err := cookie.Load(data)
set, err := file.Pick("warm-eu", rand.New(rand.NewSource(1)))
```

## Identity and concurrency

One `Client` represents one browser identity:

- one TLS/HTTP profile;
- one cookie jar;
- one proxy and exit IP;
- one reusable connection pool.

The Go client is safe for concurrent use. For multiple identities, create a
pool of clients, normally one per proxy, instead of sharing one jar across
several exits.

```go
clients := make([]*tlsforge.Client, len(proxies))
for i, proxyURL := range proxies {
	clients[i], err = tlsforge.New(tlsforge.WithProxy(proxyURL))
	if err != nil {
		return err
	}
	defer clients[i].Close()
}
```

## Profiles

Available profile names can be listed with `profile.Names()` or
`tls-forge profiles`.

```go
for _, name := range profile.Names() {
	fmt.Println(name)
}
```

`client.Profile()` returns the profile the client is actually impersonating,
which is the one to ask when the name was resolved for you — `"chrome"` picks
the newest measured Chrome, and this is how to find out which that was:

```go
fmt.Println(client.Profile().Name)
```

Load a captured profile directly:

```go
data, err := os.ReadFile("my-chrome.json")
if err != nil {
	return err
}

measured, err := profile.Load(data)
if err != nil {
	return err
}

client, err := tlsforge.New(tlsforge.WithProfileValue(measured))
```

Or register it under its embedded name:

```go
if err := profile.Register(measured); err != nil {
	return err
}
client, err := tlsforge.New(tlsforge.WithProfile(measured.Name))
```

`profile.DefaultDir()` is the per-user profile directory. The
`TLSFORGE_PROFILES` environment variable overrides it. A custom
`profile.Registry` can use `SetDir` without modifying the package default.

`profile.Profile.HTTP1` is optional. When present, its `HeaderOrder` preserves
the exact wire spelling measured from the browser and its `Headers` carries
HTTP/1.1-specific value overrides. The client chooses this layout only after
the connection negotiates HTTP/1.1; HTTP/2 continues to use the profile's
existing lower-case header block. Profiles created before this field existed
remain valid and use the legacy canonical HTTP/1.1 spelling.

## Measuring and comparing

`MeasureBrowser` launches a real browser with temporary profiles and records
what it sends to a local echo server. HTTP/1.1 and HTTP/2 use independent cold
top-level navigations, so capture machinery does not become part of the
`Sec-Fetch-*` fingerprint.

```go
capture, err := tlsforge.MeasureBrowser(ctx, tlsforge.MeasureOptions{
	Browser:  "chrome",
	Headless: true,
	Timeout:  2 * time.Minute,
	BrowserArgs: []string{
		"--no-sandbox",
	},
})
```

| `MeasureOptions` field | Meaning |
|---|---|
| `Browser` | `chrome`, `chromium`, `edge`, `brave`, or an executable path. Empty searches automatically. |
| `Headless` | Use modern headless mode. Headed mode is the default. |
| `Timeout` | Bound the complete launch and capture. Zero means two minutes. |
| `BrowserArgs` | Extra browser process arguments appended last. |

Measurement functions:

| Function | Meaning |
|---|---|
| `MeasureBrowser(ctx, options)` | Start a temporary local echo server and measure a browser. |
| `MeasureBrowserAt(ctx, server, options)` | Measure against an existing `*echo.Server`. |
| `MeasureSelf(ctx, clientOptions...)` | Measure the tls-forge client locally. |
| `MeasureSelfAt(ctx, server, clientOptions...)` | Measure the client against an existing server. |
| `CompareToBrowser(ctx, measureOptions, clientOptions...)` | Measure browser and client on one server and compare them. |
| `Compare(browserCapture, clientCapture)` | Compare two captures obtained earlier. |

```go
comparison, err := tlsforge.CompareToBrowser(
	ctx,
	tlsforge.MeasureOptions{Browser: "chrome", Headless: true},
	tlsforge.WithProfile("chrome"),
)
if err != nil {
	return err
}
if !comparison.OK() {
	fmt.Print(comparison.String())
}
```

The comparison covers the ClientHello field by field, protocol mismatch, the
HTTP/1.1 method and version with exact header casing/order/values, HTTP/2
settings, PRIORITY frames and the priority on HEADERS, pseudo-header order and
values but `:path` and `:authority`, normal header order and normal header
values. `fingerprint.TLSFields` lists
what a ClientHello is compared on and how: what the browser draws for every
connection by its shape (where GREASE goes, how long each key is, ECH's cipher
suite, the binders of `pre_shared_key`), and the length of the ECH payload,
which Chrome draws too, as a `Field` that `Varies`: shown, never compared.
`Report.Unchecked` lists an extension both sides send that no rule describes,
with contents that differ, and a field one side did not record; `OK()` is
false while it is not empty. `fingerprint.ParsePreamble` reads the frames a
client sent before its first request was whole (`capture.HTTP2.RawFrames`),
and `fingerprint.Representations` how each field of a header block was
written.
`fingerprint.CompareTLS`, `fingerprint.CompareHTTP1` and
`fingerprint.CompareHTTP2` expose the three comparisons independently.
`Comparison.Measured` says what a comparison was made of: the browser's build
and platform, its `Mode` (`ModeHeadless`, `ModeWindow`, `ModeManual`, or empty
for captures compared after the fact) and the `Scenario` compared.
`Comparison.Manifest` is `fingerprint.Manifest()`: the rule each field was
compared by.

## Programmatic proxy

The `proxy` package exposes the same intercepting proxy as the CLI.

```go
ca, err := proxy.LoadOrCreateCA("ca.pem", "ca.key")
if err != nil {
	return err
}

transport, err := tlsforge.New(tlsforge.WithoutCookieJar())
if err != nil {
	return err
}
defer transport.Close()

server, err := proxy.Start(proxy.Options{
	Addr:           "127.0.0.1:8080",
	CA:             ca,
	Client:         transport,
	MaxRequestBody: 16 << 20,
	OnError:        func(err error) { log.Print(err) },
})
if err != nil {
	return err
}
defer server.Close()
```

| `proxy.Options` field | Meaning |
|---|---|
| `Addr` | Listen address. Empty means `127.0.0.1:0`. |
| `CA` | Required authority used to sign per-host certificates. |
| `Client` | Required outbound client. |
| `MaxRequestBody` | Buffered request-body limit. Zero uses `proxy.DefaultMaxRequestBody` (16 MiB). |
| `OnError` | Optional callback for per-connection failures. |

`LoadOrCreateCA` creates material only when both files are absent. Existing
certificate and key files must match, be currently valid and form a usable
self-signed CA. Treat the private key as a sensitive credential. The proxy has
no incoming-client authentication; protect any non-loopback `Addr` with a
firewall or authenticated tunnel. Incoming connections close after 30 seconds
without read or write progress. A request's header has 10 seconds from its
first byte and 1 MiB, past which it is answered 431, and the TLS handshake in a
tunnel has 10 seconds; a body is bounded by `MaxRequestBody` and by the 30
seconds of each read, not by a time for the whole. At most 1024 connections are
served at once; the next waits to be accepted. Each authority caches at most
1024 generated leaf certificates and evicts the oldest hostname when full.

## Local echo server

The `echo` package records ClientHello and HTTP behaviour from local test
connections.

```go
server, err := echo.Start(
	echo.WithAddr("127.0.0.1:0"),
	echo.WithHost("localhost"),
	echo.WithSessionTickets(false),
)
if err != nil {
	return err
}
defer server.Close()

fmt.Println(server.URL())
```

| Echo option | Meaning |
|---|---|
| `WithAddr(address)` | Listen address; default is an available loopback port. |
| `WithHost(hostname)` | Hostname used in the generated URL, certificate and SNI. |
| `WithSessionTickets(enabled)` | Enable or disable TLS session resumption; disabled by default. |

Useful methods include `URL()`, `Addr()`, `Certificate()`, `Sessions()` and
`Await(ctx)`. A `Session` can be rendered as a `capture.Capture`. `Sessions()`
is the latest 128 connections, and the server keeps no more than the latest
128 pages served and completed captures either. Silent connections close
after 30 seconds; the deadline rolls forward while traffic makes progress. A
TLS handshake has 10 seconds in all and a request 10 seconds from its first
byte, and at most 128 connections are served at once. An HTTP/1.1 request it cannot read whole, as RFC 9112 has it,
is answered with a 4xx or 5xx that says why, and its connection closed. Over
HTTP/2 it keeps to the client's flow-control windows and header table, holds
at most 100 streams and 512 KiB per connection, and ends a connection that
breaks the protocol with a `GOAWAY` that says why. The echo protocol has no authentication. A non-loopback
`WithAddr` is an explicit trust-boundary expansion and must be protected by a
firewall or authenticated tunnel.

## Other packages

| Package | Purpose |
|---|---|
| `browser` | Find and launch Chrome, Chromium, Edge or Brave with a temporary profile. `browser.Options` contains `Headless` and `Args`. Closing it, or the end of its context, ends every process the browser started, not only its own. |
| `capture` | Serializable representation of observed TLS, HTTP/1, HTTP/2 and browser navigator data. |
| `cookie` | Load, select, merge and encode warmed cookie sessions. |
| `daemon` | JSON Lines request/response transport used by non-Go SDKs. `Serve` accepts any compatible client, and `ServeContext` stops when its context is done: no more requests are taken, the one in flight is cancelled and answered with why, and it returns the context's error. The input and output stay the caller's: a read already waiting goes on until the input ends, and a write waiting on an output with `SetWriteDeadline` is given up 250 ms later. |
| `fingerprint` | Parse ClientHello records, calculate JA3/JA4 and compare TLS, HTTP/1.1 or HTTP/2 structures. |
| `profile` | Load, create, register and resolve browser profiles. |
| `proxy` | Programmatic intercepting proxy and certificate authority. |
| `echo` | Local TLS/HTTP measurement server. |

Use `go doc` for the exported data structures in these lower-level packages:

```bash
go doc github.com/Sec-CH-Lemon/tls-forge
go doc github.com/Sec-CH-Lemon/tls-forge/fingerprint
go doc github.com/Sec-CH-Lemon/tls-forge/profile
```

## Development

```bash
make test   # race detector
make cover  # 100% statement coverage gate
make vet
make lint
```

The project is licensed under Apache-2.0; see [`LICENSE`](LICENSE),
[`NOTICE`](NOTICE) and [`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt).
