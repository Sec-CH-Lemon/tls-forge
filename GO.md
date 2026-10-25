# TLS Forge for Go

## Engine/profile compatibility (1.0.0)

The compiled engine version is **1.0.0**, independently of the browser build and
profile format **schema 4**. Every executable profile must declare the exact,
non-negative integer `engine_major: 1`. Engines reject profiles from both older
and newer majors, including files with no declaration. Schema, filename, browser
name, User-Agent and catalogue fallback cannot supply compatibility implicitly.
The check runs before request-related DNS, proxy, TCP, TLS or QUIC I/O.

```json
{"schema": 4, "engine_major": 1, "name": "my-browser"}
```

This illustrates metadata only; a complete profile still needs captured TLS/HTTP
data and the explicit `behavior` object. Browser values and selections stay in
JSON. Major selection is anchored to the latest published stable release:
`latest_released_major + 1` for an engine change, once for the whole next release.
The current candidate is **unreleased1.0.0** after0.2.2. Further runtime changes
before1.0.0 is published stay in major1; after publication, the next engine change
targets2.0.0. Existing primitives can be configured by JSON without an engine bump. Versioned CLI, daemon and SDK identity
must agree; `engine/version.json` is the compiled authority. Release builds refuse
a different version stamp. Go v1 uses the unsuffixed module path; `/v2` starts with major2. The release anchor and pending status are recorded in `engine/version.json`.

`profile.Load` is the execution loader. `profile.Inspect` reads an archive offline
without declaring it compatible. `Save` and `Clone` preserve the original
`engine_major`, including absence; they never retag an old profile. Explicit
migration creates a candidate while preserving original capture provenance:

```go
old, err := profile.Inspect(originalJSON) // offline; handle err
candidate, err := old.Migrate("my-browser-engine-1") // handle err
migratedJSON, err := candidate.Save() // save to a separate destination
```

Preserve the original file. Migration is not browser equivalence acceptance;
repeat the relevant actual browser/wire checks before relying on its behavior.
The 15 shipped profiles and all backend catalogue policies have explicit unreleased engine-1
migration provenance; older captured browser builds are not new measurements.
A bare catalogue preset still supplies no browser headers.

For a new programmatically created Go profile, explicitly set
`EngineMajor: profile.Major(tlsforge.EngineMajor())`. Never use this assignment to
silently accept an imported file. `tlsforge.Version()` and `tlsforge.EngineMajor()`
report the compiled identity. Client constructors, transport adapters, the
registry and `Fresh` enforce it; client/profile clones own their major value.

Daemon protocol **3** reports `engine_major` and `version` on `hello`. Every
request and proxy `init` line must carry `engine_major: 1`; missing or mismatched
metadata is rejected before client execution. Offline `hello` can omit the field.
Node/Python validate the actual daemon identity before every first request,
including plain requests, and revalidate a replacement process. An old executable
from PATH is rejected rather than used silently. Update the SDK and binary
together; no compatibility flag disables the gate.



The Go package is the native API behind the `tls-forge` CLI. With a current
measured profile it sends requests with a captured browser TLS ClientHello,
HTTP/1.1 wire casing and header order, HTTP/2 settings, pseudo-header order,
regular header order and browser headers. Older profiles require explicit engine migration before execution.

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

`Client.Close()` releases idle connections, and those it still reads an
answer it went on from on (below), and is final. Calls made after close
return an error; construct another client to create another identity.

A connection is kept and closed as the profile's browser keeps and closes it
([connection lifecycle](docs/profile-behavior.md#connection-lifecycle-unreleased-engine-1)).
With a shipped Chrome profile no close sends a TLS close_notify, `Close` and
`CloseIdleConnections` included; an idle HTTP/2 connection is kept until its
server closes it, an idle HTTP/1.1 one 300 s, reaped when a later request asks
for a connection; a connection a GOAWAY leaves no stream is closed at once;
and the system probes an idle TCP connection after 45 s. A request to an
HTTP/2 connection that has read nothing for more than 10 s sends a PING with
its HEADERS ([the PING](docs/profile-behavior.md#the-connections-own-ping-unreleased-engine-1));
when no answer comes and nothing is read for 10 s, the connection is given up
and a request with no answer yet goes again on another connection, so a
`Trace` may see a request dial twice.

A request goes again as the profile's browser sends one again
([requests sent again](docs/profile-behavior.md#requests-sent-again-unreleased-engine-1)).
With a shipped Chrome profile a stream the server refuses goes again at once
on its connection, and one above a GOAWAY with NO_ERROR on another, twice at
most, those two and a PING not answered counted together; above a GOAWAY with
any other code the request fails. A request whose reused connection is lost
under it before any of its answer came goes again at once on another,
whatever its method, a POST with its body, 50 times at most, and a 408 on a
reused HTTP/1.1 connection closes the connection and sends the request again.
The counts are a hop's: its answers to a 401 and a 421 share them. `Do`
returns the last failure; a `Trace` sees each connection a request went on.

An answer a request goes on from without reading it (a redirect followed, a
401 answered, a navigation started again for its client hints, a CORS
preflight) is let go of as the profile's browser lets go of it
([answers let go of unread](docs/profile-behavior.md#answers-let-go-of-unread-unreleased-engine-1)).
With a shipped Chrome profile the next request no longer waits for that
body: over HTTP/2 its stream is reset, over HTTP/1.1 a redirect's body is read
in the background on its own connection while the next hop takes another, so
a `Trace` may see a hop dial although the connection before was HTTP/1.1 and
kept. `CloseIdleConnections` and `Close` end that reading, and wait for it,
before they close the idle connections: the next request opens one of its
own.

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
| `WithTimeout(duration)` | Set how long a request may take, all of it: its connection, its preflight, every hop of its redirects, its answers to a 401 or a 421, its start again for client hints and its body. The default is `tlsforge.Timeout` (`30s`). Values must be positive and fit into a signed 32-bit millisecond value. |
| `WithMaxResponseBody(bytes)` | Limit the decompressed response retained in memory. The default is `tlsforge.DefaultMaxResponseBody` (64 MiB). Values must be positive and bounded. |
| `WithHeaders(header)` | Layer ordered default headers over the profile for every request. Existing names keep their profile position. |
| `WithCookies(cookies)` | Seed the client's jar with a warmed session. Cookies are matched to each request URL before being inserted. |
| `WithoutCookieJar()` | Disable cookie storage. Use this when another layer, such as an intercepting proxy, owns the `Cookie` header. |
| `WithCookieJar(jar)` | Supply an `fhttp.CookieJar`, for example to share or persist a jar. |
| `WithoutRedirects()` | Return the first 3xx response instead of following it. Redirects are followed by default as Chrome follows them ([Redirects](#redirects)): nineteen for navigation/form/low-level requests; twenty for Fetch/XHR contexts. |
| `WithoutSessionResumption()` | Keep no TLS session to resume, so that every connection is the cold handshake of a first contact. Without it a profile whose browser resumes does as the browser does; see below. |
| `WithInsecureSkipVerify()` | Disable upstream certificate verification. Intended for controlled local test endpoints. |
| `WithFixedExtensionOrder()` | Force a stable TLS extension order. Firefox and Safari profiles already select this behaviour automatically. |
| `WithRandomExtensionOrder()` | Force per-connection TLS extension shuffling, every order of the extensions that move as likely as any other, as Chrome draws one. Chromium profiles select it automatically; the override is useful for custom Chromium profiles whose identity cannot be inferred. |
| `WithTransportOption(options...)` | Pass advanced `tls-client` transport options through when the wrapper does not expose them directly. One that sets what tls-forge sets replaces it; see [Transport options](#transport-options). |
| `WithLogger(logger)` | Write down what the client does, as it does it, to a `*slog.Logger`; see [Logging](#logging). |
| `WithKeyLogWriter(w)` | Write the TLS secrets of every connection the client makes, to the sites and to an HTTPS proxy, to an `io.Writer` in the NSS key log format, for Wireshark to read a capture with; see [Reading a client in Wireshark](#reading-a-client-in-wireshark). |
| `WithDNSServer(address)` | Look names up with the DNS server at `address` (an IP address, with a port or without one for 53) instead of the machine's servers: the addresses, and the HTTPS records whose ECH configs a connection offers and whose ALPN may send it over HTTP/3; see [Encrypted Client Hello](#encrypted-client-hello) and [HTTP/3 from DNS](#http3-from-dns). For direct connections: through a proxy the names are the proxy's, and transport options of the caller's replace the dialer that would ask. |

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
stable. A profile draws the order for every connection as Chrome 155 was
measured drawing it (`testdata/chrome155-hellos.json`): every order of the
extensions that move as likely as any other, GREASE, padding and
`pre_shared_key` where the capture has them. A bare entry of the transport's
catalogue is the transport's, which draws its own.

### Transport options

tls-forge builds on its own forks of fhttp, tls-client and utls, with those
of quic-go-utls and websocket that name the same fhttp and utls:
`github.com/igor-lemon/fhttp`, `github.com/igor-lemon/tls-client` and
`github.com/igor-lemon/utls`, each the `tls-forge` branch of a fork of
bogdanfinn's, whose `LEMON.md` says what it changes. An option is written with
`tls_client` imported from there, a jar given to `WithCookieJar` is an
`fhttp.CookieJar` of that fhttp, and a type of utls, as the `ClientHelloSpec`
`profile.Profile.Spec` returns, is that utls's.

`WithTransportOption` hands tls-client options to the transport after
tls-forge's own. An option that sets what tls-forge already sets replaces it,
and what tls-forge did with it goes too:

- `tls_client.WithTransportOptions` replaces six idle connections per host,
  the key log of `WithKeyLogWriter` for the connections to sites, and the
  decoding of bodies by tls-forge. The transport then decodes gzip,
  deflate, br and zstd itself. It reads deflate sent as zlib only after
  waiting out the request's deadline, and over HTTP/1.1 it takes
  Content-Encoding off a body in any other coding, or in more than one,
  without decoding it.
- `tls_client.WithNotFollowRedirects` and `tls_client.WithCustomRedirectFunc`
  replace how redirects are followed: no longer as Chrome follows them
  ([Redirects](#redirects)). `WithoutRedirects` is the way to keep them.
- `tls_client.WithClientProfile` is refused as a transport override. Select an
  engine-compatible profile through `WithProfile` or `WithProfileValue`;
  profile JSON owns its handshake, H2 settings, priority and field ordering.

- `tls_client.WithCookieJar` replaces the client's jar, and `Cookies`,
  `AllCookies` and session files then see none of what the site sets.
  `WithCookieJar` is the way to bring a jar of your own.
- A proxy given as a transport option, without `WithProxy`, is the
  transport's to dial. The log's `proxy` records and the exit header fields
  of a tunnel's answer go with tls-forge's dialer. `WithProxy` is the way to
  keep them.
- `tls_client.WithTransportWrapper` replaces how tls-forge sends each hop of
  a redirect on the connections of its own top-level site and credentials
  ([Redirects](#redirects)): every hop then goes out on the connections of
  the request's first. The wrapper is handed each transport's round tripper,
  and sees every request.
- Any transport option leaves a client without a proxy dialing the
  transport's way, since the option may be a dialer: the connections HTTP/2
  dials apart from a request then go unlogged ([Logging](#logging)), and no
  HTTP/2 connection carries a request to another name, whose name would be
  looked up where the dialer may not look it up.
  `tls_client.WithConnectionCoalescing`, given a lookup of the dialer's, is
  the way to have them do so ([Browser contexts](#browser-contexts)).

An HTTPS proxy's certificate is checked against the system's roots whatever
the options. `WithInsecureSkipVerify` is for the sites and does not reach it,
since the proxy is who the password is given to: a proxy whose certificate
the system does not trust is refused, and asked for no tunnel. There is no
option for other roots yet.

### Encrypted Client Hello

A client with no proxy and no transport options of the caller's asks the
HTTPS records (RFC 9460) of every name it connects to, alongside its
addresses, of the DNS servers it looks addresses up with, as its profile says
(`dns.https_records`): the machine's servers, which a DNS client of its own
asks as Chrome's built-in client does (`dns.resolver` `built-in`; a name
under `.local`, and `localhost` and names under it, are the machine's
resolver's), or the server `WithDNSServer` names. It offers Encrypted Client
Hello (RFC 9849) with the
configs the record it takes gives (`tls.ech`): the outer hello names the
config's public name, the inner one the site, both as the profile's browser
makes them. The shipped Chrome profiles do as Chrome 155 does, measured
against servers that opened every inner hello they were sent; the fields and
what was measured are in
[the profile behavior reference](docs/profile-behavior.md#encrypted-client-hello-from-dns-https-records-unreleased-engine-1).

```go
client, err := tlsforge.New(tlsforge.WithProfile("chrome_155_macos"))
// A site whose HTTPS record gives ECH configs gets an ECH offer; one that
// refuses it with configs to retry with is offered those once, one that
// sends none is asked again without ECH.
res, err := client.Do(&tlsforge.Request{URL: "https://example.com/"})
```

A refused offer is believed only from a server whose certificate is good for
the public name (`WithInsecureSkipVerify` checks none); refused again, `Do`
fails with `tls: server rejected ECH`. A request to `http://` whose name has
a record goes to `https://` as a redirect (307, `Non-Authoritative-Reason:
DNS`) that never reaches the network (`dns.https_upgrade`), its next hop sent
as a redirect's is. Records are kept for their time to live: a connection
made again asks for none.

### HTTP/3 from DNS

The same client goes over HTTP/3 to a name whose HTTPS record names `h3`,
as its profile says (`dns.https_h3`), as Chrome's DNS ALPN job does: a QUIC
connection to the name's first address, offering that record's ECH, and the
request's TCP connection after it once QUIC's first packet has gone, as long
after as what the session knows of QUIC says (`quic.tcp_wait_*`: at once
while QUIC has not worked in it). The first up takes the request; the other
is made all the same, a QUIC connection taking the requests to its origin
after it, a TCP one kept unused for the next over TCP. QUIC that failed where
TCP did not is not tried again for a while (`quic.broken_*`). What the
session knows of QUIC its `Fresh` clients share.

```go
client, err := tlsforge.New(tlsforge.WithProfile("chrome_155_macos"))
// Over HTTP/3 where the name's record names h3, else over TCP as before.
res, err := client.Do(&tlsforge.Request{URL: "https://example.com/"})
```

Through a proxy, or with transport options of the caller's, nothing changes;
`tls_client.WithProtocolRacing` given with `WithTransportOption` still races
HTTP/3 to every origin. The fields and what was measured are in
[the profile behavior reference](docs/profile-behavior.md#http3-from-dns-https-records-unreleased-engine-1).

An answer whose `Alt-Svc` advertises `h3` sends its origin's later requests
over HTTP/3 to that alternative, as Chrome's alternative job does
(`quic.alt_svc`): the request at once on an HTTP/2 connection the origin
has, its QUIC connection made apart for the next, else QUIC and TCP raced as
for a record's `h3`. Alternatives are the session's, kept for the origin and
the top-level site: see
[the reference](docs/profile-behavior.md#http3-from-an-answers-alt-svc-unreleased-engine-1).

## Requests

`Get(url)` is shorthand for `Do(&tlsforge.Request{URL: url})`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

response, err := client.Do(&tlsforge.Request{
	Context: ctx,
	Method:  "POST",
	URL:     "https://example.com/api",
	Header:  tlsforge.NewHeader("Content-Type", "application/json"),
	Body:    []byte(`{"hello":"world"}`),
	Cookies: []tlsforge.Cookie{
		{Name: "session", Value: "abc", Secure: true},
	},
	// What sends it: the page's script, by fetch().
	Browser: &tlsforge.BrowserContext{Kind: tlsforge.KindFetch, Initiator: "https://example.com/"},
})
```

| `Request` field | Meaning |
|---|---|
| `Context` | Cancels this request. `nil` means `context.Background()`. |
| `Method` | HTTP method. An empty value means `GET`. |
| `URL` | Required absolute http or https URL, sent as Chrome writes it; see below. |
| `Header` | The request's own fields. Without a browser context, each goes in the slot Chrome writes that field in, in place of Chrome's own, and one Chrome has no slot for after `User-Agent`, by the bytes of its name; see below. In a context, what a script gives `fetch()` or an XHR. |
| `Body` | Raw request bytes. `nil` is none, an empty slice an empty body. A request without a browser context has none. |
| `Cookies` | Cookies added to the jar before this request. |
| `Trace` | Optional hooks told each step the request takes on the wire; see [Tracing a request](#tracing-a-request). |
| `Logger` | A `*slog.Logger` this request is logged to instead of the client's, so that what it is for goes with every record of it; see [Logging](#logging). |
| `Browser` | A `*BrowserContext`: what in a browser the request stands for, a navigation, a form, `fetch()` or an XHR, sent as Chrome sends that; see [Browser contexts](#browser-contexts). `nil` sends it as a navigation typed into the address bar, a `GET` with no body: another method, or a body, is refused with `ErrNeedsContext`. |
| `Reload` | The page the request opened, reloaded as Chrome reloads it (Ctrl+R); see [Reloading a page](#reloading-a-page). |

`req.FromItsOwnPage()` is `req` sent by the script of a page of its URL's own
origin, the origin's root (`OwnPage(url)`, as `https://host/` or
`https://[::1]:8443/`), as an ordinary XHR (`KindXHR`), when it has no browser
context and no navigation typed into the address bar is it (a GET is): a POST,
PUT, PATCH, DELETE or HEAD. A request in a context, a GET and one whose URL
does not read come back as they are. `fetch` sends a request without
`--request-kind` so, and the form `--form` asks for as
`&BrowserContext{Kind: KindForm, Initiator: page, Clicked: true}` of the same
page.

Use `Request.Context` for caller-driven cancellation and `WithTimeout` for the
deadline of each request, all of it. A request ends when either is reached,
with the error of its context, which `errors.Is` finds `context.Canceled` or
`context.DeadlineExceeded` in, and so does every wait in it: for a connection
another request is opening, for a handshake the server never answers, for an
address another connection is still being dialed to. The connections to one
address are dialed one after another, and apart from every other address's.

A URL is read as Chrome reads one, and the request for it goes out as Chrome
writes it, measured on Chrome 155 for every case of
`testdata/chrome155-urls.json`: the spaces and controls around it and any tab
or newline in it dropped, the scheme and the host in lower case, a name in
another script in Punycode (`пример.example` is `xn--e1afmkfd.example`), an
IPv4 address in any of its forms dotted and decimal (`http://0x7f.1/` is
`http://127.0.0.1/`), an IPv6 one as the URL Standard writes it, no port the
scheme means, a slash for a backslash, dot segments resolved, what a path or a
query cannot hold percent-encoded and what is percent-encoded already left as
it is, and no fragment. Each hop of a redirect is the URL Chrome makes of its
`Location`, relative to the hop before it. That URL is what the server name,
`Host` and `:authority`, the request target, the cookies, the origin, the
connections and an answer to a 401 are worked out from, and what
`Response.URL`, the log and a trace say. `tlsforge.CanonicalURL(raw)` returns
it, credentials and all.

What Chrome sends nothing for is refused before anything is sent: a URL it
cannot parse, one of another scheme, and one on a port it keeps away from,
Chromium's restricted ports, such as 22, 25 and 6000 (measured on 0 and 6000,
and on 4190 and 6679, which Chrome sends to though the Fetch standard blocks
them). So is a path with a percent sign that escapes nothing, such as
`/50%off`, which Chrome sends as it is and a `url.URL` would escape once more.
A redirect to any of those fails the request, and one whose `Location` has
such a path fails as the transport says it cannot parse it.

A `Cookie` in `Header` goes with the jar's cookies, as `net/http` adds a jar's
to a request's own: every cookie it names first, then those the jar holds for
the URL, in one `Cookie` over HTTP/1.1 and a field for each cookie over HTTP/2,
on the answer to a 401 too. A redirect's hop carries the jar's alone, as Chrome
makes each hop's `Cookie` of its jar (`headers.given_redirect_drops`); a
profile whose requests without a context go as given (`headers.without_context`
`as-given`) sends it on to its host and the hosts under it, as `net/http`
does. `Request.Cookies` adds values to the jar instead, where they go on every
later request they belong to and every hop, and give way to a value the server
sets, as a browser's do; a name in both would go twice.

A request without a browser context is a navigation typed into the address
bar, where the profile says so (`headers.without_context`: `typed-navigation`,
as every shipped Chrome profile does): its headers worked out as a typed
navigation in a [browser context](#browser-contexts) has them, with the client
hints its origin asked for, `Accept-CH`, `Critical-CH` and what a connection's
ALPS asks for. It is a `GET` with no body; another method or a body is refused
before anything is sent, with an error `errors.Is` finds `ErrNeedsContext` in.
What `Header` and `WithHeaders` give it goes each in the slot Chrome writes
that field in, in place of Chrome's own: a reload's `Pragma` and
`Cache-Control` and `Authorization` before the client hints, `Referer`,
`Accept-Language`, the `Cookie` and a revalidation's `If-None-Match` and
`If-Modified-Since` after `Sec-Fetch-*`, the client hints, `User-Agent` and
`Accept` where they are. A field Chrome has no slot for goes where Chrome
driven over DevTools (Playwright's `extraHTTPHeaders`) writes the extra headers
it is given: after `User-Agent`, after `Origin` in a form's and a redirect's,
by the bytes of their names as given, spelt as given over HTTP/1.1 (measured on
Chrome 155: `testdata/chrome155-given.json`). A redirect's hop goes without its
`Authorization` across origins, which Chrome sends on, and says an `Origin` it
was given as "null" across origins, as Chrome does. A `Referer` goes beside a
typed navigation's `Sec-Fetch-Site: none`, which Chrome sends only when
automation gives it one: a navigation from a page is a browser context with its
`Initiator`, which works its `Referer` out and refuses one given. To an http URL
that is not on the machine itself it goes as Chrome sends a navigation there:
without the profile's client hints and `Sec-Fetch-*`, offering neither Brotli
nor zstd, what it was given as given. `localhost`, a name under `.localhost`,
`127.0.0.1` and `[::1]` are potentially trustworthy, as https is, and get every
header of the profile; each hop of a redirect goes as its own URL is, measured
on Chrome 155 (the `nav-direct-*` and `redir-nav-direct-*` scenarios of
`testdata/chrome155-requests.json`). Its answer is a request's without a
context: no cache, and the fields of what was decoded taken off. A profile that
does not say so, a capture's and the transport catalogue's, sends a request
without a context as given: the profile's headers with the request's own over
them, a name it does not have after its last, by any method.

## Browser contexts

A request on its own goes out as a navigation typed into the address bar, with
whatever the caller adds where Chrome writes it ([Requests](#requests)). Chrome
sends other requests differently. A form's POST has `Cache-Control`, `Origin` and its own order;
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
| `Clicked` | A person's click on the page sent the navigation or the form, a link or the form's button: `Sec-Fetch-User: ?1` on every hop, a form's between `Sec-Fetch-Mode` and `Sec-Fetch-Dest`. Without it the page's script navigated or submitted the form, and the request says nothing of a person. Refused for `fetch()`, an XHR, a navigation typed into the address bar (the person's already) and `Sent`. |
| `Sent` | `Header` is what a browser sent for the request, as an intercepting proxy is given it; see below. |

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

A request in a context with `Sent` is one a browser sent, as `tls-forge proxy`
is given a browser's request: it goes with the fields `Header` says and no
others, each in Chrome's slot for its kind (a script's own, a page's
subresource's, in the renderer's map, sent as `fetch()` in its mode), but the
profile's `User-Agent`, client hints, `Accept-Language` and `Accept-Encoding`,
which the handshake says; with the `Priority` Chrome writes over HTTP/2 for
what it is for (`Sec-Fetch-Dest`: `headers.sent_priority`) when it came with
none, as over HTTP/1.1 it does, and its HTTP/2 priority weighted by its
urgency (`h2.urgency_weights`). Nothing the browser does is done again: no
`Origin`, `Referer`, `Sec-Fetch-*` or client hints of tls-forge's, no
preflight, no CORS check, no answer to a 401, no start again for
`Critical-CH`, no redirect followed, and no answer kept for later; it is
answered as a request without a context is.

The cookies go as Chrome sends them. To another site, a navigation carries
cookies of `SameSite=None` and `Lax`, and those that named none; a form's POST
carries `None`, and those that named none only for two minutes after they were
set; `fetch()` and an XHR carry `None` alone, and none at all under
credentials `omit`, or under `same-origin` to another origin and, once a
redirect has taken them to one, back at the page's own. To its own site a
request carries every cookie the jar holds for it.

The cookies an answer sets are kept as Chrome keeps them: none of those of
the answer to a request that carries none (credentials `omit`, or
`same-origin` to another origin, each hop of a redirect by its own), and none
of a preflight's. An answer CORS refuses keeps its cookies, as Chrome's
network stack keeps them before the page is refused the answer. The answer
to `fetch()` or an XHR of another site than its page's keeps those of
`SameSite=None` alone; one to the page's site, a navigation's and a form's
keep any, whatever site a redirect went through before.

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

A page over https sends nothing to plain http on another machine, a URL that
is not potentially trustworthy (not `localhost`, a name under `.localhost` or
a loopback address), as Chrome 155 was measured blocking it as mixed content
(the `mixed-*` scenarios of `testdata/chrome155-requests.json`): neither
`fetch()` nor an XHR, in any mode, with any credentials and by any method, nor
a form, which Chrome submits there only once the person using it says to go on
past a warning. `Validate` refuses such a request and `Do` sends nothing of
it, each with an error wrapping `tlsforge.ErrMixedContent`. A navigation is
never stopped, nor anything from a page that is not over https,
`http://localhost`'s included.

`fetch()` and an XHR go out on the connections of their page's site, which
its own requests use too, each HTTP/2 `HEADERS` frame with the weight Chrome
gives it: 220 for a script's request, its preflight, its redirects and its
answer to a 401, 256 for a page's. A request that carries no credentials goes
out on connections of its own, which resume only TLS sessions of their own, as
Chrome 155 sends one (`testdata/chrome155-connections.json`): `fetch()` with
credentials omitted, one kept to its page's origin that goes to another, in
cors or no-cors mode, an XHR without `withCredentials` to another origin, and
every CORS preflight, that of a request with credentials too. A hop of a
redirect that leaves a request without credentials, as one kept to its page's
origin that a redirect takes to another does, goes on there, and stays on
them, back at the page's origin too.

Connections, and the TLS sessions they resume, are kept apart for each
top-level site too, as Chrome keeps them: a navigation or a form loads a page
of a site, and goes out on that site's connections, and what a page's scripts
send goes out on the page's. So does each hop of a redirect: a navigation's
or a form's hop to another site goes out on that site's connections, though
a connection of the first site's could carry it, and one back on the first
site's, while a script's hops stay on its page's. A navigation from a page of `www.example.com` to
`www.example.net` opens a connection of its own even when a `fetch()` of the
page holds one to that host, and resumes none of its TLS sessions. A request
without a browser context goes out as a navigation typed in, on the
connections of its URL's site. A client keeps the connections of the 64 sites
it sent requests to last: a request to one more drops the site used longest
ago, whose idle connections are closed and whose TLS sessions are forgotten;
what is in flight on them ends as it would have, and a request to that site
later opens connections of its own again. `CloseIdleConnections` and `Close`
close the idle connections of every site, and a client made `Fresh` keeps
none of this client's.

Among those, a request to another name goes out on an HTTP/2 connection the
client holds to an address the name is found at, on the port the request is
for, when the connection's certificate was verified and is good for that
name, as Chrome 155 sends one: a page's `fetch()` of `api.example.com` or
`www.example.net`, with credentials or without, goes out on a connection of
its kind it holds to `www.example.com`, when both names are at that address
under that certificate, and so does a navigation to `api.example.com`, of the
page's site. The name is looked up first, as Chrome looks it up, with the
machine's resolver; when no connection fits, the request dials one as before.
None is shared through a proxy, whose address is all a connection knows, nor
with `WithInsecureSkipVerify`, which verifies no certificate (Chrome shares
none whose certificate has an error), nor when transport options of the
caller's may say how to dial ([Transport options](#transport-options)).
HTTP/1.1 connections are not shared, as Chrome shares none.

A request a server answers 421 (Misdirected Request) is sent again, once, as
Chrome 155 sends it: its body and header fields as they went, on a
connection of its host's own, which the host's later requests go out on too.
Over HTTP/2 that is a connection the client holds for the host, the same one
when the 421 came on it; over HTTP/1.1 the connection the 421 came on is
closed, and the request goes out on another. Each hop of a redirect and each
CORS preflight is sent again for a 421 of its own, a 401 answered between or
not, and a second 421 is the answer, or a preflight that did not allow the
request. The cookies a 421 sets are not kept when the request is sent again
for it: Chrome hands such a 421 to nothing, the page included.

Two things Chrome does with its connections tls-forge does not. Chrome sends
a navigation's redirect to another site on that site's connections, where
tls-forge follows every redirect on the connections of the site of the first
hop, and over HTTP/2 on one of them its certificate is good for. And a
redirect that leaves a request without credentials, `fetch()` of the page's
origin redirected to another, Chrome follows on the connections of requests
that carry none, where tls-forge follows it on the connections the request
went out on.

What a context does not do yet: the order of several headers a script set
(Chrome's renderer keeps them in a hash table where each name has its place,
so the order changes with the set of names; one goes where Chrome was
measured to put it), frames, and a form submitted by the user's click
(`Sec-Fetch-User`).

### Reloading a page

```go
res, err := client.Do(&req)
if err == nil && res.Status == http.StatusForbidden {
	again := req.Reloaded(res)
	res, err = client.Do(&again)
}
```

`Request.Reload` sends the request as Chrome sends it when the page it opened
is reloaded (Ctrl+R), as Chrome 155 was measured doing it after a 403
(`testdata/chrome155-reload.json`, `TestAPageIsReloadedAsChromeReloadedIt`):
asking for the page afresh (`Cache-Control: max-age=0`, first in a
navigation's order, `headers.reload_cache_control`), saying the person asked
(`Sec-Fetch-User: ?1`, whether a click or the page's script sent it first),
with what the page's answer set, its cookies and the client hints it asked
for, and from the page it came from (`Referer`, `Origin`, `Sec-Fetch-Site`) as
before. A form's POST goes again with its body, its `Content-Type` after
`Origin` (`headers.form_reload_order`). It goes on a connection the client
still holds to the site, as Chrome's goes on the one the page came on: make it
with the client that made the request, not a `Fresh` one.
`req.Reloaded(res)` is the request that reloads the page `res` is at: `req`
with `Reload`, to `res.URL`, where a redirect may have taken it (Chrome reloads
the page it ended on, not the redirect), by the method `res` answers
(`Response.Method`); a form's POST a redirect made a GET is reloaded as that
GET, a navigation from the form's page without its body. `fetch()` and an XHR
open no page: `Reloaded` hands them back as they are, for the page's script to
send them again, and `Reload` on one is refused, as on a request a browser sent
(`Sent`), with a profile that says nothing of reloads, and with one that sends
a request without a context as it is given. A reload that bypasses the cache
(Ctrl+Shift+R: `Pragma` and `Cache-Control` `no-cache`) is not modelled.

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
- Navigation/form and low-level requests follow nineteen redirects,then fail
  with `the 20th redirect was not followed` (twenty requests total). Fetch/XHR
  contexts follow twenty redirects,then fail with
  `the 21st redirect was not followed` (twenty-one requests total).
- Each hop goes out on the connections of its own top-level site, as Chrome
  155 was measured sending them (`testdata/chrome155-connections.json`): a
  hop to another site on that site's, and one back on the first's. A request
  without a context is a navigation typed in, whose site is its hop's.

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
- A script's hops go out on the connections of its page's site, and a hop
  that leaves the request without credentials on those of requests that
  carry none: it stays on them, back at the page's origin too, as Chrome
  sends it. The preflight a hop needs goes out on those, and the answer to
  a 401 or a 421 of a hop on the connections the hop went out on.
- CORS has to allow a redirect itself, and a hop that needs a preflight is
  asked about again at the URL it goes to, with its own `Sec-Fetch-Site`.
  `fetch()` in `same-origin` mode follows no redirect to another origin.
  To a URL with credentials in it, `fetch()` follows none but to the page's
  own origin with the page's own credentials, and a request in `cors` mode
  none across origins. Each of these is an error wrapping
  `tlsforge.ErrCORS`, with nothing more sent.
- From a page over https, `fetch()` and an XHR follow no redirect to plain
  http on another machine, and a form none that posts it there again (a 307
  or a 308); a form's GET, and a POST a 302 or a 303 made a GET, go on, as
  Chrome's go. Each stop is an error wrapping `tlsforge.ErrMixedContent`,
  with nothing more sent: CORS is asked about the redirect first.

### HTTP authentication

The credentials in a URL are used as Chrome 155 was measured using them (the
`auth-*` scenarios of `testdata/chrome155-requests.json`), by every request:

- Nothing is sent before the server asks. Go's transport sent
  `Authorization: Basic` with the first request, over HTTP/1.1 in the HTTP/2
  layout.
- A 401 is answered in the best scheme it offers that Chrome reads, Digest
  before Basic wherever each is, the first of two alike: once with the URL's
  credentials, then with what the session keeps for the realm and scheme.
  The same request goes again, its body too, with `Authorization` where
  Chrome's network stack adds it, after `Content-Length` and `Cache-Control`
  and before every other header, after `Host` and `Connection` over
  HTTP/1.1. A redirect to a URL with credentials, or a relative one from a
  URL with them, is answered the same.
- Digest is answered as RFC 7616 has it and Chrome does: MD5 and SHA-256,
  each with its `-sess`; `qop=auth`, the one qop Chrome answers, or none, as
  RFC 2069 has it; the opaque said back; the username hashed for
  `userhash=true`; the parameters in Chrome's order, and a client nonce of
  16 hexadecimal digits drawn for each answer. A challenge Chrome cannot
  read, of an algorithm it does not know or with no nonce, is passed over as
  Chrome passes it over. Every challenge's parameters are read as Chromium
  reads them.
- What was answered with is kept for the session, by origin, realm and
  scheme. It is sent unasked to the directory it was answered in and those
  under it, a Digest answer's nonce count going up by one each time, and
  answers a 401 of the realm and scheme anywhere else at the origin. A URL
  that carries credentials is sent nothing unasked. Credentials turned down
  are tried once and forgotten. A 401 that says a Digest nonce is out of date
  (`stale=true`) is answered again with the same credentials and its nonce,
  and a request that would be sent its 32nd answer fails, as Chrome stops
  there.
- A 401 that offers NTLM, or Negotiate with a profile of Windows, is left as
  it is: Chrome answers it in that scheme, which tls-forge does not. Elsewhere
  Chrome passes Negotiate over, unless a policy names the site, and so does
  tls-forge. A 401 is left as it is, too, for a request with an
  `Authorization` of its own, for a script's request CORS answers for, and
  for one that carries no credentials (`Credentials: "omit"`).
- `Response.URL` carries no credentials.

The log says `challenge answered`, with the realm, the scheme and whether the
credentials were the URL's or the realm's; `authorization sent` for what is
sent unasked, with its scheme and a Digest answer's nonce count; and `answer
refused` for a 401 to an answer, which says whether it was turned down, out of
date or another realm's: never the credentials.

### Client hints

A server asks for client hints beyond the three Chrome sends with every
request (`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`) with
`Accept-CH`, and a request in a browser context sends them as Chrome 155 was
measured sending them (`testdata/chrome155-requests.json`):

- What an origin asks for on the answer to a navigation, a form's or a
  redirect's, over a connection a page may trust, is kept for the session,
  which every client made `Fresh` from one shares. A later `Accept-CH`
  replaces it, an empty one asks for nothing, and an answer without one
  leaves it as it was. The hints Chrome knows are kept, in any case; the rest
  are passed over. A `fetch()` or an XHR asks for nothing.
- Every navigation and form to that origin carries them with the three, in
  Chrome's order (`profile.ClientHintOrder`) and where Chrome puts them: first
  in a request, and after `Sec-Fetch-Dest` after a redirect. `fetch()` and an
  XHR of a page of that origin carry them to it, first; Chrome's renderer puts
  several where its hash table does, which is not modelled.
- Another origin of the same site, another site, and a page of another site
  asking that origin get none of them.
- A hint the profile has no value for (`profile.Profile.ClientHints`) is not
  sent: of the shipped profiles, `chrome_155_macos` has every one.
- A navigation whose answer, or a redirect's on the way, names in
  `Critical-CH` a hint its origin now asks for that it did not carry, and the
  profile has a value of, starts again where it began, once, as Chrome's
  does: its first request with the hints after `Accept`, and the cookies the
  answers set. A form's POST and a script's request are not started again.
- A request without a browser context neither keeps nor sends them.

## Responses and errors

The response body is already decoded and read into memory, subject to the
configured maximum, which counts the decoded bytes. A body is decoded as Chrome
decodes it: from gzip, x-gzip, deflate (zlib, or the raw deflate some servers
send under that name), br and zstd, in the reverse of the order they were
applied, including `206` responses. Gzip returns the available decoded prefix
at a clean HTTP EOF, ignores additional gzip members and drains trailing bytes;
malformed gzip/DEFLATE and incomplete HTTP framing still fail. A body in a
coding Chrome does not know, an empty one and the answer to a `HEAD` are left as they came, with
their `Content-Encoding`.

| `Response` field or method | Meaning |
|---|---|
| `Status` | HTTP status code |
| `URL` | Final URL after redirects, as Chrome writes it |
| `Method` | The method of the request this answers: the request's own, or `GET` where a redirect made a `POST` one |
| `Header` | Lower-cased names mapped to every field value. With `Browser`, received representation headers are preserved, as in Fetch; `Body` is decoded and `Encoding` says what was removed. Without `Browser`, `content-encoding` and `content-length` are removed after decoding so the headers describe `Body` |
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
| `slog.LevelInfo` | The client and its profile; a record for each request and each answer, for a navigation started again for its critical client hints, and for a request sent again for a 421. |
| `slog.LevelWarn` | A request that failed: the step it gave up in as `phase` (`prepare`, `dns`, `connect`, `proxy`, `tls`, `send`, `wait`, `receive`, `body` or `redirect`), whether it was a timeout, and the error. A lookup that failed, a proxy that would not open a tunnel, with up to 1 KiB of what it said, a handshake with an HTTPS proxy that failed, and the redirect that is not followed, the twentieth. |
| `slog.LevelDebug` | Every step: each lookup with the addresses found, each TCP dial, the `CONNECT` to a proxy and its answer with the tunnel's number, the connection by its two ends with what its handshake settled on and the server's certificate, a connection reused, the header fields as written, pseudo-headers included, the first byte, the answer's header fields, each redirect, what an origin asked for with `Accept-CH`, and when a client is made, made `Fresh`, closes its idle connections and is closed. The profile's JA4, HTTP/2 preface and header order when a client is made. |
| `tlsforge.LevelTrace` | The ClientHello of every new connection, with its JA4, JA4_r, JA3, every list in it and the length of its GREASE ECH payload as `ech_payload_bytes`, and every certificate of the server's chain. |

Every record carries `client`, the client's number in the process, and
`request`, the request's number on the client. A request with a `Logger` of its
own is logged there instead, with `client` added and without `request`, so that
a caller can say what the request is for. A record that ends a step says how
long the step took as `took`.

Every connection is dialed for a request, within its context: its lookup,
dial and tunnel are in that request's records, an HTTP/2 connection's too,
which later requests go out on, and whose `connected` records name it as
`conn` and its tunnel as `tunnel`. A client given `WithTransportOption` dials
the transport's own way, since one of those options may be a dialer or a
proxy; such dials then go unlogged.

A log is made to be passed on, so it leaves out what a session is worth: a
proxy's password, cookie values, `Authorization` and `Proxy-Authorization`
credentials and the values of headers whose names contain `token`, `secret`,
`password` or `key` are written as `***`. Without `WithLogger`, or a request's
`Logger`, nothing is logged and nothing is spent on it.

### Reading a client in Wireshark

```go
keys, err := os.OpenFile("run.keys", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
if err != nil {
	return err
}
defer keys.Close()
client, err := tlsforge.New(tlsforge.WithKeyLogWriter(keys))
```

`WithKeyLogWriter` has a client write the TLS secrets of every connection it
makes to `w`, in the NSS key log format browsers write to the file
`SSLKEYLOGFILE` names: the connections to the sites, over TCP and over QUIC,
the one to an HTTPS proxy and those inside its tunnels, and those of every
client `Fresh` makes of it.
Given them, Wireshark reads a capture of the client's traffic (tcpdump,
dumpcap) as the client wrote and read it, and so does anybody else who has
them, which is why the file above is made with mode `0600`, and why it is for
looking into a run, never for keeping. A site's TLS inside an HTTPS proxy's
tunnel, TLS within TLS, Wireshark 4.6.9 shows as HTTP continuation data; its
secrets are written all the same.

Each line is one write, and tls-forge makes no two at once, of this client or
of any other, so `w` need not be safe for concurrent use. A write that fails
fails the handshake it was for, as crypto/tls's `KeyLogWriter` does: a caller
who asked for the secrets learns they were not written. Transport options
given with `WithTransportOption` replace the ones the secrets go with for the
connections to sites, which then write none ([Transport options](#transport-options));
an HTTPS proxy's still do.

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

A server's `Set-Cookie` is held to what Chrome takes of it, measured on
Chrome 155: a prefix's rules, in any case (`__Secure-` with `Secure`,
`__Host-` with `Secure`, `Path=/` and no `Domain`, `__Http-` with `Secure`
and `HttpOnly`, `__Host-Http-` with all of those); `SameSite=None` only with
`Secure`; `Secure` only from https or plain http to the machine itself, which
Chrome deems secure and sends `Secure` cookies to; a cookie without `Secure`
from plain http leaves a `Secure` one of its name alone; at most 4096 bytes of
name and value, and a `Path` or `Domain` longer than 1024 bytes passed over.
The cookies you give (`WithCookies`, `Request.Cookies`, a session read with
`--cookies`) are yours, and are filed as they are.

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
| `Secure` | Send only over HTTPS, or plain HTTP to the machine itself, which Chrome deems secure. |
| `HTTPOnly` | Preserve the HttpOnly attribute in exported session data. |
| `Expires` | Expiration time; zero represents a session cookie. |
| `SameSite` | `strict`, `lax`, `none`, or empty when the server named none. Kept, written down, and held to as Chrome holds a request in a browser context to it, sent and set; a request without one is a navigation typed into the address bar, which carries every SameSite. |

`client.CookiesFor(url)` returns the cookies the jar would send to a URL, read
as a request reads it (a port Chrome sends nothing to is no refusal here), and
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
- one pool of connections, kept apart for each top-level site and by
  credentials, as Chrome keeps them ([Browser contexts](#browser-contexts)).

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

Raw `WithTransportOption(WithClientProfile(...))` overrides are refused before transport creation; use `WithProfile` or `WithProfileValue` with explicit `engine_major`.
