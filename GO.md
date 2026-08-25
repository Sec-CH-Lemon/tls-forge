# tls-forge for Go

The Go package is the native API behind the `tls-forge` CLI. It sends requests
with a measured browser TLS ClientHello, HTTP/2 settings, pseudo-header order,
regular header order and browser headers.

This document covers the public client API and the optional measurement, proxy,
echo, profile, capture, cookie, daemon and fingerprint packages.

## Requirements and installation

Go 1.25.13 or newer is required.

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

## Client options

Every option below is passed to `tlsforge.New(options...)`.

| Option | Meaning |
|---|---|
| `WithProfile(name)` | Resolve a built-in, locally installed or runtime-registered profile by name. A profile file path is also accepted by the default registry. |
| `WithProfileValue(profile)` | Use a previously loaded `*profile.Profile` directly. |
| `WithProxy(url)` | Route requests through `http://`, `https://`, `socks5://` or `socks5h://`; credentials may be included in the URL. |
| `WithTimeout(duration)` | Set the transport request timeout. The default is `tlsforge.Timeout` (`30s`). Values must be positive and fit into a signed 32-bit millisecond value. |
| `WithMaxResponseBody(bytes)` | Limit the decompressed response retained in memory. The default is `tlsforge.DefaultMaxResponseBody` (64 MiB). Values must be positive and bounded. |
| `WithHeaders(header)` | Layer ordered default headers over the profile for every request. Existing names keep their profile position. |
| `WithCookies(cookies)` | Seed the client's jar with a warmed session. Cookies are matched to each request URL before being inserted. |
| `WithoutCookieJar()` | Disable cookie storage. Use this when another layer, such as an intercepting proxy, owns the `Cookie` header. |
| `WithCookieJar(jar)` | Supply an `fhttp.CookieJar`, for example to share or persist a jar. |
| `WithoutRedirects()` | Return the first 3xx response instead of following it. Redirects are followed by default. |
| `WithInsecureSkipVerify()` | Disable upstream certificate verification. Intended for controlled local test endpoints. |
| `WithFixedExtensionOrder()` | Force a stable TLS extension order. Firefox and Safari profiles already select this behaviour automatically. |
| `WithRandomExtensionOrder()` | Force per-connection TLS extension shuffling. Chromium profiles select it automatically; the override is useful for custom Chromium profiles whose identity cannot be inferred. |
| `WithTransportOption(options...)` | Pass advanced `tls-client` transport options through when the wrapper does not expose them directly. |

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

Use `Request.Context` for caller-driven cancellation and `WithTimeout` for the
transport deadline. A request ends when either limit is reached.

Do not construct a `Cookie` header manually unless replacing the jar's complete
output is intentional. `Request.Cookies` adds values to the jar, preserving
cookies received earlier in the session.

## Responses and errors

The response body is already decompressed and read into memory, subject to the
configured maximum.

| `Response` field or method | Meaning |
|---|---|
| `Status` | HTTP status code |
| `URL` | Final URL after redirects |
| `Header` | Lower-cased header names mapped to every field value |
| `Body` | Decompressed `[]byte` body |
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
wrapped errors with a `tlsforge:` prefix.

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
| `Has(name)` | Report whether the name exists, including with an empty value. |
| `Set(name, value)` | Replace a value in place or append a new field. |
| `Del(name)` | Remove all fields with this name. |
| `Names()` | Return names in wire order. |
| `Clone()` | Return an independent copy. |
| `Merge(overrides)` | Apply overrides while preserving positions from the base list. |

`client.Headers()` returns a copy of the effective default request headers.

## Cookies and sessions

The default jar uses the public suffix list and applies normal domain, path,
secure and expiry rules.

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
| `Path` | Cookie path. Empty defaults to `/` when seeded. |
| `Secure` | Send only over HTTPS. |
| `HTTPOnly` | Preserve the HttpOnly attribute in exported session data. |
| `Expires` | Expiration time; zero represents a session cookie. |

`client.Cookies(url)` returns cookies currently applicable to a URL.
`client.CookiesFor(url)` returns the same full cookie representation and is the
method used by session exporters. Both return `nil` when the jar is disabled.

The `cookie` subpackage reads and writes project JSON session files, flat
browser-export JSON and Netscape cookies.txt data:

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

## Measuring and comparing

`MeasureBrowser` launches a real browser with a temporary profile and records
what it sends to a local echo server.

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

The comparison covers complete TLS fields, protocol mismatch, HTTP/2 settings,
pseudo-header order, normal header order and normal header values.

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
self-signed CA. Treat the private key as a sensitive credential.

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
`Await(ctx)`. A `Session` can be rendered as a `capture.Capture`.

## Other packages

| Package | Purpose |
|---|---|
| `browser` | Find and launch Chrome, Chromium, Edge or Brave with a temporary profile. `browser.Options` contains `Headless` and `Args`. |
| `capture` | Serializable representation of observed TLS, HTTP/1, HTTP/2 and browser navigator data. |
| `cookie` | Load, select, merge and encode warmed cookie sessions. |
| `daemon` | JSON Lines request/response transport used by non-Go SDKs. `Serve` accepts any compatible client. |
| `fingerprint` | Parse ClientHello records, calculate JA3/JA4 and compare TLS or HTTP/2 structures. |
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
