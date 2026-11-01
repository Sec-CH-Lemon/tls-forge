# Go library

The native package supplies `Client`, `Request`, `Response`, client options and measurement APIs. Subpackages provide profiles, captures, cookie files, fingerprint parsing, the echo server, daemon protocol and local proxy. The [generated Go API reference](../reference/go-api.md) lists exported declarations from each package.

```go title="Go"
import tlsforge "github.com/Sec-CH-Lemon/tls-forge"

client, err := tlsforge.New(
    tlsforge.WithProfile("chrome"),
    tlsforge.WithTimeout(30*time.Second),
)
if err != nil { return err }
defer client.Close()

response, err := client.Get("https://example.com/")
if err != nil { return err }
fmt.Println(response.Status, response.Text())
```

`Client` is safe for concurrent use. With shipped profiles, each `Do` has an isolated browser network instance. `Fresh` creates an independent client from explicit inputs. A custom profile can choose client scope when a workflow needs state across calls.

| Task | API |
| --- | --- |
| Choose a profile or a validated profile value | `WithProfile`, `WithProfileValue`, `profile.Load` |
| Route or time requests | `WithProxy`, `WithTimeout`, `WithDNSServer` |
| Supply headers or cookies | `WithHeaders`, `WithCookies`, `Request.Header`, `Request.Cookies` |
| Choose a browser request kind | `Request.Browser` with `BrowserContext` |
| Inspect network events or TLS secrets | `Request.Trace`, `WithKeyLogWriter` |
| Measure a browser | `MeasureBrowser`, `CompareToBrowser` |
| Start a local proxy | `proxy.Start` |

Other exported options, response fields and helpers are in the generated reference. A raw `WithTransportOption(WithClientProfile(...))` override is rejected before transport construction; select transport behaviour through validated profile JSON. More detailed implementation and API notes remain in the repository's [Go source guide](https://github.com/Sec-CH-Lemon/tls-forge/blob/development/GO.md).
