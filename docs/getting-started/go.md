# Install for Go

Go **1.27.3** or newer is required. Add the module path of engine 2, which ends in `/v2`:

```bash title="Terminal"
go get github.com/Sec-CH-Lemon/tls-forge/v2
```

```go title="Go"
package main

import (
    "fmt"
    "log"

    tlsforge "github.com/Sec-CH-Lemon/tls-forge/v2"
)

func main() {
    client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
    if err != nil { log.Fatal(err) }
    defer client.Close()

    response, err := client.Get("https://example.com/")
    if err != nil { log.Fatal(err) }
    fmt.Println(response.Status, response.Text())
}
```

A browser is not needed to make requests. The Go package can also start a local echo server, measure a browser, compare captures, load profiles, and start a local proxy. Continue with the [Go guide](../integrations/go.md) and [generated API reference](../reference/go-api.md).

Engine 2 is not published yet: until it is, use a checkout and a `replace` directive in your application. The latest published module is `github.com/Sec-CH-Lemon/tls-forge@v1.0.1`, engine 1, whose path has no suffix.
