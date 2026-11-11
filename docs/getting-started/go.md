# Install for Go

Go **1.27.4** or newer is required. Add the unsuffixed module path (engine 1 has no `/v1` suffix):

```bash title="Terminal"
go get github.com/Sec-CH-Lemon/tls-forge
```

```go title="Go"
package main

import (
    "fmt"
    "log"

    tlsforge "github.com/Sec-CH-Lemon/tls-forge"
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

The latest published module is `github.com/Sec-CH-Lemon/tls-forge@v1.0.1`. Engine 1.1.0 is not published yet: until it is, use a checkout and a `replace` directive in your application.
