# Upstream proxies

An upstream proxy changes the route to the origin. Every interface can select one. This differs from running the [local intercepting proxy](../integrations/proxy.md), which accepts requests from another program.

=== "CLI"

    ```bash
    tls-forge fetch --proxy http://proxy.example:8080 https://example.com/
    TLSFORGE_PROXY='http://user:password@proxy.example:8080' \
      tls-forge fetch --proxy-env TLSFORGE_PROXY https://example.com/
    ```

    `--proxy-env` names an environment variable explicitly; the CLI does not read one automatically. It keeps the password off the process command line. The [CLI reference](../reference/cli.md) lists `--exit-lookup`, `--exit-headers`, DNS and other proxy diagnostics.

=== "Go"

    ```go
    client, err := tlsforge.New(
        tlsforge.WithProfile("chrome"),
        tlsforge.WithProxy("http://proxy.example:8080"),
    )
    ```

=== "Node.js"

    ```js
    const client = new Client({
      profile: 'chrome',
      proxy: 'http://proxy.example:8080',
    });
    ```

=== "Python"

    ```python
    with tlsforge.Client(profile="chrome", proxy="http://proxy.example:8080") as client:
        response = client.get("https://example.com/")
    ```

HTTP, HTTPS and SOCKS proxy forms supported by the selected transport can be used. Authentication and the proxy's own TLS trust are distinct from origin authentication. `--insecure` or SDK `insecure` disables upstream certificate validation and should be limited to controlled endpoints. When comparing a browser and client, record the same network path and proxy settings for both.
