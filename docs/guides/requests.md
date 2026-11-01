# Make requests

`fetch` collects a response for scraping. It does not parse a page into a data model or run its JavaScript. Use a browser context when the request should represent a page's form, `fetch()`, or XHR; see [browser contexts](browser-context.md).

=== "CLI"

    ```bash
    tls-forge fetch --print-body https://example.com/
    tls-forge fetch --method POST --data '{"hello":"world"}' \
      -H 'Content-Type: application/json' https://example.com/api
    ```

    `fetch` defaults to GET. An explicit non-GET request without `--request-kind` is sent as an XHR from the target origin's root. `--print-body` prints to a terminal; redirecting stdout to a file prints the body without it.

=== "Go"

    ```go
    client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
    if err != nil { return err }
    defer client.Close()

    response, err := client.Do(&tlsforge.Request{
        Method: "POST",
        URL: "https://example.com/api",
        Header: tlsforge.NewHeader("content-type", "application/json"),
        Body: []byte(`{"hello":"world"}`),
        Browser: &tlsforge.BrowserContext{
            Kind: tlsforge.KindFetch,
            Initiator: "https://example.com/",
        },
    })
    if err != nil { return err }
    fmt.Println(response.Status, response.Text())
    ```

    The Go API requires a browser context for a non-GET with the shipped Chrome profiles. A nil `Body` means no body; a non-nil empty slice means an explicit zero-byte upload.

=== "Node.js"

    ```js
    const response = await client.post(
      'https://example.com/api',
      JSON.stringify({ hello: 'world' }),
      {
        headers: { 'content-type': 'application/json' },
        browserContext: { kind: 'fetch', initiator: 'https://example.com/' },
      },
    );
    console.log(response.status, response.body);
    ```

=== "Python"

    ```python
    response = client.post(
        "https://example.com/api",
        '{"hello":"world"}',
        headers={"content-type": "application/json"},
        browser_context={"kind": "fetch", "initiator": "https://example.com/"},
    )
    print(response.status, response.body)
    ```

## Response behaviour

The CLI can print a body, status and headers, or JSON Lines; see [output and diagnostics](diagnostics.md). SDKs return a response object containing status, final URL, headers, cookies, text and raw body bytes. A non-2xx HTTP response is still a response; a DNS, TLS, transport, or execution failure is an error. SDK request methods do not provide the CLI's `--wait-for` or report writer: implement those application checks using the returned response.

Request URLs must be absolute HTTP or HTTPS URLs. The engine canonicalizes them using its browser URL rules and refuses unsupported input before sending it. `--timeout` and SDK timeouts bound the whole request, including redirects and body handling.
