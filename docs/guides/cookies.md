# Cookies and sessions

The bundled profiles make each request a fresh browser network instance. Redirects, preflights, authentication restarts and protocol retries inside one request share that request's state. Separate calls do not automatically inherit cookies, HTTP cache, connections or TLS tickets. A custom profile may explicitly set `behavior.http.instance_scope` to `client` for a persistent sequence.

## Seed or save cookies

=== "CLI"

    ```bash
    tls-forge fetch --cookie 'session=abc' https://example.com/
    tls-forge fetch --cookies cookies.json --cookie-set warm-eu \
      --save-cookies updated.json https://example.com/
    ```

    `--save-cookies` writes the end-of-run state. A `.txt` destination writes Netscape `cookies.txt` format.

=== "Go"

    ```go
    client, err := tlsforge.New(tlsforge.WithCookies([]tlsforge.Cookie{
        {Name: "session", Value: "abc", Domain: "example.com"},
    }))
    ```

    Go also exposes `Response.AllCookies`, `Client.Fresh`, and cookie file helpers. The response snapshot from one request is not automatically applied to another request-scoped call.

=== "Node.js"

    ```js
    const client = new Client({ cookieFile: '/path/cookies.json', cookieSet: 'warm-eu' });
    const response = await client.get('https://example.com/', { cookies: ['session=abc'] });
    ```

=== "Python"

    ```python
    with tlsforge.Client(cookie_file="/path/cookies.json", cookie_set="warm-eu") as client:
        response = client.get("https://example.com/", cookies=["session=abc"])
    ```

A caller-supplied `Cookie` header is one request's header; cookie inputs through the jar are scoped by URL and may participate in redirects. Avoid putting the same name in both places. Use the returned response's `cookies` or Go cookie snapshot to inspect what was retained for the final URL. The SDKs have no `--save-cookies` option; application code can persist returned cookie data according to its own format.
