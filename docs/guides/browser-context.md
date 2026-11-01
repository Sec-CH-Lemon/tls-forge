# Browser contexts

A network fingerprint alone does not say **why** a browser sent a request. A navigation, form submission, `fetch()`, and XHR can have different headers, CORS behaviour, cookies, priorities and connection use. Supply the request's real initiator page when you know it.

| Kind | Typical request | Required context |
| --- | --- | --- |
| `navigation` | Address bar or link | `initiator` only for a page-originated navigation |
| `form` | Form GET or POST | Initiator page |
| `fetch` | Page script's `fetch()` | Initiator page; optional mode and credentials |
| `xhr` | Page script's XHR | Initiator page; optional credentials |

=== "CLI"

    ```bash
    tls-forge fetch --request-kind fetch \
      --initiator-url https://example.com/page \
      -H 'Accept: application/json' \
      https://example.com/api
    ```

    For a clicked link or submitted form, add `--clicked`; for a form submission use `--form`. The CLI's `--request-kind` and `--initiator-url` determine the context of every URL in that invocation.

=== "Go"

    ```go
    response, err := client.Do(&tlsforge.Request{
        URL: "https://example.com/api",
        Browser: &tlsforge.BrowserContext{
            Kind: tlsforge.KindFetch,
            Initiator: "https://example.com/page",
            Mode: "cors",
            Credentials: "same-origin",
        },
    })
    ```

=== "Node.js"

    ```js
    const response = await client.get('https://example.com/api', {
      browserContext: {
        kind: 'fetch',
        initiator: 'https://example.com/page',
        mode: 'cors',
        credentials: 'same-origin',
      },
    });
    ```

=== "Python"

    ```python
    response = client.get(
        "https://example.com/api",
        browser_context={
            "kind": "fetch",
            "initiator": "https://example.com/page",
            "mode": "cors",
            "credentials": "same-origin",
        },
    )
    ```

The CLI supports the `clicked` flag. Go's `BrowserContext` also exposes `Clicked` and `Sent` for click and already-sent browser requests. The Node.js and Python public browser-context types currently expose the four kinds, initiator, referrer policy, mode, and credentials; they do not expose every Go-only field. Compare only the scenario you actually model.
