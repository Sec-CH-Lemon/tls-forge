# Choose an interface

<p class="tf-lede">Use the same engine from the command line, an SDK, or a local proxy.</p>

<div class="tf-card-grid">
  <a class="tf-card" href="cli/"><strong>CLI</strong><span>Fetch URLs, run batches, capture browsers, compare results, and write reports.</span></a>
  <a class="tf-card" href="go/"><strong>Go library</strong><span>Use the native client, options, and measurement packages.</span></a>
  <a class="tf-card" href="node/"><strong>Node.js SDK</strong><span>Use an ESM client backed by the engine-matched daemon.</span></a>
  <a class="tf-card" href="python/"><strong>Python SDK</strong><span>Use a context-managed client with typed responses.</span></a>
  <a class="tf-card" href="proxy/"><strong>Local proxy</strong><span>Route an existing HTTP(S) caller through a new profile-shaped connection.</span></a>
  <a class="tf-card" href="daemon/"><strong>Daemon protocol</strong><span>Connect another language through the JSON Lines interface.</span></a>
</div>

Every interface uses the same engine and an executable JSON profile. They differ in orchestration and diagnostics.

| Capability | CLI | Go | Node.js | Python | Local proxy |
| --- | --- | --- | --- | --- | --- |
| One GET or POST | `fetch` | `Get` / `Do` | `get` / `post` / `request` | `get` / `post` / `request` | Caller sends HTTP(S) |
| Browser context | `--request-kind` | `Request.Browser` | `browserContext` | `browser_context` | Incoming browser request metadata |
| Upstream proxy | `--proxy` / `--proxy-env` | `WithProxy` | `proxy` option | `proxy` option | `proxy --proxy` |
| Cookies | `--cookie`, files | client/request options | constructor/request options | constructor/request options | Caller-managed |
| URL list and concurrency | Built in | Application code | Application code / client pool | Application code / client pool | Caller-managed |
| Capture and compare | Commands | Measurement API | CLI invocation | CLI invocation | No |
| HTML/JSON report, trace, PCAPNG | Built in | Trace and key-log APIs | Application code | Application code | No CLI report writer |
| Low-level daemon protocol | `daemon` | `daemon` package | Used internally | Used internally | No |

## Same task, four ways

All four examples request a response from `https://example.com/` using the `chrome` profile.

=== "CLI"

    ```bash
    tls-forge fetch --profile chrome --print-body https://example.com/
    ```

=== "Go"

    ```go
    client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
    if err != nil { return err }
    defer client.Close()
    response, err := client.Get("https://example.com/")
    ```

=== "Node.js"

    ```js
    const client = new Client({ profile: 'chrome' });
    try { const response = await client.get('https://example.com/'); }
    finally { client.close(); }
    ```

=== "Python"

    ```python
    with tlsforge.Client(profile="chrome") as client:
        response = client.get("https://example.com/")
    ```

For a POST, supply a real [browser context](../guides/browser-context.md). SDKs do not inherit every CLI feature; the table identifies where the application must own the equivalent work.
