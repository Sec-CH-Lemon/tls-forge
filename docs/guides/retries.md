# Retries and page checks

## Retry a CLI fetch

```bash
tls-forge fetch --retry 3 --wait-for-element '#price' \
  https://example.com/product
tls-forge fetch --retry 3 --wait-for '/in stock/i' \
  https://example.com/product
```

`--retry` repeats on a non-2xx answer or transport failure. `--wait-for` and `--wait-for-element` instead decide success from the response body, regardless of HTTP status. The element check parses returned HTML; it does not run page scripts. `--html-decoding` selects how the body is decoded for those checks. `-X HEAD` cannot be combined with a body check.

For a browser-style reload after an answer, `--retry-as-browser` requires `--retry` and a **client-scoped** profile. It can reuse the response URL, cookies, client hints and connection according to that profile. `--reuse-connection` and `--fresh-connection` control CLI connection reuse in the documented scopes; see the [CLI flag reference](../reference/cli.md).

## SDK equivalents

SDKs expose response status, body and errors, so callers can implement their own retry and page condition. Go also exposes `Request.Reload` and `Request.Reloaded` for a supported browser reload sequence. SDKs do not expose CLI's `--wait-for`, `--wait-for-element`, or `--retry-as-browser` switch directly.

Be careful with non-idempotent requests: a retry can repeat an operation after the server has applied it. Profile transport retry rules are independent of an application's own retry loop. Keep the profile and retry policy aligned with the operation being sent.
