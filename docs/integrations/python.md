# Python SDK

The typed package starts a matching Go daemon lazily. Its `Client` serializes calls and is a context manager; create separate clients for parallel work.

```python
import tlsforge

with tlsforge.Client(profile="chrome", timeout=45.0) as client:
    response = client.request(
        "https://example.com/api",
        method="POST",
        body=b'{"hello":"world"}',
        headers={"content-type": "application/json"},
        browser_context={"kind": "fetch", "initiator": "https://example.com/"},
    )
    print(response.status, response.content)
```

The constructor accepts a profile, upstream proxy, timeout, binary path, certificate-validation choice, warm cookie file and set, and stderr callback. Requests accept headers, header order, cookies, browser context and actual network context. `Response.body` is text; `Response.content` preserves bytes, and `Response.json()` parses JSON. A non-2xx response is returned normally.

`get`, `post`, `request`, `hello`, `close` and the context-manager methods are public. The [generated Python API reference](../reference/python-api.md) lists signatures, fields and errors. The SDK checks daemon major and capabilities before use. It does not provide the CLI's capture, comparison, report or PCAPNG commands.
