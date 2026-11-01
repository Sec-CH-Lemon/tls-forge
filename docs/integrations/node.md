# Node.js SDK

The ESM package starts a matching Go daemon lazily and exposes one `Client` per process. It serializes a client's requests. For parallel work, create separate clients and close each one.

```js
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome', timeout: 45_000 });
try {
  const response = await client.request({
    url: 'https://example.com/api',
    method: 'POST',
    body: JSON.stringify({ hello: 'world' }),
    headers: { 'content-type': 'application/json' },
    browserContext: { kind: 'fetch', initiator: 'https://example.com/' },
  });
  console.log(response.status, response.headers, response.content);
} finally {
  client.close();
}
```

The constructor accepts a profile, upstream proxy, timeout, binary path, certificate-validation choice, warm cookie file and set, and stderr callback. Request options include headers, header order, cookies, browser context and actual network context. `get`, `post`, `request`, `hello` and `close` are the public methods. The [generated TypeScript API reference](../reference/node-api.md) has their exact signatures and error types.

`hello()` discovers the daemon offline; each request still pins the SDK engine major. The SDK rejects an older or mismatched transport rather than silently using it. The package does not run a browser or provide CLI reports, capture or compare commands.
