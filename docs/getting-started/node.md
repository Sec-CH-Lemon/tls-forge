# Install for Node.js

Node.js **20.12** or newer is required:

```bash title="Terminal"
npm install tls-forge
```

The package is ESM and uses an included platform transport binary through optional dependencies. Avoid `--no-optional` unless you provide your own matching executable. For a development build:

```bash title="Terminal"
export TLSFORGE_BIN=/absolute/path/to/tls-forge
```

```js title="Node.js"
import { Client } from 'tls-forge';

const client = new Client({ profile: 'chrome' });
try {
  const response = await client.get('https://example.com/');
  console.log(response.status, response.body);
} finally {
  client.close();
}
```

The SDK starts the Go daemon lazily, checks its engine identity, and uses one process per `Client`. Continue with the [Node.js guide](../integrations/node.md) and [generated API reference](../reference/node-api.md).
