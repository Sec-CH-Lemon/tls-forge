// The Node.js example in TypeScript: the same request, checked against the
// package's types by `npm run check`, and run as it is by Node, which strips
// the types.
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client, type ClientOptions, type Response } from 'tls-forge';

const defaultURL = 'https://tls.browserleaks.com/json';
const target = process.argv[2] ?? defaultURL;
const executable = process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge';
const repositoryBinary = fileURLToPath(new URL(`../../bin/${executable}`, import.meta.url));
const binary = process.env.TLSFORGE_BIN ?? (existsSync(repositoryBinary) ? repositoryBinary : undefined);

const options: ClientOptions = { profile: 'chrome', ...(binary ? { binary } : {}) };
const client = new Client(options);

try {
  const response: Response = await client.get(target);
  console.log(`status: ${response.status}`);
  console.log(`url: ${response.url}\n`);
  console.log(response.body);
} finally {
  client.close();
}
