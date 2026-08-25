import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client } from 'tls-forge';

const defaultURL = 'https://tls.browserleaks.com/json';
const target = process.argv[2] ?? defaultURL;
const executable = process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge';
const repositoryBinary = fileURLToPath(new URL(`../../bin/${executable}`, import.meta.url));
const binary = process.env.TLSFORGE_BIN
  ?? (existsSync(repositoryBinary) ? repositoryBinary : undefined);

const client = new Client({
  profile: 'chrome',
  ...(binary ? { binary } : {}),
});

try {
  const response = await client.get(target);
  console.log(`status: ${response.status}`);
  console.log(`url: ${response.url}\n`);
  console.log(response.body);
} finally {
  client.close();
}
