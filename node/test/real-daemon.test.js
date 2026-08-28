import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';

import { Client } from '../index.js';

const binary = process.env.TLSFORGE_REAL_BIN;

test('the Node wrapper decodes bytes emitted by the real Go daemon', { skip: !binary }, async () => {
  const want = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0xd8, 0xff]);
  const server = http.createServer((_request, response) => {
    response.setHeader('set-cookie', ['a=1', 'b=2']);
    response.end(want);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  const client = new Client({ binary });
  try {
    const address = server.address();
    const response = await client.get(`http://127.0.0.1:${address.port}/binary`);
    assert.deepEqual(response.content, want);
    assert.deepEqual(response.headers['set-cookie'], ['a=1', 'b=2']);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
