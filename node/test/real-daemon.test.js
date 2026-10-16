import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
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

test('a request the real Go daemon cannot make rejects', { skip: !binary }, async () => {
  // A port that was listening a moment ago and is not any more: refused at
  // once, on every platform, without reaching anything outside this machine.
  const closed = net.createServer();
  await new Promise((resolve) => closed.listen(0, '127.0.0.1', resolve));
  const { port } = closed.address();
  await new Promise((resolve) => closed.close(resolve));

  const client = new Client({ binary });
  try {
    await assert.rejects(() => client.get(`http://127.0.0.1:${port}/`), /refused/i);
  } finally {
    client.close();
  }
});
