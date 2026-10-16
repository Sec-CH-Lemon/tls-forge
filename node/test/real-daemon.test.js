import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { test } from 'node:test';
import zlib from 'node:zlib';

import { Client, MAX_REQUEST_BYTES } from '../index.js';

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

test('a deflate page from the real Go daemon arrives decoded, its fields describing it', { skip: !binary }, async () => {
  // deflate in the zlib form the name means: the transport used to hang on it
  // until the request's deadline.
  const page = 'a page worth compressing. '.repeat(50);
  const server = http.createServer((_request, response) => {
    response.setHeader('content-encoding', 'deflate');
    response.end(zlib.deflateSync(page));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  const client = new Client({ binary, timeout: 10_000 });
  try {
    const response = await client.get(`http://127.0.0.1:${server.address().port}/page`);
    assert.equal(response.body, page);
    assert.equal(response.headers['content-encoding'], undefined);
    assert.equal(response.headers['content-length'], undefined);
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

// listen starts a server on a port of its own on this machine.
async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server;
}

// tunnelling is a proxy that opens a tunnel for a CONNECT that says who it is
// with the right password, and turns away any other, as a paid proxy does. It
// keeps where each tunnel went.
async function tunnelling(user, password) {
  const tunnels = [];
  const proxy = http.createServer((_request, response) => {
    response.statusCode = 405;
    response.end();
  });
  proxy.on('connect', (request, socket, head) => {
    const expected = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
    if (request.headers['proxy-authorization'] !== expected) {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    tunnels.push(request.url);
    const [host, port] = request.url.split(':');
    const upstream = net.connect(Number(port), host, () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  });
  await listen(proxy);
  return { proxy, tunnels, url: `http://${user}:${password}@127.0.0.1:${proxy.address().port}` };
}

test('the real Go daemon goes through the proxy its environment names', { skip: !binary }, async () => {
  // The URL, password and all, reaches the daemon in its environment, named on
  // its command line by --proxy-env: a daemon that did not read it would go
  // to the site directly, and the proxy would see no tunnel.
  let asked = 0;
  const origin = await listen(http.createServer((_request, response) => {
    asked += 1;
    response.end('through the proxy');
  }));
  const { proxy, tunnels, url } = await tunnelling('alice', 's3cret');
  const client = new Client({ binary, proxy: url, timeout: 10_000 });
  try {
    const response = await client.get(`http://127.0.0.1:${origin.address().port}/`);
    assert.equal(response.body, 'through the proxy');
    assert.deepEqual(tunnels, [`127.0.0.1:${origin.address().port}`]);
    assert.equal(asked, 1);
  } finally {
    client.close();
    await new Promise((resolve) => proxy.close(resolve));
    await new Promise((resolve) => origin.close(resolve));
  }
});

test('a proxy the real Go daemon turns down says why without its password', { skip: !binary }, async () => {
  const origin = await listen(http.createServer((_request, response) => response.end('never')));
  const { proxy, tunnels } = await tunnelling('alice', 's3cret');
  const port = proxy.address().port;
  for (const url of [
    // One that will not parse: quoted back whole by whatever tried to read it.
    'http://alice:s3cret-never-shown@[bad',
    // One that answers 407 to a password it does not know.
    `http://alice:s3cret-never-shown@127.0.0.1:${port}`,
  ]) {
    const client = new Client({ binary, proxy: url, timeout: 10_000 });
    try {
      await assert.rejects(() => client.get(`http://127.0.0.1:${origin.address().port}/`), (err) => {
        assert.ok(!err.message.includes('s3cret-never-shown'), err.message);
        return true;
      });
    } finally {
      client.close();
    }
  }
  assert.deepEqual(tunnels, []);
  await new Promise((resolve) => proxy.close(resolve));
  await new Promise((resolve) => origin.close(resolve));

  // What the daemon itself says of the one it cannot read, as the client
  // starts it: its last words, read here to the end.
  const started = spawnSync(binary, ['daemon', '--proxy-env=TLSFORGE_PROXY'], {
    env: { ...process.env, TLSFORGE_PROXY: 'http://alice:s3cret-never-shown@[bad' },
    input: '',
    encoding: 'utf8',
  });
  assert.equal(started.status, 1, started.stderr);
  assert.match(started.stderr, /\[redacted\]@\[bad/);
  assert.ok(!started.stderr.includes('s3cret-never-shown'), started.stderr);
});

test('the real Go daemon reads a request as long as the limit, and keeps its session past one longer', { skip: !binary }, async () => {
  // The limit this client refuses a request at has to be the daemon's, to the
  // byte: one byte under it, and the daemon would end, its session with it.
  let seen = null;
  const origin = await listen(http.createServer((request, response) => {
    if (request.url === '/set') {
      response.setHeader('set-cookie', 'visitor=42; Path=/');
      response.end('set');
      return;
    }
    let length = 0;
    request.on('data', (chunk) => { length += chunk.length; });
    request.on('end', () => {
      seen = { cookie: request.headers.cookie ?? '', length };
      response.end('seen');
    });
  }));
  const base = `http://127.0.0.1:${origin.address().port}`;
  const client = new Client({ binary, timeout: 60_000 });
  try {
    await client.get(`${base}/set`);
    const url = `${base}/echo`;
    const overhead = Buffer.byteLength(JSON.stringify({ url, body: '', method: 'POST', id: 2 }) + '\n');
    const body = 'x'.repeat(MAX_REQUEST_BYTES - overhead);
    await client.post(url, body);
    assert.deepEqual(seen, { cookie: 'visitor=42', length: body.length });

    await assert.rejects(() => client.post(url, `${body}x`), RangeError);
    await client.get(url);
    assert.deepEqual(seen, { cookie: 'visitor=42', length: 0 });
  } finally {
    client.close();
    await new Promise((resolve) => origin.close(resolve));
  }
});
