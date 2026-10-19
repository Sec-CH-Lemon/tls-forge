import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import { test } from 'node:test';
import zlib from 'node:zlib';

import { Client, MAX_REQUEST_BYTES, RequestFailed } from '../index.js';

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

test('the real Go daemon follows nineteen redirects and stops at the twentieth', { skip: !binary }, async () => {
  // As Chrome 155 does, and as the CLI and the Go library do: twenty requests,
  // the twentieth redirect not followed, and nothing past it asked.
  let requests = 0;
  let ends = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    const left = Number(request.url.slice('/chain/'.length));
    if (left === 0) {
      ends += 1;
      response.end('landed');
      return;
    }
    response.writeHead(302, { location: `/chain/${left - 1}` });
    response.end();
  });
  await listen(server);
  const client = new Client({ binary, timeout: 10_000 });
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const [redirects, landed] of [[19, true], [20, false], [21, false]]) {
      requests = 0;
      ends = 0;
      const asked = client.get(`${base}/chain/${redirects}`);
      if (landed) {
        assert.equal((await asked).body, 'landed');
      } else {
        await assert.rejects(asked, /the 20th redirect was not followed/);
      }
      assert.deepEqual({ redirects, requests, ends }, { redirects, requests: 20, ends: landed ? 1 : 0 });
    }
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
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

test('the real Go daemon goes through the proxy its input names', { skip: !binary }, async () => {
  // The URL, password and all, reaches the daemon on the first line of its
  // input, the init line --proxy-stdin asks for: a daemon that did not read it
  // would go to the site directly, and the proxy would see no tunnel.
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
  // starts it: its answer to the init line and its last words, read here to
  // the end.
  const started = spawnSync(binary, ['daemon', '--proxy-stdin'], {
    input: JSON.stringify({ id: 1, control: 'init', proxy: 'http://alice:s3cret-never-shown@[bad' }) + '\n',
    encoding: 'utf8',
  });
  assert.equal(started.status, 1, started.stderr);
  assert.match(started.stderr, /\[redacted\]@\[bad/);
  assert.equal(JSON.parse(started.stdout).id, 1);
  assert.match(JSON.parse(started.stdout).error, /\[redacted\]@\[bad/);
  assert.ok(!(started.stderr + started.stdout).includes('s3cret-never-shown'), started.stderr);
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

test('the real Go daemon keeps no cookie of an answer to a request without credentials', { skip: !binary }, async () => {
  // fetch() with credentials omit carries no cookies and keeps none its
  // answer sets, as Chrome's; one with the page's own credentials keeps them.
  const server = http.createServer((request, response) => {
    response.setHeader('Set-Cookie', `${request.url.slice(1)}=1; Path=/`);
    response.end('ok');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const client = new Client({ binary });
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const from = `${base}/page`;
    const omitted = await client.get(`${base}/omitted`, {
      browserContext: { kind: 'fetch', initiator: from, credentials: 'omit' },
    });
    assert.deepEqual(omitted.cookies, []);
    const kept = await client.get(`${base}/kept`, { browserContext: { kind: 'fetch', initiator: from } });
    assert.deepEqual(kept.cookies, ['kept=1']);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('the real Go daemon applies a browser context, CORS and all', { skip: !binary }, async () => {
  // Two servers, two origins: the page's, and another one CORS answers for.
  const serve = (answer) => {
    const seen = [];
    const server = http.createServer((request, response) => {
      seen.push({ method: request.method, url: request.url, headers: request.headers });
      answer(request, response);
    });
    return { seen, server };
  };
  const page = serve((_request, response) => response.end('ok'));
  const other = serve((_request, response) => {
    response.statusCode = 403;
    response.end();
  });
  await Promise.all([page, other].map(({ server }) => new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))));
  const client = new Client({ binary });
  try {
    const base = `http://127.0.0.1:${page.server.address().port}`;
    const elsewhere = `http://127.0.0.1:${other.server.address().port}`;
    assert.deepEqual(await client.hello(), { protocol: 2, capabilities: ['browser_context'] });
    const from = `${base}/page`;
    const response = await client.get(`${base}/api`, { browserContext: { kind: 'fetch', initiator: from } });
    assert.equal(response.status, 200);
    const api = page.seen.find((hit) => hit.url === '/api');
    assert.equal(api.headers['sec-fetch-mode'], 'cors');
    assert.equal(api.headers['sec-fetch-site'], 'same-origin');
    assert.equal(api.headers.accept, '*/*');
    assert.equal(api.headers.referer, from);
    assert.equal(api.headers['upgrade-insecure-requests'], undefined);

    // JSON to the other origin asks first, is refused, and nothing more goes.
    await assert.rejects(
      client.request({
        url: `${elsewhere}/cart`, method: 'POST', body: '{}', headers: { 'content-type': 'application/json' },
        browserContext: { kind: 'fetch', initiator: from },
      }),
      /CORS: the preflight of POST .* refused it: it was answered 403/,
    );
    assert.deepEqual(other.seen.map((hit) => hit.method), ['OPTIONS']);

    // A context the daemon cannot send is refused, and nothing is sent; a key
    // the protocol does not have is refused before it is asked.
    const before = page.seen.length;
    await assert.rejects(
      client.get(`${base}/x`, { browserContext: { kind: 'websocket', initiator: from } }),
      (err) => err instanceof RequestFailed && /kind "websocket" is not navigation, form, fetch or xhr/.test(err.message),
    );
    await assert.rejects(
      client.get(`${base}/x`, { browserContext: { kind: 'fetch', initiator: from, frame: 'top' } }),
      (err) => err instanceof TypeError && /browserContext has no key "frame"/.test(err.message),
    );
    assert.equal(page.seen.length, before);
  } finally {
    client.close();
    await Promise.all([page, other].map(({ server }) => new Promise((resolve) => server.close(resolve))));
  }
});
