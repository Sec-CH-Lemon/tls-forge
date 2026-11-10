import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import http from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { test } from 'node:test';
import zlib from 'node:zlib';

import { Client, MAX_REQUEST_BYTES, RequestFailed, type BrowserContext, type RequestOptions } from '../src/index.ts';

const binary = process.env.TLSFORGE_REAL_BIN;

// portOf is the port a listening server was given.
function portOf(server: net.Server): number {
  const address = server.address();
  assert.ok(address !== null && typeof address === 'object', 'not listening on a port');
  return address.port;
}

test('the Node wrapper decodes bytes emitted by the real Go daemon', { skip: !binary }, async () => {
  const want = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0xd8, 0xff]);
  const server = http.createServer((_request, response) => {
    response.setHeader('set-cookie', ['a=1', 'b=2']);
    response.end(want);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const client = new Client({ binary });
  try {
    const response = await client.get(`http://127.0.0.1:${portOf(server)}/binary`);
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
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const client = new Client({ binary, timeout: 10_000 });
  try {
    const response = await client.get(`http://127.0.0.1:${portOf(server)}/page`);
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
  await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
  const port = portOf(closed);
  await new Promise((resolve) => closed.close(resolve));

  const client = new Client({ binary });
  try {
    await assert.rejects(() => client.get(`http://127.0.0.1:${port}/`), /refused/i);
  } finally {
    client.close();
  }
});

test('the real Go daemon follows nineteen redirects and stops at the twentieth', { skip: !binary }, async () => {
  // Navigation follows nineteen redirects; Fetch uses a separate twenty-hop bound.
  let requests = 0;
  let ends = 0;
  const server = http.createServer((request, response) => {
    requests += 1;
    const left = Number(request.url!.slice('/chain/'.length));
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
    const base = `http://127.0.0.1:${portOf(server)}`;
    for (const [redirects, landed] of [[19, true], [20, false], [21, false]] as [number, boolean][]) {
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
async function listen<T extends net.Server>(server: T): Promise<T> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server;
}

// tunnelling is a proxy that opens a tunnel for a CONNECT that says who it is
// with the right password, and turns away any other, as a paid proxy does. It
// keeps where each tunnel went.
async function tunnelling(user: string, password: string) {
  const tunnels: string[] = [];
  const proxy = http.createServer((request, response) => {
    const expected = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
    if (request.headers['proxy-authorization'] !== expected) {
      response.writeHead(407, { 'content-length': '0' });
      response.end();
      return;
    }
    const target = new URL(request.url!);
    assert.equal(target.protocol, 'http:');
    assert.equal(target.hostname, '127.0.0.1');
    tunnels.push(target.host);
    const headers: http.OutgoingHttpHeaders = { ...request.headers, connection: 'close' };
    delete headers['proxy-authorization'];
    delete headers['proxy-connection'];
    const upstream = http.request(target, { method: request.method, headers }, (answer) => {
      response.writeHead(answer.statusCode!, answer.headers);
      answer.pipe(response);
    });
    upstream.on('error', () => response.destroy());
    request.pipe(upstream);
  });
  proxy.on('connect', (request, socket, head) => {
    const expected = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
    if (request.headers['proxy-authorization'] !== expected) {
      socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    tunnels.push(request.url!);
    const [host, port] = request.url!.split(':');
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
  return { proxy, tunnels, url: `http://${user}:${password}@127.0.0.1:${portOf(proxy)}` };
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
    const response = await client.get(`http://127.0.0.1:${portOf(origin)}/`);
    assert.equal(response.body, 'through the proxy');
    assert.deepEqual(tunnels, [`127.0.0.1:${portOf(origin)}`]);
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
  const port = portOf(proxy);
  for (const url of [
    // One that will not parse: quoted back whole by whatever tried to read it.
    'http://alice:s3cret-never-shown@[bad',
    // One that answers 407 to a password it does not know.
    `http://alice:s3cret-never-shown@127.0.0.1:${port}`,
  ]) {
    const client = new Client({ binary, proxy: url, timeout: 10_000 });
    try {
      await assert.rejects(() => client.get(`http://127.0.0.1:${portOf(origin)}/`), (err: Error) => {
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
  const started = spawnSync(binary!, ['daemon', '--proxy-stdin'], {
    input: JSON.stringify({ id: 1, engine_major: 2, control: 'init', proxy: 'http://alice:s3cret-never-shown@[bad' }) + '\n',
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
  let seen: { cookie: string; length: number } | null = null;
  const origin = await listen(http.createServer((request, response) => {
    if (request.url === '/set') {
      response.setHeader('set-cookie', 'visitor=42; Path=/');
      response.end('set');
      return;
    }
    let length = 0;
    request.on('data', (chunk: Buffer) => { length += chunk.length; });
    request.on('end', () => {
      seen = { cookie: request.headers.cookie ?? '', length };
      response.end('seen');
    });
  }));
  const base = `http://127.0.0.1:${portOf(origin)}`;
  const client = new Client({ binary, timeout: 60_000 });
  try {
    await client.get(`${base}/set`);
    const url = `${base}/echo`;
    // As a page's script posts: a request without a browser context is a
    // navigation typed into the address bar, which posts nothing.
    const browserContext: BrowserContext = { kind: 'fetch', initiator: `${base}/` };
    const overhead = Buffer.byteLength(JSON.stringify({
      url, body: '', method: 'POST', browser: browserContext, id: 3, engine_major: 2,
    }) + '\n');
    const body = 'x'.repeat(MAX_REQUEST_BYTES - overhead);
    await client.post(url, body, { browserContext });
    assert.deepEqual(seen, { cookie: '', length: body.length });

    await assert.rejects(() => client.post(url, `${body}x`, { browserContext }), RangeError);
    await client.get(url);
    assert.deepEqual(seen, { cookie: '', length: 0 });
  } finally {
    client.close();
    await new Promise((resolve) => origin.close(resolve));
  }
});

test('the real Go daemon keeps no cookie of an answer to a request without credentials', { skip: !binary }, async () => {
  // fetch() with credentials omit carries no cookies and keeps none its
  // answer sets, as Chrome's; one with the page's own credentials keeps them.
  const server = http.createServer((request, response) => {
    response.setHeader('Set-Cookie', `${request.url!.slice(1)}=1; Path=/`);
    response.end('ok');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const client = new Client({ binary });
  try {
    const base = `http://127.0.0.1:${portOf(server)}`;
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
  const serve = (answer: http.RequestListener) => {
    const seen: { method?: string; url?: string; headers: http.IncomingHttpHeaders }[] = [];
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
  await Promise.all([page, other].map(({ server }) => new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))));
  const client = new Client({ binary });
  try {
    const base = `http://127.0.0.1:${portOf(page.server)}`;
    const elsewhere = `http://127.0.0.1:${portOf(other.server)}`;
    assert.deepEqual(await client.hello(), { protocol: 3, capabilities: ['browser_context', 'engine_major', 'catalogue_json_v1', 'network_hints_estimator_v1', 'network_context_v1'], engine_major: 2, version: '2.0.0' });
    const from = `${base}/page`;
    const response = await client.get(`${base}/api`, { browserContext: { kind: 'fetch', initiator: from } });
    assert.equal(response.status, 200);
    const api = page.seen.find((hit) => hit.url === '/api');
    assert.ok(api);
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
      // @ts-expect-error -- a kind the daemon does not send
      client.get(`${base}/x`, { browserContext: { kind: 'websocket', initiator: from } }),
      (err: Error) => err instanceof RequestFailed && /kind "websocket" is not navigation, form, fetch or xhr/.test(err.message),
    );
    await assert.rejects(
      // @ts-expect-error -- a key the protocol does not have
      client.get(`${base}/x`, { browserContext: { kind: 'fetch', initiator: from, frame: 'top' } }),
      (err: Error) => err instanceof TypeError && /browserContext has no key "frame"/.test(err.message),
    );
    assert.equal(page.seen.length, before);
  } finally {
    client.close();
    await Promise.all([page, other].map(({ server }) => new Promise((resolve) => server.close(resolve))));
  }
});


test('invalid profile semantics fail before real daemon origin or proxy I/O', { skip: !binary }, async () => {
  let connections = 0;
  const server = net.createServer((socket) => { connections += 1; socket.destroy(); });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const dir = mkdtempSync(join(tmpdir(), 'tlsforge-a6-'));
  const profile = JSON.parse(readFileSync(new URL('../../profile/data/chrome_155/macos.json', import.meta.url), 'utf8'));
  profile.name = 'sdk-semantic-negative';
  profile.http2.settings = [{ id: 5, value: 1 }];
  const file = join(dir, 'renamed.json');
  writeFileSync(file, JSON.stringify(profile));
  const address = `127.0.0.1:${portOf(server)}`;
  try {
    for (const proxy of [undefined, `http://${address}`, `https://${address}`, `socks5://${address}`]) {
      let diagnostic = (): void => {};
      const seen = new Promise<void>((resolve) => { diagnostic = resolve; });
      const client = new Client({ binary, profile: file, proxy, timeout: 2_000, onStderr: (line) => {
        if (line.includes('http2.settings[0].value') && line.includes('sdk-semantic-negative')) diagnostic();
      } });
      try {
        await assert.rejects(client.get(`https://${address}/`));
        await Promise.race([seen, new Promise((_, reject) => {
          const timer = setTimeout(() => reject(new Error('profile field diagnostic missing')), 1_000);
          timer.unref();
        })]);
      } finally { client.close(); }
    }
    assert.equal(connections, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await new Promise((resolve) => server.close(resolve));
  }
});

test('the real daemon rejects invalid UTF-8 URL hosts before transport', { skip: !binary }, async () => {
  const client = new Client({ binary });
  try {
    for (const host of ['%80.invalid', '%C0%AF.invalid', '%ED%A0%80.invalid']) {
      await assert.rejects(() => client.get(`https://${host}/`), /not valid UTF-8/);
    }
  } finally {
    client.close();
  }
});

test('each Node request through the real daemon owns a cold browser', { skip: !binary }, async () => {
  const peers: (number | undefined)[] = [], cookies: string[] = [];
  const origin = await listen(http.createServer((request, response) => {
    peers.push(request.socket.remotePort);
    cookies.push(request.headers.cookie ?? '');
    assert.equal(request.headers['if-none-match'], undefined);
    response.writeHead(200, { 'cache-control': 'max-age=600', etag: '"v1"', 'set-cookie': 'received=secret; Path=/' });
    response.end(`body-${peers.length}`);
  }));
  const client = new Client({ binary });
  try {
    const base = `http://127.0.0.1:${portOf(origin)}`;
    for (let i = 1; i <= 4; i++) {
      const options: RequestOptions = i <= 2 ? {} : { browserContext: { kind: 'fetch', initiator: `${base}/start` } };
      assert.equal((await client.get(`${base}/page`, options)).body, `body-${i}`);
    }
    assert.deepEqual(cookies, ['', '', '', '']);
    assert.equal(new Set(peers).size, 4);
  } finally {
    client.close();
    await new Promise((resolve) => origin.close(resolve));
  }
});

test('typed network metadata selects JSON estimator seeds in the real daemon', {skip:!binary}, async()=>{
 const p=JSON.parse(readFileSync(new URL('../../profile/data/chrome_156/macos.json',import.meta.url),'utf8'));
 const policy=JSON.parse(readFileSync(new URL('../../networkquality/testdata/chromium156-nqe-source-candidate.json',import.meta.url),'utf8'));
 p.client_hints=p.client_hints.filter((h: {name: string})=>!['rtt','downlink','ect'].includes(h.name));p.headers=p.headers.filter((h: {name: string})=>!['rtt','downlink','ect'].includes(h.name));
 policy.cache.enabled=false;policy.cache.read_after_bootstrap=false;policy.compute.sparse_rtt_cap_ms=0;policy.compute.use_end=false;policy.compute.transport_lower=0;
 policy.noise.salt_min=1;policy.noise.salt_max=1;policy.noise.buckets=1;policy.noise.base=1;policy.noise.step=0;policy.noise.rtt_quantum_ms=10;
 for(const seed of policy.seeds){seed.http_ms={value:seed.type==='wifi'?1110:2220,available:true};seed.transport_ms={value:0,available:false};seed.downlink_kbps={value:0,available:false}}
 p.network_hints={mode:'estimated',policy};
 const dir=mkdtempSync(join(tmpdir(),'tls-forge-nqe-'));const path=join(dir,'profile.json');writeFileSync(path,JSON.stringify(p));
 let requests=0;
 const server=http.createServer((request,response)=>{requests++;response.setHeader('Accept-CH','rtt');response.setHeader('Critical-CH','rtt');response.setHeader('Cache-Control','no-store');response.end(request.headers.rtt??'');});
 await new Promise<void>((resolve)=>server.listen(0,'127.0.0.1',resolve));
 const c=new Client({binary,profile:path});
 try{
  const url=`http://127.0.0.1:${portOf(server)}/`;
  const wifi=await c.get(url,{networkContext:{type:'wifi',id:'wifi-a',generation:1,signal:0}});
  const unknown=await c.get(url,{networkContext:{type:'unknown',id:'unknown-b',generation:2,signal:null}});
  assert.equal(wifi.body,'1110');assert.equal(unknown.body,'2220');assert.equal(requests,4);
 }finally{c.close();await new Promise((resolve)=>server.close(resolve));rmSync(dir,{recursive:true,force:true});}
});
