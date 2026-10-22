#!/usr/bin/env node
// A stand-in for the Go transport, so the client's protocol handling can be
// tested without Go and without a network.
//
// Every behaviour the real transport can exhibit — including the ones that only
// happen when something has gone wrong — is reachable by asking for it in the
// URL. That is the point: the interesting code in the client is what it does
// with a late answer, a garbage line or a dead pipe, and none of those are
// reproducible against a healthy server.
//
// The scenarios are the ones testdata/fake-daemon/scenarios.json names, and
// every fake answers the same ones: see that file.

import readline from 'node:readline';
import { closeSync, readFileSync, appendFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// A tls-forge older than the client, which does not know --proxy-stdin and
// refuses to start as pflag does, with code 2; or one that refuses whatever it
// is started with.
const refuse = process.env.TLSFORGE_TEST_REFUSE;
const proxyStdin = process.argv.includes('--proxy-stdin');
if (refuse === 'always' || (refuse === 'proxy-stdin' && proxyStdin)) {
  process.stderr.write('tlsforge: bad usage: unknown flag: --proxy-stdin\n');
  process.exit(2);
}

// What the init line is answered with, by TLSFORGE_TEST_INIT, for a fake
// started with --proxy-stdin, which reads it first: without an error when it
// says nothing. "deaf" is the one acted on before the line is read.
const initMode = process.env.TLSFORGE_TEST_INIT ?? '';
const inits = {
  '': (request) => write(blank(request)),
  refuse: (request) => {
    const said = String(request.proxy ?? '').replace(/:[^:@/]*@/, ':***@');
    write(blank(request, { error: `the init line's proxy ${said} is no proxy` }));
    process.exit(1);
  },
  silent: () => {},
  exit: () => process.exit(3),
  garbage: () => raw('not json at all\n'),
  // Closes its input before anything has read from it, and stays: the
  // client's write of the init line finds a pipe nobody can read. Closed
  // under no handle, since closing one a live handle holds takes the process
  // down with a signal.
  deaf: () => {
    closeSync(0);
    setTimeout(() => {}, 30_000);
  },
};

// The proxy the init line named, and whether it has been read.
let proxy = null;
let initialised = !proxyStdin;
function init(request) {
  initialised = true;
  proxy = request.proxy ?? null;
  (inits[initMode] ?? ((request) => write(blank(request, { error: `unknown init mode "${initMode}"` }))))(request);
}

// What reads the input: none for a fake deaf to its init line.
let reader = null;

// How many control lines and requests this process has read: what a client
// sent, which a test of what it did not send reads back.
let controls = 0;
let requests = 0;

const write = (value) => process.stdout.write(JSON.stringify(value) + '\n');
const raw = (line) => process.stdout.write(line);
const fixture = (name) =>
  JSON.parse(readFileSync(path.join(here, '..', '..', 'testdata', 'protocol', name), 'utf8'));

// answer is a 200 to request, its body saying what reached this process, with
// extra laid over it.
function answer(request, extra = {}) {
  return {
    id: request.id,
    status: 200,
    url: request.url,
    body: JSON.stringify({
      argv: process.argv.slice(2),
      env: { TLSFORGE_PROXY: process.env.TLSFORGE_PROXY ?? null },
      // The proxy the init line named, and the line it was: the first.
      proxy,
      // Which process answered, and how much of a body reached it: a
      // request refused before it was sent must leave both as they were.
      pid: process.pid,
      bodyLength: (request.body ?? '').length,
      headers: request.headers ?? {},
      order: request.order ?? [],
      cookies: request.setCookie ?? [],
      // The browser context, as the transport was given it.
      browser: request.browser ?? null,
      sent: Object.keys(request).sort(),
      controls,
      requests,
    }),
    headers: { 'content-type': ['application/json'], 'set-cookie': ['a=1', 'b=2'] },
    cookies: [],
    ...extra,
  };
}

const reply = (request, extra) => write(answer(request, extra));

// What a request is answered with, by the host of its URL.
const scenarios = {
  ok: (request) => reply(request),
  error: (request) => write({ id: request.id, error: 'upstream refused' }),
  // What the transport really sends when a request fails: the shape is whole.
  'null-fields': (request) =>
    write({ id: request.id, status: 0, url: '', body: '', headers: null, cookies: null }),
  'null-values': (request) => reply(request, { status: null, url: null, body: null, headers: null, cookies: null }),
  'bad-error': (request) => reply(request, { error: {} }),
  'bad-status': (request) => reply(request, { status: '200' }),
  'bad-url': (request) => reply(request, { url: 7 }),
  'bad-body': (request) => reply(request, { body: [] }),
  // The bytes a JSON string cannot hold: PNG magic and a stray 0xff.
  binary: (request) =>
    reply(request, {
      body: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff]).toString('base64'),
      bodyEncoding: 'base64',
    }),
  // Hands back what it was sent, so the request direction can be checked.
  'echo-body': (request) => reply(request, { body: request.body ?? '', bodyEncoding: request.bodyEncoding ?? '' }),
  'utf8-encoding': (request) => reply(request, { body: 'plain text', bodyEncoding: 'utf8' }),
  'bad-body-encoding': (request) => reply(request, { body: 'x', bodyEncoding: 'rot13' }),
  'bad-body-encoding-type': (request) => reply(request, { body: 'x', bodyEncoding: 7 }),
  'bad-base64': (request) => reply(request, { body: '!!not base64!!', bodyEncoding: 'base64' }),
  'bad-headers': (request) => reply(request, { headers: [] }),
  'bad-header-scalar': (request) => reply(request, { headers: { broken: 7 } }),
  'bad-header-list': (request) => reply(request, { headers: { broken: [7] } }),
  'bad-cookies': (request) => reply(request, { cookies: {} }),
  'bad-cookie-item': (request) => reply(request, { cookies: [7] }),
  'legacy-headers': (request) => reply(request, { headers: { 'content-type': 'application/json' } }),
  'null-headers': (request) => reply(request, { headers: null }),
  'newer-fields': (request) => reply(request, { teleport: true }),
  // The committed wire format, replayed verbatim except for the id, which the
  // client matches on. See testdata/protocol/README.md.
  fixture: (request) => write({ ...fixture('response.json'), id: request.id }),
  'fixture-text': (request) => write({ ...fixture('response-text.json'), id: request.id }),
  'fixture-error': (request) => write({ ...fixture('response-error.json'), id: request.id }),
  garbage: () => raw('not json at all\n'),
  'null-line': () => raw('null\n'),
  'no-id': (request) => {
    write({ status: 200, body: 'anonymous' });
    setTimeout(() => reply(request), 50);
  },
  'wrong-id': (request) => {
    write({ id: request.id + 1000, status: 200, body: 'stray' });
    // …then the right one, so the request still completes and the test can
    // assert the stray line was ignored rather than merely slow.
    setTimeout(() => reply(request), 10);
  },
  'trailing-lines': (request) => {
    reply(request);
    setTimeout(() => {
      raw('not json at all\n');
      write({ status: 200, body: 'orphan' });
    }, 10);
  },
  // Never answers. The client's deadline is the only thing that ends this.
  silent: () => {},
  slow: (request) => setTimeout(() => reply(request), 400),
  exit: () => process.exit(3),
  // Answers, and dies while nobody is asking it anything.
  'answer-then-exit': (request) => {
    reply(request);
    setTimeout(() => process.exit(4), 50);
  },
  // Never answers, and reads nothing more: the end of its input is not
  // noticed, and it has to be stopped.
  stubborn: () => {
    reader.close();
    process.stdin.pause();
    setTimeout(() => {}, 30_000);
  },
  // Answers, and then reads nothing more, for as long as it is left running:
  // its client finds a pipe nobody reads rather than a process that exited.
  deaf: (request) => {
    reply(request);
    reader.close();
    process.stdin.destroy();
    setTimeout(() => {}, 30_000);
  },
  stderr: (request) => {
    process.stderr.write('a note on stderr\n');
    reply(request);
  },
  'stderr-chunks': (request) => {
    process.stderr.write('one logical');
    setTimeout(() => {
      process.stderr.write(' line\nsecond line\n');
      reply(request);
    }, 5);
  },
};

// What hello is answered with, by TLSFORGE_TEST_PROTOCOL: protocol 2 with
// TLSFORGE_TEST_CAPABILITIES when it says nothing.
const blank = (request, extra) => ({ id: request.id, status: 0, url: '', body: '', headers: null, cookies: null, ...extra });
const protocols = {
  '': (request) => {
    const capabilities = (process.env.TLSFORGE_TEST_CAPABILITIES ?? '').split(',').filter(Boolean);
    const engine_major = process.env.TLSFORGE_TEST_ENGINE_MAJOR;
    const identity = { protocol: 3, version: process.env.TLSFORGE_TEST_ENGINE_VERSION ?? '5.0.0', ...(capabilities.length ? { capabilities } : {}) };
    if (engine_major !== 'missing') identity.engine_major = engine_major === undefined ? 5 : JSON.parse(engine_major);
    write(blank(request, identity));
  },
  1: (request) => write(blank(request, { error: 'bad request: no url' })),
  fixture: (request) => write({ ...fixture('response-hello.json'), id: request.id }),
  'fixture-old': (request) => write({ ...fixture('response-hello-old.json'), id: request.id }),
  bad: (request) => write(blank(request, { protocol: 'two' })),
  bool: (request) => write(blank(request, { protocol: true })),
  'bad-capabilities': (request) => write(blank(request, { protocol: 2, capabilities: [7] })),
  'no-capabilities': (request) => write(blank(request, { protocol: 2, capabilities: 'all' })),
  low: (request) => write(blank(request, { protocol: 1 })),
  newer: (request) => write(blank(request, { protocol: 7, engine_major: 5, version: '5.0.0', capabilities: ['browser_context', 'teleport'] })),
  silent: () => {},
  exit: () => process.exit(3),
};

function onLine(line) {
  if (process.env.TLSFORGE_TEST_WIRE_LOG) appendFileSync(process.env.TLSFORGE_TEST_WIRE_LOG, line + "\n");
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    raw('{"id":0,"error":"bad request"}\n');
    return;
  }
  if (!initialised) {
    if (request.control !== 'init') {
      write({ ...blank(request), error: 'the first line is not the init line' });
      process.exit(1);
    }
    init(request);
    return;
  }

  if (request.control !== undefined) {
    controls += 1;
    // What this fake answers, for the suite that holds it to scenarios.json.
    if (request.control === 'scenarios') {
      write({
        id: request.id,
        requests: Object.keys(scenarios).sort(),
        protocols: Object.keys(protocols).sort(),
        inits: Object.keys(inits).sort(),
      });
      return;
    }
    const mode = process.env.TLSFORGE_TEST_PROTOCOL ?? '';
    (protocols[mode] ?? ((request) => write(blank(request, { error: `unknown protocol mode "${mode}"` }))))(request);
    return;
  }

  requests += 1;
  const behaviour = new URL(request.url).host;
  (scenarios[behaviour] ?? ((request) => write({ id: request.id, error: `unknown scenario "${behaviour}"` })))(request);
}

if (proxyStdin && initMode === 'deaf') {
  inits.deaf();
} else {
  reader = readline.createInterface({ input: process.stdin });
  reader.on('line', onLine);
}
