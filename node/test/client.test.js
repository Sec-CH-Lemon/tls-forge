import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

import { BinaryNotFound, Client, MAX_REQUEST_BYTES, SessionReset, resolveBinary } from '../index.js';
import { builtBinary, exeName, platformPackage, platformPackageName } from '../binary.js';

const here = path.dirname(fileURLToPath(import.meta.url));

// Not the developer's: a TLSFORGE_BIN set in the shell that runs the tests
// would answer every resolution these tests are about. A file is a process of
// its own under node --test, so this is this file's alone, and a test that
// wants the variable sets it.
delete process.env.TLSFORGE_BIN;
const fakeDaemon = path.join(here, 'fake-daemon.js');
// Where the native fake, which stands in on Windows, finds the committed answers.
process.env.TLSFORGE_PROTOCOL_FIXTURES = path.join(here, '..', '..', 'testdata', 'protocol');

// The client builds its own argv, so the fake is injected as the BINARY: a
// shell wrapper that ignores whatever flags it is handed and execs the fake
// daemon. Substituting at the process boundary rather than by reaching into the
// client's internals means these tests exercise the spawn, the pipes and the
// readline plumbing — which is where the interesting failures live.
const wrapperDir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-test-'));
const configuredDaemon = process.env.TLSFORGE_TEST_DAEMON;
let wrapper;
if (configuredDaemon) {
  wrapper = path.resolve(configuredDaemon);
} else if (process.platform === 'win32') {
  throw new Error('TLSFORGE_TEST_DAEMON must name the native fake daemon on Windows');
} else {
  wrapper = path.join(wrapperDir, 'wrapper.sh');
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${fakeDaemon}" "$@"\n`);
  chmodSync(wrapper, 0o755);
}

function fake(options = {}) {
  return new Client({ binary: wrapper, ...options });
}

// COLD_START is a deadline with time in it for a transport to start and
// answer, however slowly this machine starts one: a binary just built has
// taken over half a second to answer on macOS, and a loaded machine is slower.
const COLD_START = 5_000;

// pastDeadline makes ask with setTimeout in the test's hands, and lets every
// deadline it set pass at once. A client has one timeout, for starting a
// transport as for any request: one short enough to wait out would be too
// short for a start the test makes after it, and on the test's clock it can
// be COLD_START and cost nothing. Nothing is in flight when ask is made: the
// test's clearTimeout does not clear a deadline set on the real clock, which
// would pass later. The real clock is back for what follows.
function pastDeadline(t, ask) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const asked = ask();
    t.mock.timers.runAll();
    return asked;
  } finally {
    t.mock.timers.reset();
  }
}

// untimed waits for ask with setTimeout in the test's hands, for a test that
// times a deadline and must not time a start with it: the deadline ask sets
// passes only after COLD_START, and the interval that passes it holds the
// event loop open meanwhile, as a running deadline would. Nothing is in flight
// when ask is made, as for pastDeadline. Every deadline still set once ask is
// answered passes then, as it would later on the real clock: putting the
// test's clock away would drop it unseen.
async function untimed(t, ask) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const late = setInterval(() => t.mock.timers.runAll(), COLD_START);
  try {
    return await ask();
  } finally {
    clearInterval(late);
    t.mock.timers.runAll();
    t.mock.timers.reset();
  }
}

test('get returns the transport response', async () => {
  const c = fake();
  const res = await c.get('https://ok/page');
  assert.equal(res.status, 200);
  assert.equal(res.url, 'https://ok/page');
  assert.deepEqual(res.headers['content-type'], ['application/json']);
  assert.deepEqual(res.headers['set-cookie'], ['a=1', 'b=2']);
  c.close();
});

test('a response has the fields it documents, and no other', async () => {
  // What else the line carries, its id and its body's encoding among them,
  // and a field a newer transport adds, stays in the client.
  const c = fake();
  try {
    for (const host of ['ok', 'fixture', 'binary', 'newer-fields']) {
      const res = await c.get(`https://${host}/`);
      assert.deepEqual(Object.keys(res), ['status', 'url', 'body', 'content', 'headers', 'cookies'], host);
      assert.ok(Number.isInteger(res.status) && typeof res.url === 'string' && typeof res.body === 'string', host);
      assert.ok(Buffer.isBuffer(res.content), host);
      for (const values of Object.values(res.headers)) {
        assert.ok(Array.isArray(values) && values.every((value) => typeof value === 'string'), host);
      }
      assert.ok(Array.isArray(res.cookies) && res.cookies.every((cookie) => typeof cookie === 'string'), host);
    }
  } finally {
    c.close();
  }
});

test('headers, order and cookies reach the transport', async () => {
  const c = fake();
  const res = await c.get('https://ok/x', {
    headers: { referer: 'https://example.com' },
    order: ['referer', 'user-agent'],
    cookies: ['a=1', 'b=2'],
  });
  const echoed = JSON.parse(res.body);
  assert.deepEqual(echoed.headers, { referer: 'https://example.com' });
  assert.deepEqual(echoed.order, ['referer', 'user-agent']);
  assert.deepEqual(echoed.cookies, ['a=1', 'b=2']);
  c.close();
});

test('post sends a body', async () => {
  const c = fake();
  const res = await c.post('https://ok/submit', 'hello=world');
  assert.equal(res.status, 200);
  c.close();
});

test('client options become daemon arguments', async () => {
  const c = fake({ profile: 'firefox', proxy: 'http://proxy:8080', insecure: true, timeout: 20_001 });
  const argv = JSON.parse((await c.get('https://ok/x')).body).argv;
  assert.deepEqual(argv, [
    'daemon', '--profile', 'firefox', '--proxy-stdin', '--insecure', '--timeout', '36s',
  ]);
  c.close();
});

// withEnv sets environment variables of this process for one test, and puts
// back what was there, including nothing.
async function withEnv(values, body) {
  const before = Object.fromEntries(Object.keys(values).map((name) => [name, process.env[name]]));
  for (const [name, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  try {
    return await body();
  } finally {
    for (const [name, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("a proxy reaches its own process on its input, and nowhere else", async () => {
  // Off the command line, which `ps` shows every user of the machine, and out
  // of the environment, which the process's owner can read: on the first line
  // of the client's own process. Two clients do not get each other's, and
  // this process's environment is left as it was.
  await withEnv({ TLSFORGE_PROXY: undefined }, async () => {
    const one = fake({ proxy: 'http://alice:s3cret-one@proxy.test:8080' });
    const two = fake({ proxy: 'socks5://bob:s3cret-two@proxy.test:1080' });
    const plain = fake();
    try {
      const [first, second, third] = await Promise.all([
        one.get('https://ok/x'), two.get('https://ok/x'), plain.get('https://ok/x'),
      ]);
      for (const [response, proxy] of [[first, 'http://alice:s3cret-one@proxy.test:8080'],
        [second, 'socks5://bob:s3cret-two@proxy.test:1080']]) {
        const echoed = JSON.parse(response.body);
        assert.equal(echoed.proxy, proxy);
        assert.equal(echoed.env.TLSFORGE_PROXY, null);
        assert.ok(echoed.argv.includes('--proxy-stdin'));
        assert.ok(!echoed.argv.join(' ').includes('s3cret'), echoed.argv.join(' '));
      }
      const echoed = JSON.parse(third.body);
      assert.equal(echoed.env.TLSFORGE_PROXY, null);
      assert.ok(!echoed.argv.some((arg) => arg.startsWith('--proxy')));
      assert.equal(process.env.TLSFORGE_PROXY, undefined);
    } finally {
      one.close();
      two.close();
      plain.close();
    }
  });
});

test("a variable this process has is not a proxy unless the client names one", async () => {
  // Inherited, it is not named on the command line, and the transport reads
  // the variable only when it is; named, the client's own replaces it.
  await withEnv({ TLSFORGE_PROXY: 'http://someone:else@elsewhere.test:3128' }, async () => {
    const plain = fake();
    const proxied = fake({ proxy: 'http://mine.test:8080' });
    try {
      const inherited = JSON.parse((await plain.get('https://ok/x')).body);
      assert.ok(!inherited.argv.some((arg) => arg.startsWith('--proxy')));
      const own = JSON.parse((await proxied.get('https://ok/x')).body);
      assert.equal(own.proxy, 'http://mine.test:8080');
      assert.equal(process.env.TLSFORGE_PROXY, 'http://someone:else@elsewhere.test:3128');
    } finally {
      plain.close();
      proxied.close();
    }
  });
});

test('a transport older than the client is said to be, for every request waiting', async () => {
  await withEnv({ TLSFORGE_TEST_REFUSE: 'proxy-stdin' }, async () => {
    const c = fake({ proxy: 'http://alice:s3cret@proxy.test:8080' });
    try {
      const older = /refused its arguments \(code 2\): a tls-forge older than this package does not know --proxy-stdin/;
      const [first, second] = await Promise.allSettled([c.get('https://ok/a'), c.get('https://ok/b')]);
      assert.equal(first.status, 'rejected');
      assert.match(first.reason.message, older);
      assert.equal(second.status, 'rejected');
      assert.match(second.reason.message, older);
      assert.ok(!first.reason.message.includes('s3cret'));
      // Asked again, it is asked of a new process, which says the same.
      await assert.rejects(() => c.get('https://ok/c'), older);
    } finally {
      c.close();
    }
  });
});

test('a transport that will not take its proxy starts no session, and says why', async (t) => {
  // Refused, unanswered, garbled or gone before it answers the init line:
  // every request waiting fails with why, without the password, and none is
  // told a session went. The transport is stopped, so the next request starts
  // another, which is told the proxy first: one kept would take it unasked.
  for (const [mode, says] of [
    ['refuse', /^tlsforge: the transport did not take its proxy: the init line's proxy http:\/\/alice:\*\*\*@proxy\.test:8080 is no proxy$/],
    ['exit', /^tlsforge: transport exited \(code 3\)$/],
    ['silent', /^tlsforge: request timed out$/],
    ['garbage', /^tlsforge: bad response: /],
  ]) {
    await withEnv({ TLSFORGE_TEST_INIT: mode }, async () => {
      const c = fake({ proxy: 'http://alice:s3cret@proxy.test:8080', timeout: COLD_START });
      // Unanswered, the init line is ended by its deadline, which passes at once.
      const settle = (ask) => (mode === 'silent' ? pastDeadline(t, ask) : ask());
      try {
        const [first, second] = await settle(() => Promise.allSettled([c.get('https://ok/a'), c.get('https://ok/b')]));
        const third = await settle(() => Promise.allSettled([c.get('https://ok/c')]));
        for (const outcome of [first, second, ...third]) {
          assert.equal(outcome.status, 'rejected', mode);
          assert.match(outcome.reason.message, says);
          assert.ok(!outcome.reason.message.includes('s3cret'), mode);
          assert.ok(!(outcome.reason instanceof SessionReset), mode);
        }
        process.env.TLSFORGE_TEST_INIT = '';
        const again = JSON.parse((await c.get('https://ok/c')).body);
        assert.equal(again.proxy, 'http://alice:s3cret@proxy.test:8080');
      } finally {
        c.close();
      }
    });
  }
});

test('an init line that cannot be written starts no session', async () => {
  // Longer than a pipe holds, to a transport that closed its input unread:
  // the write fails, and there was no session to lose.
  const proxy = `http://alice:s3cret@proxy.test:8080/${'x'.repeat(1 << 20)}`;
  await withEnv({ TLSFORGE_TEST_INIT: 'deaf' }, async () => {
    const c = fake({ proxy, timeout: 5_000 });
    try {
      const [first, second] = await Promise.allSettled([c.get('https://ok/a'), c.get('https://ok/b')]);
      for (const outcome of [first, second]) {
        assert.equal(outcome.status, 'rejected');
        assert.match(outcome.reason.message, /^tlsforge: write failed: /);
        assert.ok(!(outcome.reason instanceof SessionReset));
      }
      process.env.TLSFORGE_TEST_INIT = '';
      assert.equal(JSON.parse((await c.get('https://ok/c')).body).proxy, proxy);
    } finally {
      c.close();
    }
  });
});

test('a transport started again is told its proxy again, first', async (t) => {
  const c = fake({ proxy: 'http://alice:s3cret@proxy.test:8080', timeout: COLD_START });
  try {
    const first = JSON.parse((await c.get('https://ok/a')).body);
    await assert.rejects(() => pastDeadline(t, () => c.get('https://silent/x')), /timed out/);
    await assert.rejects(() => c.get('https://ok/b'), SessionReset);
    const after = JSON.parse((await c.get('https://ok/c')).body);
    assert.notEqual(after.pid, first.pid);
    assert.equal(after.proxy, 'http://alice:s3cret@proxy.test:8080');
    assert.deepEqual(await c.hello(), { protocol: 3, capabilities: [], engine_major: 1, version: '1.0.0' });
  } finally {
    c.close();
  }
});

test('a transport that refuses its arguments without a proxy says only that', async () => {
  await withEnv({ TLSFORGE_TEST_REFUSE: 'always' }, async () => {
    const c = fake();
    try {
      await assert.rejects(() => c.get('https://ok/a'), (err) => {
        assert.match(err.message, /refused its arguments \(code 2\)$/);
        return true;
      });
    } finally {
      c.close();
    }
  });
});

test('cookie file options become daemon arguments', async () => {
  const c = fake({ cookieFile: '/tmp/warm.json', cookieSet: 'eu' });
  const argv = JSON.parse((await c.get('https://ok/x')).body).argv;
  assert.ok(argv.includes('--cookies'));
  assert.ok(argv.includes('/tmp/warm.json'));
  assert.ok(argv.includes('--cookie-set'));
  assert.ok(argv.includes('eu'));
  c.close();
});

test('cookieSet requires cookieFile', () => {
  assert.throws(() => fake({ cookieSet: 'eu' }), /cookieSet requires cookieFile/);
});

test('an error field becomes a rejection', async () => {
  const c = fake();
  await assert.rejects(() => c.get('https://error/x'), /upstream refused/);
  c.close();
});

test('a request with no url is rejected without spawning anything', async () => {
  const c = fake();
  await assert.rejects(() => c.request({}), /needs a url/);
  c.close();
});

test('a garbage line fails the in-flight request rather than hanging', async () => {
  const c = fake();
  await assert.rejects(() => c.get('https://garbage/x'), /bad response/);
  c.close();
});

test('a line that is valid JSON but not an object is also rejected', async () => {
  const c = fake();
  await assert.rejects(() => c.get('https://null-line/x'), /bad response/);
  c.close();
});

for (const behaviour of [
  'bad-error',
  'bad-status',
  'bad-url',
  'bad-body',
  'bad-headers',
  'bad-header-scalar',
  'bad-header-list',
  'bad-cookies',
  'bad-cookie-item',
]) {
  test(`a ${behaviour} response is rejected without breaking the client`, async () => {
    const c = fake();
    await assert.rejects(() => c.get(`https://${behaviour}/x`), /bad response/);
    assert.equal((await c.get('https://ok/after')).status, 200);
    c.close();
  });
}

test('an answer for a different id is ignored, not mistaken for this one', async () => {
  const notes = [];
  const c = fake({ onStderr: (line) => notes.push(line) });
  const res = await c.get('https://wrong-id/x');
  // The stray line carried body "stray"; the real answer did not.
  assert.notEqual(res.body, 'stray');
  assert.ok(notes.some((line) => line.includes('dropping answer')));
  c.close();
});

test('a request that is never answered times out and the client stays usable', async (t) => {
  // Stopped, the transport took the session with it: the next request is told,
  // unsent, and the one after starts a new session.
  const c = fake({ timeout: COLD_START });
  await assert.rejects(() => pastDeadline(t, () => c.get('https://silent/x')), /timed out/);
  await assert.rejects(() => c.get('https://ok/after'), (err) => {
    assert.ok(err instanceof SessionReset);
    assert.match(err.message, /has gone \(a request timed out, and it was stopped\)/);
    return true;
  });
  const res = await c.get('https://ok/after');
  assert.equal(res.status, 200);
  c.close();
});

test("a request's deadline counts from the call, the time it waited included", async (t) => {
  // The request in front of it is answered late, in time; what is left of the
  // second's deadline is what it has once it is sent. Counted from being sent,
  // it would have had the whole deadline again. The transport is started
  // first: how long that takes is no part of what is timed.
  const c = fake({ timeout: 600 });
  try {
    await untimed(t, () => c.get('https://ok/started'));
    const started = performance.now();
    const first = c.get('https://slow/a');
    const second = c.get('https://silent/b');
    assert.equal((await first).status, 200);
    await assert.rejects(() => second, /timed out/);
    const took = performance.now() - started;
    assert.ok(took > 550 && took < 900, `the second request took ${Math.round(took)} ms`);
  } finally {
    c.close();
  }
});

test('a request leaves no deadline set, however it ends', async (t) => {
  // A deadline left set when its request ended would pass later, under
  // whatever request is in flight then, and stop the transport, the session
  // in it and that request with it. Each ending is waited for untimed, which
  // then lets every deadline still set pass: the next request finds the
  // transport it found before. The client has a proxy, so that a start's
  // init line is among the endings; a write that fails is the dead pipe's.
  const c = fake({ proxy: 'http://proxy.test:8080', timeout: COLD_START });
  // transport is the process that answers the next request, or why none did.
  const transport = () => c.get('https://ok/next').then(
    (res) => JSON.parse(res.body).pid,
    (err) => `${err.name}: ${err.message}`,
  );
  try {
    const started = JSON.parse((await untimed(t, () => c.get('https://ok/start'))).body).pid;
    assert.equal(await transport(), started, 'a start');
    for (const [ending, ask, says] of [
      ['an answer', () => c.get('https://ok/x'), /^answered$/],
      ['a failure', () => c.get('https://error/x'), /^upstream refused$/],
      ['an answer of the wrong shape', () => c.get('https://bad-status/x'), /^tlsforge: bad response: field "status"/],
      ['a line that is not JSON', () => c.get('https://garbage/x'), /^tlsforge: bad response: /],
      ['an answer to hello', () => c.hello(), /^answered$/],
    ]) {
      const outcome = await untimed(t, () => ask().then(() => 'answered', (err) => err.message));
      assert.match(outcome, says, ending);
      assert.equal(await transport(), started, ending);
    }
    // An exit takes the transport, and the session in it, which the next
    // request is told; the one after starts another, which the deadline of
    // the request the exit ended does not stop.
    const next = await untimed(t, async () => {
      await assert.rejects(() => c.get('https://exit/x'), /transport exited \(code 3\)/);
      await assert.rejects(() => c.get('https://ok/told'), SessionReset);
      return transport();
    });
    assert.ok(Number.isInteger(next), String(next));
    assert.equal(await transport(), next, 'an exit');
  } finally {
    c.close();
  }
});

test('a transport that exits rejects the request in flight', async () => {
  const c = fake();
  await assert.rejects(() => c.get('https://exit/x'), /exited|closed/);
  c.close();
});

test('requests waiting when the transport exits are told their session has gone, unsent', async () => {
  // Made in a session that has gone, none of them would be what was asked for
  // in a new one. The request after them starts that new one.
  const c = fake();
  const before = JSON.parse((await c.get('https://ok/before')).body).pid;
  const first = c.get('https://exit/x');
  const waiting = [c.get('https://ok/one'), c.post('https://ok/two', 'a body')];
  await assert.rejects(() => first, /transport exited \(code 3\)/);
  for (const outcome of await Promise.allSettled(waiting)) {
    assert.equal(outcome.status, 'rejected');
    assert.ok(outcome.reason instanceof SessionReset, outcome.reason.message);
    assert.match(outcome.reason.message, /has gone \(it exited \(code 3\)\).*was not sent/);
  }
  const after = JSON.parse((await c.get('https://ok/after')).body).pid;
  assert.notEqual(after, before);
  c.close();
});

test('a transport that dies while nobody asks it anything tells the next request', async () => {
  const c = fake();
  await c.get('https://answer-then-exit/x');
  await new Promise((resolve) => setTimeout(resolve, 300));
  await assert.rejects(() => c.get('https://ok/after'), (err) => {
    assert.ok(err instanceof SessionReset);
    assert.match(err.message, /it exited \(code 4\)/);
    return true;
  });
  assert.equal((await c.get('https://ok/again')).status, 200);
  c.close();
});

// sized is a POST whose line is exactly size bytes as the transport reads it,
// made as the id-th request of its client, with a body of one character
// repeated: ASCII is a byte each, "я" two.
function sized(size, id, char = 'x') {
  const url = 'https://ok/sized';
  const overhead = Buffer.byteLength(JSON.stringify({ url, body: '', method: 'POST', id, engine_major: 1 }) + '\n');
  const each = Buffer.byteLength(char);
  const count = Math.floor((size - overhead) / each);
  const body = char.repeat(count) + 'x'.repeat(size - overhead - count * each);
  assert.equal(Buffer.byteLength(JSON.stringify({ url, body, method: 'POST', id, engine_major: 1 }) + '\n'), size);
  return { url, body };
}

test('a request is measured as the transport reads it, and one too long is not sent', async () => {
  const c = fake({ timeout: 30_000 });
  try {
    const first = JSON.parse((await c.get('https://ok/first')).body).pid;
    let id = 2;
    for (const [size, char] of [[MAX_REQUEST_BYTES - 1, 'x'], [MAX_REQUEST_BYTES, 'x'], [MAX_REQUEST_BYTES, 'я']]) {
      const { url, body } = sized(size, ++id, char);
      const echoed = JSON.parse((await c.post(url, body)).body);
      assert.equal(echoed.bodyLength, body.length);
      assert.equal(echoed.pid, first);
    }
    // One byte more, in bytes rather than characters: refused before it is
    // queued, and the session it would have ended is the one the next request
    // is made in.
    for (const char of ['x', 'я']) {
      const { url, body } = sized(MAX_REQUEST_BYTES + 1, ++id, char);
      await assert.rejects(() => c.post(url, body), (err) => {
        assert.ok(err instanceof RangeError);
        assert.match(err.message, new RegExp(`is ${MAX_REQUEST_BYTES + 1} bytes .* more than the ${MAX_REQUEST_BYTES}`));
        return true;
      });
    }
    // Bytes travel as base64, four characters for every three.
    const bytes = Buffer.alloc(Math.floor((MAX_REQUEST_BYTES / 4) * 3));
    await assert.rejects(() => c.post('https://ok/binary', bytes), RangeError);
    assert.equal(JSON.parse((await c.get('https://ok/after')).body).pid, first);
  } finally {
    c.close();
  }
});

test('requests on either side of one too long are made in the same session', async () => {
  const c = fake({ timeout: 30_000 });
  try {
    const big = 'x'.repeat(MAX_REQUEST_BYTES);
    const [before, refused, after] = await Promise.allSettled([
      c.get('https://ok/before'), c.post('https://ok/big', big), c.get('https://ok/after'),
    ]);
    assert.equal(refused.status, 'rejected');
    assert.ok(refused.reason instanceof RangeError);
    assert.equal(JSON.parse(before.value.body).pid, JSON.parse(after.value.body).pid);
  } finally {
    c.close();
  }
});

test('stderr is forwarded to the callback', async () => {
  const notes = [];
  const c = fake({ onStderr: (line) => notes.push(line) });
  await c.get('https://stderr/x');
  assert.ok(notes.some((line) => line.includes('a note on stderr')));
  c.close();
});

test('stderr chunks are reassembled into logical lines', async () => {
  const notes = [];
  const c = fake({ onStderr: (line) => notes.push(line) });
  await c.get('https://stderr-chunks/x');
  assert.deepEqual(notes, ['one logical line', 'second line']);
  c.close();
});

test('stderr is harmless without a callback', async () => {
  const c = fake();
  assert.equal((await c.get('https://stderr/x')).status, 200);
  c.close();
});

test('an exception in the stderr callback does not break the client', async () => {
  const c = fake({ onStderr: () => { throw new Error('callback failed'); } });
  assert.equal((await c.get('https://stderr/x')).status, 200);
  assert.equal((await c.get('https://ok/after')).status, 200);
  c.close();
});

test('legacy scalar and null response headers are normalised', async () => {
  const c = fake();
  const legacy = await c.get('https://legacy-headers/x');
  assert.deepEqual(legacy.headers, { 'content-type': ['application/json'] });
  const empty = await c.get('https://null-headers/x');
  assert.deepEqual(empty.headers, {});
  c.close();
});

test('null response fields are normalised to the public response shape', async () => {
  // What the transport sends on a failure, and every field null.
  for (const scenario of ['null-fields', 'null-values']) {
    const c = fake();
    const response = await c.get(`https://${scenario}/x`);
    assert.equal(response.status, 0);
    assert.equal(response.url, '');
    assert.equal(response.body, '');
    assert.deepEqual(response.headers, {});
    assert.deepEqual(response.cookies, []);
    c.close();
  }
});

test('an unencodable request does not block the queue', async () => {
  const c = fake();
  const headers = {};
  headers.circular = headers;
  await assert.rejects(
    () => c.get('https://ok/bad', { headers }),
    /request cannot be encoded as JSON/,
  );
  assert.equal((await c.get('https://ok/after')).status, 200);
  c.close();
});

test('unsolicited malformed and anonymous lines are ignored when idle', async () => {
  const notes = [];
  const c = fake({ onStderr: (line) => notes.push(line) });
  await c.get('https://trailing-lines/x');
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.ok(notes.some((line) => line.includes('(none)')));
  assert.equal((await c.get('https://ok/after')).status, 200);
  c.close();
});

test('requests queue and are answered in order', async () => {
  const c = fake();
  const results = await Promise.all([
    c.get('https://ok/1'),
    c.get('https://ok/2'),
    c.get('https://ok/3'),
  ]);
  assert.deepEqual(
    results.map((r) => r.url),
    ['https://ok/1', 'https://ok/2', 'https://ok/3'],
  );
  c.close();
});

test('a queued request is settled by close rather than left hanging', async () => {
  const c = fake({ timeout: 5_000 });
  const first = c.get('https://silent/1');
  const second = c.get('https://ok/2');
  c.close();
  await assert.rejects(() => first, /closed/);
  await assert.rejects(() => second, /closed/);
});

test('a closed client refuses to respawn', async () => {
  const c = fake();
  await c.get('https://ok/x');
  c.close();
  await assert.rejects(() => c.get('https://ok/y'), /closed/);
});

test('an idle client does not keep a Node program alive without close()', async () => {
  // The child says when its last answer came, and only what follows is timed:
  // how long Node and the transport took to start is no part of it. Its
  // requests, its proxy's init line among them, end in every way a running
  // transport ends one, and in an exit, and their deadline is far past the
  // wait: one an ending left set would hold the child beyond it.
  const moduleURL = new URL('../index.js', import.meta.url).href;
  const script = `
    import { Client } from ${JSON.stringify(moduleURL)};
    const client = new Client({
      binary: ${JSON.stringify(wrapper)}, proxy: 'http://proxy.test:8080', timeout: 60_000,
    });
    await client.hello();
    await client.get('https://ok/x');
    for (const host of ['error', 'bad-status', 'garbage', 'exit']) {
      await client.get('https://' + host + '/x').catch(() => {});
    }
    process.stdout.write('answered\\n');
  `;
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '--eval', script], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    let timer;
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    // From its answer, an exit takes milliseconds, under load too.
    child.stdout.once('data', () => {
      timer = setTimeout(() => {
        child.kill();
        reject(new Error('child stayed alive after its answer without close()'));
      }, 2_000);
    });
    // Closed, its output has all been read: an answer not seen by then never came.
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0 && timer !== undefined) resolve();
      else reject(new Error(`child exited ${code} ${timer === undefined ? 'unanswered' : 'answered'}: ${stderr}`));
    });
  });
});

test('a missing binary is reported when the client is built', () => {
  assert.throws(() => new Client({ binary: '/nope/tlsforge' }), /no binary at/);
});

for (const timeout of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
  test(`timeout ${timeout} is rejected`, () => {
    assert.throws(() => new Client({ binary: wrapper, timeout }), /positive finite/);
  });
}

test('onStderr must be a function', () => {
  assert.throws(() => new Client({ binary: wrapper, onStderr: 'log' }), /must be a function/);
});

test('a binary that cannot be executed fails the request, not the process', async () => {
  const notExecutable = path.join(wrapperDir, 'not-executable');
  writeFileSync(notExecutable, 'not a program');
  chmodSync(notExecutable, 0o644);
  const c = new Client({ binary: notExecutable });
  await assert.rejects(() => c.get('https://ok/x'), /failed to start|exited/);
  c.close();
});

test('a binary removed after construction fails through the spawn error event', async () => {
  const disappearing = path.join(wrapperDir, 'disappearing');
  writeFileSync(disappearing, '#!/bin/sh\n');
  chmodSync(disappearing, 0o755);
  const c = new Client({ binary: disappearing });
  unlinkSync(disappearing);
  await assert.rejects(() => c.get('https://ok/x'), /failed to start/);
  c.close();
});

test('resolveBinary prefers an explicit path', () => {
  assert.equal(resolveBinary(wrapper), wrapper);
});

test('resolveBinary reads TLSFORGE_BIN', () => {
  const previous = process.env.TLSFORGE_BIN;
  process.env.TLSFORGE_BIN = wrapper;
  try {
    assert.equal(resolveBinary(), wrapper);
  } finally {
    if (previous === undefined) delete process.env.TLSFORGE_BIN;
    else process.env.TLSFORGE_BIN = previous;
  }
});

test('resolveBinary rejects a path that does not exist', () => {
  assert.throws(() => resolveBinary('/definitely/not/here'), (err) => err instanceof BinaryNotFound && /no binary at/.test(err.message));
});

test('resolveBinary rejects a directory', () => {
  assert.throws(() => resolveBinary(wrapperDir), /no binary at/);
});

test('resolveBinary uses a local build before PATH', (t) => {
  if (!existsSync(builtBinary)) {
    mkdirSync(path.dirname(builtBinary), { recursive: true });
    writeFileSync(builtBinary, '#!/bin/sh\n');
    chmodSync(builtBinary, 0o755);
    t.after(() => rmSync(path.dirname(builtBinary), { recursive: true, force: true }));
  }
  assert.equal(resolveBinary(), builtBinary);
});

// The binary normally arrives as an optional dependency: one package per
// platform, each declaring `os` and `cpu`, so npm installs only the matching
// one. These tests build that layout for real rather than stubbing the
// resolver, because the thing worth checking is that Node's resolution finds it.
function installPlatformPackage(t, { withBinary = true } = {}) {
  const dir = path.join(here, '..', 'node_modules', platformPackage);
  mkdirSync(path.join(dir, 'bin'), { recursive: true });
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: platformPackage, version: '0.0.0' }));
  const binary = path.join(dir, 'bin', exeName);
  if (withBinary) {
    writeFileSync(binary, '#!/bin/sh\n');
    chmodSync(binary, 0o755);
  }
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return binary;
}

test('the binary is found in the platform package', (t) => {
  const binary = installPlatformPackage(t);
  assert.equal(resolveBinary(), binary);
});

test('an explicit path still wins over the platform package', (t) => {
  installPlatformPackage(t);
  assert.equal(resolveBinary(wrapper), wrapper);
});

test('a platform package without its binary is not used', (t) => {
  // An interrupted install can leave the directory without the file in it.
  // Resolving to a path that does not exist would fail later, at spawn, with a
  // much worse message.
  installPlatformPackage(t, { withBinary: false });
  const previous = process.env.TLSFORGE_BIN;
  delete process.env.TLSFORGE_BIN;
  try {
    let found = null;
    try {
      found = resolveBinary();
    } catch {
      /* nothing installed anywhere, which is the expected case here */
    }
    if (found && found.includes(platformPackage)) {
      assert.fail(`resolved to a missing binary: ${found}`);
    }
  } finally {
    if (previous !== undefined) process.env.TLSFORGE_BIN = previous;
  }
});

test('the not-found message names the platform package', () => {
  const previous = process.env.TLSFORGE_BIN;
  delete process.env.TLSFORGE_BIN;
  try {
    resolveBinary();
    // A binary on PATH or a local build is a perfectly normal state for a
    // checkout, and not what this test is about.
  } catch (err) {
    assert.match(err.message, /tls-forge-/);
    assert.match(err.message, new RegExp(`${process.platform}-${process.arch}`));
  } finally {
    if (previous !== undefined) process.env.TLSFORGE_BIN = previous;
  }
});

test('the platform package name follows npm platform and arch', () => {
  const packagePlatform = process.platform === 'win32' ? 'windows' : process.platform;
  assert.equal(platformPackage, `tls-forge-${packagePlatform}-${process.arch}`);
  assert.equal(platformPackageName('linux', 'arm64'), 'tls-forge-linux-arm64');
  assert.equal(platformPackageName('win32', 'x64'), 'tls-forge-windows-x64');
  assert.equal(exeName, process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge');
});

test('a write into a dead pipe fails that request and restarts', async (t) => {
  // The process is still alive but has stopped reading, so the write reaches a
  // pipe with no reader. That is the gap the write callback exists for: the
  // liveness check passed, and the pipe died before the bytes landed.
  const binary = configuredDaemon ? wrapper : path.join(here, 'deaf-daemon.sh');
  const c = new Client({ binary, timeout: COLD_START });
  try {
    await c.get('https://deaf/first');
    // Untimed, and every deadline still set passes after: the failed
    // request's has gone with it, or it would stop the transport again.
    await untimed(t, async () => {
      const second = c.get('https://deaf/second');
      const waiting = c.get('https://deaf/third');
      // The transport is stopped, and the session in it lost: the request that
      // waited behind is told so, unsent.
      await Promise.all([
        assert.rejects(second, /write failed/),
        assert.rejects(waiting, (err) => err instanceof SessionReset && /could not be written/.test(err.message)),
      ]);
    });
    // So the lost session is told of once, and the next request starts another.
    assert.equal((await c.get('https://deaf/again')).status, 200);
  } finally {
    c.close();
  }
});

test('a transport that cannot be spawned fails the request, not the process', async () => {
  // spawn throws synchronously for an argv it will not accept, rather than
  // emitting 'error'. Unhandled, that throw escapes request(), which returns a
  // promise everywhere else, so the caller's catch would miss it. A NUL byte
  // is what spawn will not accept, written as an escape so that an editor or
  // a formatter cannot quietly drop it and leave this test passing for
  // another reason.
  const c = new Client({ binary: wrapper, profile: 'chrome\u0000151' });
  await assert.rejects(() => c.get('https://ok/page'), /transport failed to start/);
  c.close();
});

// Resolution with nothing installed anywhere. Every source resolveBinary knows
// about is taken away at once: no override, no platform package under either
// resolution base, no local build, and nothing on PATH.
test('no binary anywhere is an error that says what to do', (t) => {
  const previous = {
    bin: process.env.TLSFORGE_BIN,
    path: process.env.PATH,
    cwd: process.cwd(),
  };
  const sterile = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-sterile-'));
  // A manifest, so the cwd resolution base exists and resolves to nothing
  // rather than throwing for want of a package.json.
  writeFileSync(path.join(sterile, 'package.json'), '{"name":"sterile","version":"0.0.0"}');

  delete process.env.TLSFORGE_BIN;
  process.env.PATH = path.join(sterile, 'empty');
  process.chdir(sterile);
  t.after(() => {
    process.chdir(previous.cwd);
    process.env.PATH = previous.path;
    if (previous.bin === undefined) delete process.env.TLSFORGE_BIN;
    else process.env.TLSFORGE_BIN = previous.bin;
    rmSync(sterile, { recursive: true, force: true });
  });

  assert.throws(() => resolveBinary(), (err) => {
    // The message has to name the package that was missing and both ways out,
    // or it tells someone their install is broken and leaves them there.
    assert.ok(err instanceof BinaryNotFound);
    assert.match(err.message, /no binary for/);
    assert.ok(err.message.includes(platformPackage));
    assert.match(err.message, /TLSFORGE_BIN/);
    assert.match(err.message, /go install/);
    return true;
  });
});

test('a package linked into a project finds the binary that project installed', (t) => {
  // A file: dependency, npm link and a monorepo leave this package in a
  // checkout of its own, where no platform package is: the binary is the one
  // the project being run installed, its own or hoisted to the monorepo's
  // root, which is found from the working directory.
  const previous = { bin: process.env.TLSFORGE_BIN, cwd: process.cwd() };
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-linked-'));
  delete process.env.TLSFORGE_BIN;
  t.after(() => {
    process.chdir(previous.cwd);
    if (previous.bin === undefined) delete process.env.TLSFORGE_BIN;
    else process.env.TLSFORGE_BIN = previous.bin;
    rmSync(scratch, { recursive: true, force: true });
  });
  const install = (root) => {
    const dir = path.join(root, 'node_modules', platformPackage);
    mkdirSync(path.join(dir, 'bin'), { recursive: true });
    writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: platformPackage, version: '0.0.0' }));
    writeFileSync(path.join(dir, 'bin', exeName), '#!/bin/sh\n');
    chmodSync(path.join(dir, 'bin', exeName), 0o755);
    return path.join(dir, 'bin', exeName);
  };
  const project = (dir) => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, 'package.json'), '{"name":"app","version":"0.0.0"}');
    return dir;
  };

  const own = project(path.join(scratch, 'app'));
  const ownBinary = install(own);
  process.chdir(own);
  assert.equal(realpathSync(resolveBinary()), realpathSync(ownBinary));

  const monorepo = project(path.join(scratch, 'monorepo'));
  const hoisted = install(monorepo);
  process.chdir(project(path.join(monorepo, 'packages', 'app')));
  assert.equal(realpathSync(resolveBinary()), realpathSync(hoisted));
});

test('the binary is found on PATH when nothing else has one', (t) => {
  const previous = {
    bin: process.env.TLSFORGE_BIN,
    path: process.env.PATH,
    cwd: process.cwd(),
  };
  const sterile = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-path-'));
  writeFileSync(path.join(sterile, 'package.json'), '{"name":"sterile","version":"0.0.0"}');

  const onPath = path.join(sterile, exeName);
  writeFileSync(onPath, '#!/bin/sh\n');
  chmodSync(onPath, 0o755);

  delete process.env.TLSFORGE_BIN;
  // `which` itself has to stay findable, so the real PATH is kept behind the
  // directory holding the stand-in.
  process.env.PATH = sterile + path.delimiter + previous.path;
  process.chdir(sterile);
  t.after(() => {
    process.chdir(previous.cwd);
    process.env.PATH = previous.path;
    if (previous.bin === undefined) delete process.env.TLSFORGE_BIN;
    else process.env.TLSFORGE_BIN = previous.bin;
    rmSync(sterile, { recursive: true, force: true });
  });

  // where.exe expands an 8.3 segment such as RUNNER~1 to its long spelling.
  // Node's realpathSync does not consistently expand that alias in an input
  // path, so compare the filesystem's volume and file identifiers instead.
  const actual = statSync(resolveBinary(), { bigint: true });
  const expected = statSync(onPath, { bigint: true });
  assert.deepEqual([actual.dev, actual.ino], [expected.dev, expected.ino]);
});

test('an unusable path lookup result is treated as not found', (t) => {
  const previous = {
    bin: process.env.TLSFORGE_BIN,
    finder: process.env.TLSFORGE_TEST_FINDER,
    path: process.env.PATH,
    cwd: process.cwd(),
  };
  const sterile = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-false-path-'));
  writeFileSync(path.join(sterile, 'package.json'), '{"name":"sterile","version":"0.0.0"}');
  const finder = path.join(sterile, process.platform === 'win32' ? 'where.exe' : 'which');
  if (process.platform === 'win32') {
    copyFileSync(wrapper, finder);
    process.env.TLSFORGE_TEST_FINDER = 'missing';
  } else {
    writeFileSync(finder, "#!/bin/sh\nprintf '/definitely/not/here\\r\\n'\n");
    chmodSync(finder, 0o755);
  }

  delete process.env.TLSFORGE_BIN;
  process.env.PATH = sterile;
  process.chdir(sterile);
  t.after(() => {
    process.chdir(previous.cwd);
    process.env.PATH = previous.path;
    if (previous.bin === undefined) delete process.env.TLSFORGE_BIN;
    else process.env.TLSFORGE_BIN = previous.bin;
    if (previous.finder === undefined) delete process.env.TLSFORGE_TEST_FINDER;
    else process.env.TLSFORGE_TEST_FINDER = previous.finder;
    rmSync(sterile, { recursive: true, force: true });
  });

  assert.throws(() => resolveBinary(), /no binary for/);

  // A successful finder that prints no path is the other false result.
  if (process.platform === 'win32') {
    process.env.TLSFORGE_TEST_FINDER = 'empty';
  } else {
    writeFileSync(finder, '#!/bin/sh\nexit 0\n');
  }
  assert.throws(() => resolveBinary(), /no binary for/);
});

test('a binary body arrives as bytes, not as replacement characters', async () => {
  const client = fake();
  try {
    const response = await client.get('https://binary/logo.png');
    const want = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff]);
    assert.deepEqual(response.content, want);
  } finally {
    await client.close();
  }
});

test('a text body is a Buffer of the same text', async () => {
  const client = fake();
  try {
    const response = await client.get('https://ok/');
    assert.equal(response.content.toString('utf8'), response.body);
  } finally {
    await client.close();
  }
});

test('an explicit utf8 encoding is accepted', async () => {
  const client = fake();
  try {
    const response = await client.get('https://utf8-encoding/');
    assert.equal(response.body, 'plain text');
    assert.equal(response.content.toString('utf8'), 'plain text');
  } finally {
    await client.close();
  }
});

test('a Buffer request body is sent as base64 and arrives intact', async () => {
  const client = fake();
  try {
    const sent = Buffer.from([0x00, 0xff, 0xfe, 0x80]);
    const response = await client.post('https://echo-body/', sent);
    assert.deepEqual(response.content, sent);
  } finally {
    await client.close();
  }
});

test('a Uint8Array request body is sent as base64 too', async () => {
  const client = fake();
  try {
    const sent = new Uint8Array([0x01, 0xff, 0x00]);
    const response = await client.post('https://echo-body/', sent);
    assert.deepEqual(response.content, Buffer.from(sent));
  } finally {
    await client.close();
  }
});

test('a request body that is neither text nor bytes is refused', async () => {
  const client = fake();
  try {
    await assert.rejects(
      client.post('https://ok/', { not: 'a body' }),
      /must be a string, Buffer or Uint8Array/,
    );
  } finally {
    await client.close();
  }
});

test('an unknown bodyEncoding is refused', async () => {
  const client = fake();
  try {
    await assert.rejects(client.get('https://bad-body-encoding/'), /unknown bodyEncoding/);
  } finally {
    await client.close();
  }
});

test('a bodyEncoding that is not a string is refused', async () => {
  const client = fake();
  try {
    await assert.rejects(
      client.get('https://bad-body-encoding-type/'),
      /"bodyEncoding" must be a string/,
    );
  } finally {
    await client.close();
  }
});

test('a body that claims to be base64 and is not is refused', async () => {
  const client = fake();
  try {
    await assert.rejects(client.get('https://bad-base64/'), /not valid base64/);
  } finally {
    await client.close();
  }
});
