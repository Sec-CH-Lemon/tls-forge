import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client, resolveBinary } from '../index.js';
import { exeName, platformPackage } from '../binary.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fakeDaemon = path.join(here, 'fake-daemon.js');

// The client builds its own argv, so the fake is injected as the BINARY: a
// shell wrapper that ignores whatever flags it is handed and execs the fake
// daemon. Substituting at the process boundary rather than by reaching into the
// client's internals means these tests exercise the spawn, the pipes and the
// readline plumbing — which is where the interesting failures live.
const wrapperDir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-test-'));
const wrapper = path.join(wrapperDir, 'wrapper.sh');
writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${fakeDaemon}"\n`);
chmodSync(wrapper, 0o755);

function fake(options = {}) {
  return new Client({ binary: wrapper, ...options });
}

test('get returns the transport response', async () => {
  const c = fake();
  const res = await c.get('https://ok/page');
  assert.equal(res.status, 200);
  assert.equal(res.url, 'https://ok/page');
  assert.equal(res.headers['content-type'], 'application/json');
  c.close();
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

test('an answer for a different id is ignored, not mistaken for this one', async () => {
  const notes = [];
  const c = fake({ onStderr: (line) => notes.push(line) });
  const res = await c.get('https://wrong-id/x');
  // The stray line carried body "stray"; the real answer did not.
  assert.notEqual(res.body, 'stray');
  assert.ok(notes.some((line) => line.includes('dropping answer')));
  c.close();
});

test('a request that is never answered times out and the client stays usable', async () => {
  const c = fake({ timeout: 150 });
  await assert.rejects(() => c.get('https://silent/x'), /timed out/);
  const res = await c.get('https://ok/after');
  assert.equal(res.status, 200);
  c.close();
});

test('a transport that exits rejects the request in flight', async () => {
  const c = fake();
  await assert.rejects(() => c.get('https://exit/x'), /exited|closed/);
  c.close();
});

test('stderr is forwarded to the callback', async () => {
  const notes = [];
  const c = fake({ onStderr: (line) => notes.push(line) });
  await c.get('https://stderr/x');
  assert.ok(notes.some((line) => line.includes('a note on stderr')));
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

test('a missing binary is reported when the client is built', () => {
  assert.throws(() => new Client({ binary: '/nope/tlsforge' }), /no binary at/);
});

test('a binary that cannot be executed fails the request, not the process', async () => {
  const notExecutable = path.join(wrapperDir, 'not-executable');
  writeFileSync(notExecutable, 'not a program');
  chmodSync(notExecutable, 0o644);
  const c = new Client({ binary: notExecutable });
  await assert.rejects(() => c.get('https://ok/x'), /failed to start|exited/);
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
  assert.throws(() => resolveBinary('/definitely/not/here'), /no binary at/);
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
  t.after(() => rmSync(path.join(here, '..', 'node_modules', '@sec-ch-lemon'), { recursive: true, force: true }));
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
    if (found && found.includes('@sec-ch-lemon')) {
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
    assert.match(err.message, /@sec-ch-lemon\/tls-forge-/);
    assert.match(err.message, new RegExp(`${process.platform}-${process.arch}`));
  } finally {
    if (previous !== undefined) process.env.TLSFORGE_BIN = previous;
  }
});

test('the platform package name follows npm platform and arch', () => {
  assert.equal(platformPackage, `@sec-ch-lemon/tls-forge-${process.platform}-${process.arch}`);
  assert.equal(exeName, process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge');
});
