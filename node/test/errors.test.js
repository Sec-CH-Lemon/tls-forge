// What a caller is rejected with, as classes it can act on: the ones the
// Python package raises, by the same names, for the same failures; and a
// mistake in the call, a TypeError or a RangeError, which is none of them.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, mkdtempSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as tlsforge from '../index.js';
import * as errors from '../errors.js';
import {
  BinaryNotFound,
  Client,
  MAX_REQUEST_BYTES,
  RequestFailed,
  SessionReset,
  TLSForgeError,
  Timeout,
  TransportError,
  Unsupported,
} from '../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
delete process.env.TLSFORGE_BIN;
const wrapperDir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-errors-'));
const configuredDaemon = process.env.TLSFORGE_TEST_DAEMON;
let wrapper;
if (configuredDaemon) {
  wrapper = path.resolve(configuredDaemon);
} else if (process.platform === 'win32') {
  throw new Error('TLSFORGE_TEST_DAEMON must name the native fake daemon on Windows');
} else {
  wrapper = path.join(wrapperDir, 'wrapper.sh');
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${path.join(here, 'fake-daemon.js')}" "$@"\n`);
  chmodSync(wrapper, 0o755);
}

// The classes, each under the one it extends.
const TREE = [
  [TLSForgeError, Error],
  [BinaryNotFound, TLSForgeError],
  [TransportError, TLSForgeError],
  [SessionReset, TransportError],
  [RequestFailed, TLSForgeError],
  [Unsupported, TLSForgeError],
  [Timeout, TLSForgeError],
];

test('each error is an Error named as its class, under the one it extends', () => {
  for (const [kind, parent] of TREE) {
    assert.equal(Object.getPrototypeOf(kind), parent, kind.name);
    const cause = new Error('underneath');
    const err = new kind('tlsforge: what happened', { cause });
    assert.ok(err instanceof parent, kind.name);
    assert.equal(err.name, kind.name);
    assert.equal(err.message, 'tlsforge: what happened');
    assert.equal(err.cause, cause);
    assert.match(err.stack, new RegExp(`^${kind.name}: tlsforge: what happened\\n`));
    assert.equal(new kind('without one').cause, undefined);
  }
});

test('the package exports every error class, and errors.js nothing else', () => {
  assert.deepEqual(Object.keys(errors).sort(), TREE.map(([kind]) => kind.name).sort());
  for (const [name, kind] of Object.entries(errors)) assert.equal(tlsforge[name], kind, name);
});

test('the package ships every module it imports', () => {
  // A module the manifest leaves out is missing from the tarball, and the
  // package cannot be imported where it is installed.
  const root = path.join(here, '..');
  const { files } = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const file of files.filter((name) => name.endsWith('.js'))) {
    const source = readFileSync(path.join(root, file), 'utf8');
    for (const [, imported] of source.matchAll(/from '\.\/([^']+)'/g)) {
      assert.ok(files.includes(imported), `${file} imports ${imported}, which package.json does not list`);
    }
  }
});

// withEnv runs body with the variables set, and restores them after.
async function withEnv(env, body) {
  const saved = Object.fromEntries(Object.keys(env).map((name) => [name, process.env[name]]));
  Object.assign(process.env, env);
  try {
    return await body();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

// Each failure a client can meet, what it is rejected with, and what that says.
const FAILURES = [
  { name: 'a request the far end failed', ask: (c) => c.get('https://error/'), kind: RequestFailed,
    says: /^upstream refused$/ },
  { name: 'no answer in time', ask: (c) => c.get('https://silent/'), kind: Timeout,
    says: /^tlsforge: request timed out$/ },
  { name: 'a request made in a session that went',
    ask: async (c) => {
      await assert.rejects(() => c.get('https://silent/'), Timeout);
      return c.get('https://ok/');
    },
    kind: SessionReset, says: /has gone \(a request timed out, and it was stopped\)/ },
  { name: 'an answer that is not JSON', ask: (c) => c.get('https://garbage/'), kind: TransportError,
    says: /^tlsforge: bad response: /, cause: SyntaxError },
  { name: 'an answer that is not an object', ask: (c) => c.get('https://null-line/'), kind: TransportError,
    says: /^tlsforge: bad response: expected an object/, cause: Error },
  { name: 'an answer of the wrong shape', ask: (c) => c.get('https://bad-status/'), kind: TransportError,
    says: /^tlsforge: bad response: /, cause: TypeError },
  { name: 'a hello not understood', env: { TLSFORGE_TEST_PROTOCOL: 'bad' }, ask: (c) => c.hello(),
    kind: TransportError, says: /^tlsforge: bad response: hello must give/, cause: TypeError },
  { name: 'a transport that exits', ask: (c) => c.get('https://exit/'), kind: TransportError,
    says: /^tlsforge: transport exited \(code 3\)$/ },
  { name: 'arguments the transport refuses', env: { TLSFORGE_TEST_REFUSE: 'always' },
    ask: (c) => c.get('https://ok/'), kind: TransportError, says: /refused its arguments \(code 2\)$/ },
  { name: 'a proxy the transport does not take', env: { TLSFORGE_TEST_INIT: 'refuse' },
    options: { proxy: 'http://proxy.test:8080' }, ask: (c) => c.get('https://ok/'), kind: TransportError,
    says: /^tlsforge: the transport did not take its proxy: / },
  { name: 'an init line that cannot be written', env: { TLSFORGE_TEST_INIT: 'deaf' },
    options: { proxy: `http://proxy.test:8080/${'x'.repeat(1 << 20)}`, timeout: 5_000 },
    ask: (c) => c.get('https://ok/'), kind: TransportError, says: /^tlsforge: write failed: /, cause: Error },
  { name: 'a browser context the transport does not apply',
    ask: (c) => c.request({ url: 'https://ok/', browserContext: { kind: 'fetch', initiator: 'https://a.test/' } }),
    kind: Unsupported, says: /does not apply browser contexts; the request was not sent$/ },
  { name: 'a client closed', ask: (c) => (c.close(), c.get('https://ok/')), kind: TransportError,
    says: /^tlsforge: this client was closed and will not respawn; construct a new one$/ },
  { name: 'a closed client asked what it is', ask: (c) => (c.close(), c.hello()), kind: TransportError,
    says: /^tlsforge: this client was closed/ },
  { name: 'a request in flight when the client closes',
    ask: (c) => {
      const asked = c.get('https://silent/');
      setTimeout(() => c.close(), 50);
      return asked;
    },
    kind: TransportError, says: /^tlsforge: client closed$/ },
  { name: 'an argument spawn refuses', options: { profile: 'chrome\u0000151' }, ask: (c) => c.get('https://ok/'),
    kind: TransportError, says: /^tlsforge: transport failed to start /, cause: TypeError },
  { name: 'a binary gone before it is started',
    binary: () => {
      const gone = path.join(wrapperDir, 'gone');
      writeFileSync(gone, '#!/bin/sh\n');
      chmodSync(gone, 0o755);
      return gone;
    },
    before: (binary) => unlinkSync(binary),
    ask: (c) => c.get('https://ok/'), kind: TransportError, says: /^tlsforge: transport failed to start /,
    cause: Error },
];

for (const failure of FAILURES) {
  test(`${failure.name}: ${failure.kind.name}`, async () => {
    await withEnv(failure.env ?? {}, async () => {
      const binary = failure.binary?.() ?? wrapper;
      const client = new Client({ binary, timeout: 300, ...failure.options });
      failure.before?.(binary);
      try {
        await assert.rejects(() => failure.ask(client), (err) => {
          assert.ok(err instanceof failure.kind, `${err.name}: ${err.message}`);
          assert.ok(err instanceof TLSForgeError);
          assert.match(err.message, failure.says);
          if (failure.cause) assert.ok(err.cause instanceof failure.cause, String(err.cause));
          else assert.equal(err.cause, undefined);
          return true;
        });
      } finally {
        client.close();
      }
    });
  });
}

test('an install problem is BinaryNotFound', () => {
  assert.throws(() => new Client({ binary: path.join(wrapperDir, 'no-such-binary') }), (err) => {
    assert.ok(err instanceof BinaryNotFound);
    assert.match(err.message, /^tls-forge: no binary at /);
    return true;
  });
});

test('a mistake in the call is a TypeError or a RangeError, and none of the package\'s', async () => {
  const isMistake = (kind, says) => (err) => err instanceof kind && !(err instanceof TLSForgeError) && says.test(err.message);
  assert.throws(() => new Client({ binary: wrapper, timeout: 0 }), isMistake(RangeError, /positive finite/));
  assert.throws(() => new Client({ binary: wrapper, onStderr: 'log' }), isMistake(TypeError, /must be a function/));
  assert.throws(() => new Client({ binary: wrapper, cookieSet: 'eu' }), isMistake(TypeError, /requires cookieFile/));
  const client = new Client({ binary: wrapper });
  try {
    await assert.rejects(() => client.request({}), isMistake(TypeError, /needs a url/));
    await assert.rejects(() => client.post('https://ok/', 7), isMistake(TypeError, /must be a string, Buffer/));
    await assert.rejects(() => client.get('https://ok/', { headers: { n: 10n } }), isMistake(TypeError, /JSON/));
    await assert.rejects(() => client.post('https://ok/', 'x'.repeat(MAX_REQUEST_BYTES)),
      isMistake(RangeError, /send a smaller body/));
    // None of them reached the transport, or cost the session.
    assert.equal((await client.get('https://ok/')).status, 200);
  } finally {
    client.close();
  }
});
