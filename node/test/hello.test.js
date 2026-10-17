// What a transport is, asked before a request relies on it: hello, and a
// browser context sent only to a transport that says it applies one.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client, Unsupported } from '../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fakeDaemon = path.join(here, 'fake-daemon.js');
// Where the native fake, which stands in on Windows, finds the committed answers.
process.env.TLSFORGE_PROTOCOL_FIXTURES = path.join(here, '..', '..', 'testdata', 'protocol');
const wrapperDir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-hello-'));
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

// withTransport runs body with a client whose transport is started with env
// set, and closes it, the variables restored, after.
async function withTransport(env, body, options = {}) {
  const saved = {};
  for (const [name, value] of Object.entries(env)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  const client = new Client({ binary: wrapper, ...options });
  try {
    await body(client);
  } finally {
    client.close();
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

// seen is what the transport had read by the time it answered a plain request.
async function seen(client) {
  return JSON.parse((await client.get('https://ok/')).body);
}

test('a transport says the protocol it speaks and what it can do, once', async () => {
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: 'one,two' }, async (client) => {
    const first = await client.hello();
    assert.deepEqual(first, { protocol: 2, capabilities: ['one', 'two'] });
    // A copy each time: what one caller does with it is not the next's.
    first.capabilities.push('three');
    assert.deepEqual(await client.hello(), { protocol: 2, capabilities: ['one', 'two'] });
    const { controls, requests } = await seen(client);
    assert.equal(controls, 1);
    assert.equal(requests, 1);
  });
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: '' }, async (client) => {
    assert.deepEqual(await client.hello(), { protocol: 2, capabilities: [] });
  });
});

test('a transport newer than this package is read for what it says it can do', async () => {
  // A protocol after 2, and a capability no package knows yet, are no reason
  // to refuse what both know.
  await withTransport({ TLSFORGE_TEST_PROTOCOL: 'newer' }, async (client) => {
    assert.deepEqual(await client.hello(), { protocol: 7, capabilities: ['browser_context', 'teleport'] });
    const context = { kind: 'fetch', initiator: 'https://example.com/' };
    const answer = JSON.parse((await client.get('https://ok/', { browserContext: context })).body);
    assert.deepEqual(answer.browser, context);
  });
});

test('a transport older than the question speaks protocol 1', async () => {
  await withTransport({ TLSFORGE_TEST_PROTOCOL: '1' }, async (client) => {
    assert.deepEqual(await client.hello(), { protocol: 1, capabilities: [] });
  });
});

test('the committed answers to hello read as they say', async () => {
  for (const [mode, want] of [
    ['fixture', { protocol: 2, capabilities: ['browser_context'] }],
    ['fixture-old', { protocol: 1, capabilities: [] }],
  ]) {
    await withTransport({ TLSFORGE_TEST_PROTOCOL: mode }, async (client) => {
      assert.deepEqual(await client.hello(), want);
    });
  }
});

test('an answer to hello that says nothing it can is a bad response, asked again', async () => {
  for (const mode of ['bad', 'bad-capabilities', 'no-capabilities', 'low']) {
    await withTransport({ TLSFORGE_TEST_PROTOCOL: mode }, async (client) => {
      await assert.rejects(client.hello(), /^Error: tlsforge: bad response: hello must give a protocol from 2/);
      await assert.rejects(client.hello(), /bad response/);
      assert.equal((await seen(client)).controls, 2, mode);
    });
  }
});

test('a transport that does not answer hello has said nothing, and is asked again', async () => {
  await withTransport({ TLSFORGE_TEST_PROTOCOL: 'silent' }, async (client) => {
    await assert.rejects(client.hello(), /request timed out/);
    // A question was made in no session: it is asked of the next transport,
    // and the next request is the one told its session has gone.
    await assert.rejects(client.hello(), /request timed out/);
    await assert.rejects(client.get('https://ok/'), (err) => err.name === 'SessionReset');
    assert.equal((await seen(client)).controls, 0);
  }, { timeout: 300 });
  await withTransport({ TLSFORGE_TEST_PROTOCOL: 'exit' }, async (client) => {
    await assert.rejects(client.hello(), /transport exited \(code 3\)/);
  });
});

test('a question asked after a session went leaves the next request to be told', async () => {
  await withTransport({}, async (client) => {
    await assert.rejects(client.get('https://silent/'), /request timed out/);
    assert.deepEqual(await client.hello(), { protocol: 2, capabilities: [] });
    await assert.rejects(client.get('https://ok/'), (err) => err.name === 'SessionReset');
    assert.equal((await seen(client)).requests, 1);
  }, { timeout: 300 });
});

test('a closed client asks nothing', async () => {
  const client = new Client({ binary: wrapper });
  client.close();
  await assert.rejects(client.hello(), /closed/);
});

test('a browser context goes to a transport that applies one, and to no other', async () => {
  const context = { kind: 'fetch', initiator: 'https://example.com/' };
  for (const [env, protocol] of [[{ TLSFORGE_TEST_CAPABILITIES: 'other' }, 2], [{ TLSFORGE_TEST_PROTOCOL: '1' }, 1]]) {
    await withTransport(env, async (client) => {
      const refused = await client.get('https://ok/', { browserContext: context }).then(
        () => assert.fail('sent'),
        (err) => err,
      );
      assert.ok(refused instanceof Unsupported);
      assert.equal(refused.name, 'Unsupported');
      assert.equal(
        refused.message,
        `tlsforge: the tls-forge at ${wrapper} speaks protocol ${protocol} and does not apply browser ` +
          'contexts; the request was not sent',
      );
      // Asked, and nothing sent: the plain request after it is the first.
      assert.equal((await seen(client)).requests, 1);
    });
  }
  await withTransport({ TLSFORGE_TEST_CAPABILITIES: 'browser_context' }, async (client) => {
    const answer = JSON.parse((await client.post('https://ok/', 'x', { browserContext: context })).body);
    // Sent as the protocol names it, and under no other name.
    assert.deepEqual(answer.browser, context);
    assert.ok(answer.sent.includes('browser'));
    assert.ok(!answer.sent.includes('browserContext'));
    assert.equal(answer.bodyLength, 1);
  });
  // Without one, nothing is asked.
  await withTransport({}, async (client) => {
    const answer = await seen(client);
    assert.equal(answer.controls, 0);
    assert.equal(answer.browser, null);
    assert.ok(!answer.sent.includes('browser'));
  });
});
