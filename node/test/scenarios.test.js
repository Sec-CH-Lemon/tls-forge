// The fake is held to testdata/fake-daemon/scenarios.json, which every fake —
// this one, Python's and the native one both suites run on Windows — answers
// alike: a scenario added to one and not the others fails here, or in theirs.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, '..', '..', 'testdata', 'protocol');
const table = JSON.parse(readFileSync(path.join(here, '..', '..', 'testdata', 'fake-daemon', 'scenarios.json'), 'utf8'));
const configuredDaemon = process.env.TLSFORGE_TEST_DAEMON;
let wrapper;
if (configuredDaemon) {
  wrapper = path.resolve(configuredDaemon);
} else if (process.platform === 'win32') {
  throw new Error('TLSFORGE_TEST_DAEMON must name the native fake daemon on Windows');
} else {
  wrapper = path.join(mkdtempSync(path.join(os.tmpdir(), 'tls-forge-scenarios-')), 'wrapper.sh');
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${path.join(here, 'fake-daemon.js')}" "$@"\n`);
  chmodSync(wrapper, 0o755);
}

// ask writes one line to a fake started with env, and is its first answer.
async function ask(line, env = {}) {
  const child = spawn(wrapper, ['daemon'], {
    stdio: ['pipe', 'pipe', 'ignore'],
    env: { ...process.env, TLSFORGE_PROTOCOL_FIXTURES: fixtures, ...env },
  });
  const lines = readline.createInterface({ input: child.stdout });
  try {
    child.stdin.write(JSON.stringify(line) + '\n');
    for await (const answer of lines) return JSON.parse(answer);
    throw new Error('the fake said nothing');
  } finally {
    lines.close();
    child.kill();
  }
}

test('the fake answers every scenario scenarios.json names, and no other', async () => {
  const declared = await ask({ id: 1, control: 'scenarios' });
  assert.deepEqual(declared.requests, Object.keys(table.requests).sort());
  assert.deepEqual(declared.protocols, Object.keys(table.protocols).sort());
});

test('a scenario or a protocol mode no fake has is an error naming it', async () => {
  const client = new Client({ binary: wrapper });
  try {
    await assert.rejects(client.get('https://no-such-scenario/'), /unknown scenario "no-such-scenario"/);
  } finally {
    client.close();
  }
  const answer = await ask({ id: 2, control: 'hello' }, { TLSFORGE_TEST_PROTOCOL: 'no-such-mode' });
  assert.equal(answer.id, 2);
  assert.equal(answer.error, 'unknown protocol mode "no-such-mode"');
});
