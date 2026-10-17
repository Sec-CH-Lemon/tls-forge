import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { problems, unpinned } from './check-actions.mjs';

const script = fileURLToPath(new URL('./check-actions.mjs', import.meta.url));
const WORKFLOWS = path.join(path.dirname(script), '..', '.github', 'workflows');
const SHA = 'a'.repeat(40);

test('an action pinned to a release commit, a local one and an image by digest are pinned', () => {
  assert.deepEqual(unpinned([
    'jobs:',
    '  a:',
    '    steps:',
    `      - uses: actions/checkout@${SHA} # v7.0.1`,
    `      - uses: "actions/setup-go@${SHA}" # v7`,
    `      - uses: 'actions/setup-node@${SHA}'   #  v7.1`,
    `      - uses: github/codeql-action/init@${SHA} # v4.2.0`,
    `        uses: docker/login-action@${SHA} # v4.6.0`,
    '      - uses: ./.github/actions/local',
    `      - uses: docker://alpine@sha256:${'b'.repeat(64)}`,
    '  reuse:',
    '    uses: ./.github/workflows/capture.yml',
    '    # uses: actions/checkout@v7 in a comment is no step',
    '      - run: echo uses: actions/checkout@v7',
  ].join('\n')), []);
});

test('a tag, a branch, a short commit or a missing release is not pinned', () => {
  assert.deepEqual(unpinned([
    '      - uses: actions/checkout@v7',
    '      - uses: pypa/gh-action-pypi-publish@release/v1',
    `      - uses: actions/checkout@${SHA.slice(0, 7)} # v7.0.1`,
    `      - uses: actions/checkout@${SHA}`,
    `      - uses: actions/checkout@${SHA} # latest`,
    `      - uses: actions/checkout@${SHA} # v7.0.1.2`,
    `      - uses: actions/checkout@${'A'.repeat(40)} # v7`,
    `      - uses: actions/checkout@${SHA}0 # v7`,
    '      - uses: docker://alpine:3.22',
    `      - uses: docker://alpine@sha256:${'b'.repeat(63)}`,
    '      - uses: actions/checkout',
    `      - uses: checkout@${SHA} # v7`,
    `      - uses: https://github.com/actions/checkout@${SHA} # v7.0.1`,
  ].join('\n')), [
    { line: 1, uses: 'actions/checkout@v7', why: 'is not pinned to a commit' },
    { line: 2, uses: 'pypa/gh-action-pypi-publish@release/v1', why: 'is not pinned to a commit' },
    { line: 3, uses: `actions/checkout@${SHA.slice(0, 7)}`, why: 'is not pinned to a commit' },
    { line: 4, uses: `actions/checkout@${SHA}`, why: 'does not name the release its commit is, as # vX.Y.Z' },
    { line: 5, uses: `actions/checkout@${SHA}`, why: 'does not name the release its commit is, as # vX.Y.Z' },
    { line: 6, uses: `actions/checkout@${SHA}`, why: 'does not name the release its commit is, as # vX.Y.Z' },
    { line: 7, uses: `actions/checkout@${'A'.repeat(40)}`, why: 'is not pinned to a commit' },
    { line: 8, uses: `actions/checkout@${SHA}0`, why: 'is not pinned to a commit' },
    { line: 9, uses: 'docker://alpine:3.22', why: 'is an image not pinned by its digest' },
    { line: 10, uses: `docker://alpine@sha256:${'b'.repeat(63)}`, why: 'is an image not pinned by its digest' },
    { line: 11, uses: 'actions/checkout', why: 'is not pinned to a commit' },
    { line: 12, uses: `checkout@${SHA}`, why: 'is not pinned to a commit' },
    { line: 13, uses: `https://github.com/actions/checkout@${SHA}`, why: 'is not pinned to a commit' },
  ]);
});

test('every workflow of this repository is pinned', () => {
  assert.deepEqual(problems(WORKFLOWS), []);
});

test('the command says each one, by file and line, and exits by it', (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-actions-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(path.join(dir, 'b.yml'), `steps:\n  - uses: actions/checkout@v7\n  - uses: actions/setup-go@${SHA} # v7\n`);
  writeFileSync(path.join(dir, 'a.yaml'), 'steps:\n  - uses: docker://alpine:3\n');
  writeFileSync(path.join(dir, 'notes.md'), '- uses: actions/checkout@v7\n');
  mkdirSync(path.join(dir, 'nested.yml.d'));
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  const found = run(dir);
  assert.equal(found.status, 1);
  assert.equal(found.stderr, [
    `${path.join(dir, 'a.yaml')}:2: docker://alpine:3 is an image not pinned by its digest`,
    `${path.join(dir, 'b.yml')}:2: actions/checkout@v7 is not pinned to a commit`,
    '',
  ].join('\n'));
  // By name, whatever order the directory lists them in.
  const many = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-actions-'));
  t.after(() => rmSync(many, { recursive: true, force: true }));
  const names = ['zeta.yml', 'alpha.yml', 'mu.yml', 'delta.yml', 'omega.yml', 'beta.yml', 'kappa.yml', 'gamma.yml'];
  for (const name of names) writeFileSync(path.join(many, name), '- uses: actions/checkout@v7\n');
  assert.deepEqual(problems(many), [...names].sort().map((name) => `${path.join(many, name)}:1: actions/checkout@v7 is not pinned to a commit`));
  // Without a directory, the repository's own workflows, which are pinned.
  const own = run();
  assert.equal(own.status, 0, own.stderr);
  const missing = run(path.join(dir, 'none'));
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /ENOENT/);
});
