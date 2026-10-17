import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { TARGETS, assemble } from './npm-release.mjs';

const script = fileURLToPath(new URL('./npm-release.mjs', import.meta.url));
const ROOT = path.resolve(path.dirname(script), '..');
const LEGAL = ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt'];
const PLATFORMS = ['tls-forge-darwin-arm64', 'tls-forge-darwin-x64', 'tls-forge-linux-arm64', 'tls-forge-linux-x64', 'tls-forge-windows-x64'];

const temporary = (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-npm-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// binaries is a directory of the five binaries a release builds, each saying
// which it is and none of them executable, as an artifact download leaves
// them.
function binaries(t) {
  const dir = path.join(temporary(t), 'bin');
  mkdirSync(dir);
  for (const target of TARGETS) {
    const name = `tls-forge-${target.goos}-${target.goarch}${target.goos === 'windows' ? '.exe' : ''}`;
    writeFileSync(path.join(dir, name), `binary ${name}`, { mode: 0o644 });
  }
  return dir;
}

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));

test('each platform gets a package of its binary, stamped with the version', (t) => {
  const out = path.join(temporary(t), 'npm');
  const published = assemble({ version: '1.2.3', binaries: binaries(t), out });
  assert.deepEqual(published.map((p) => p.name), [...PLATFORMS, 'tls-forge']);
  assert.deepEqual(readdirSync(out).sort(), [...PLATFORMS, 'tls-forge'].sort());
  for (const target of TARGETS) {
    const name = `tls-forge-${target.packagePlatform ?? target.platform}-${target.arch}`;
    const dir = path.join(out, name);
    const manifest = read(path.join(dir, 'package.json'));
    assert.equal(manifest.name, name);
    assert.equal(manifest.version, '1.2.3');
    // npm's names for the machine, not Go's: win32 and x64.
    assert.deepEqual(manifest.os, [target.platform]);
    assert.deepEqual(manifest.cpu, [target.arch]);
    assert.deepEqual(manifest.files, ['bin/', ...LEGAL]);
    assert.equal(manifest.license, 'Apache-2.0');
    const exe = target.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge';
    assert.equal(readFileSync(path.join(dir, 'bin', exe), 'utf8'), `binary tls-forge-${target.goos}-${target.goarch}${target.platform === 'win32' ? '.exe' : ''}`);
    // Executable, whatever mode it arrived with.
    if (process.platform !== 'win32') assert.equal(statSync(path.join(dir, 'bin', exe)).mode & 0o777, 0o755, name);
    for (const file of LEGAL) assert.deepEqual(readFileSync(path.join(dir, file)), readFileSync(path.join(ROOT, file)), `${name} ${file}`);
    assert.match(readFileSync(path.join(dir, 'README.md'), 'utf8'), /^# tls-forge-.*\n\nThe tls-forge binary for .*\n\nThis package is not meant to be installed directly/);
  }
  assert.equal(read(path.join(out, 'tls-forge-windows-x64', 'package.json')).os[0], 'win32');
});

test('the main package pins every platform package to exactly its version', (t) => {
  const out = path.join(temporary(t), 'npm');
  assemble({ version: '1.2.3-rc.1', binaries: binaries(t), out });
  const ours = read(path.join(ROOT, 'node', 'package.json'));
  const main = read(path.join(out, 'tls-forge', 'package.json'));
  assert.equal(main.name, 'tls-forge');
  assert.equal(main.version, '1.2.3-rc.1');
  assert.deepEqual(main.optionalDependencies, Object.fromEntries(PLATFORMS.map((name) => [name, '1.2.3-rc.1'])));
  assert.equal(main.scripts, undefined);
  assert.deepEqual(main.files, ours.files);
  // Every file the manifest names is in it, the legal ones from the root.
  for (const file of ours.files) {
    const from = LEGAL.includes(file) ? path.join(ROOT, file) : path.join(ROOT, 'node', file);
    assert.deepEqual(readFileSync(path.join(out, 'tls-forge', file)), readFileSync(from), file);
  }
  for (const file of LEGAL) assert.ok(existsSync(path.join(out, 'tls-forge', file)), file);
});

test('what was there before is not left in the packages', (t) => {
  const out = path.join(temporary(t), 'npm');
  mkdirSync(path.join(out, 'tls-forge-linux-x64', 'bin'), { recursive: true });
  writeFileSync(path.join(out, 'tls-forge-linux-x64', 'bin', 'stale'), 'stale');
  writeFileSync(path.join(out, 'leftover.tgz'), 'old');
  assemble({ version: '1.2.3', binaries: binaries(t), out });
  assert.ok(!existsSync(path.join(out, 'leftover.tgz')));
  assert.deepEqual(readdirSync(path.join(out, 'tls-forge-linux-x64', 'bin')), ['tls-forge']);
});

test('a version npm and PyPI would read apart, a missing binary or a missing notice builds nothing', (t) => {
  const bin = binaries(t);
  for (const version of ['1.2.3-1', 'v1.2.3', '1.2.3+build', '1.2', '01.2.3', '1.2.3-gamma', '', undefined]) {
    const out = path.join(temporary(t), 'npm');
    assert.throws(() => assemble({ version, binaries: bin, out }), { message: `--version ${version} is not a registry-compatible SemVer version` },
      String(version));
    assert.ok(!existsSync(out), String(version));
  }
  rmSync(path.join(bin, 'tls-forge-linux-arm64'));
  assert.throws(() => assemble({ version: '1.2.3', binaries: bin, out: path.join(temporary(t), 'npm') }),
    { message: `no binary at ${path.join(bin, 'tls-forge-linux-arm64')}` });
  // A repository without its NOTICE publishes no binary.
  const root = temporary(t);
  for (const file of ['LICENSE', 'THIRD-PARTY-NOTICES.txt']) cpSync(path.join(ROOT, file), path.join(root, file));
  assert.throws(() => assemble({ version: '1.2.3', binaries: binaries(t), out: path.join(temporary(t), 'npm'), root }),
    { message: 'NOTICE is missing; a published binary must carry it' });
});

test('the command writes the packages where it is told, and says why it did not', (t) => {
  const bin = binaries(t);
  const out = path.join(temporary(t), 'npm');
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', cwd: path.dirname(out) });
  const made = run('--version', '1.2.3', '--binaries', bin, '--out', out);
  assert.equal(made.status, 0, made.stderr);
  assert.deepEqual(made.stdout.trim().split('\n').map((line) => line.split('\t')[0]), [...PLATFORMS, 'tls-forge']);
  assert.ok(made.stdout.includes(`tls-forge\t${path.join(out, 'tls-forge')}\n`));
  // Its defaults are dist/bin and dist/npm, from where it runs.
  const cwd = path.dirname(out);
  mkdirSync(path.join(cwd, 'dist'));
  cpSync(bin, path.join(cwd, 'dist', 'bin'), { recursive: true });
  const defaults = run('--version', '1.2.3');
  assert.equal(defaults.status, 0, defaults.stderr);
  assert.ok(existsSync(path.join(cwd, 'dist', 'npm', 'tls-forge', 'package.json')));
  for (const args of [[], ['--version'], ['--version', 'v1']]) {
    const refused = run(...args);
    assert.equal(refused.status, 1, args.join(' '));
    assert.match(refused.stderr, /is not a registry-compatible SemVer version\n$/);
  }
});
