import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { TARGETS, build, run } from './release-build.mjs';
import { MANIFEST, pep440, problems, required } from './release-set.mjs';

const script = fileURLToPath(new URL('./release-build.mjs', import.meta.url));
const ROOT = path.resolve(path.dirname(script), '..');
const VERSION = '4.0.0';
const COMMIT = 'a'.repeat(40);

const temporary = (t, prefix = 'tls-forge-build-test-') => {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// The npm packages npm-release.mjs makes, by name.
const PACKAGES = ['tls-forge', 'tls-forge-darwin-arm64', 'tls-forge-darwin-x64', 'tls-forge-linux-arm64', 'tls-forge-linux-x64',
  'tls-forge-windows-x64'];

const option = (args, name) => args[args.indexOf(name) + 1];

// fakeTools stands in for every tool a build runs, each leaving what the real
// one would where the real one would, and notes how each was run: an archive
// notes what was in it, and with what mode. fail names a tool that fails, and
// change changes what one leaves.
function fakeTools({ fail = null, change = {} } = {}) {
  const calls = [];
  const archives = new Map();
  const exec = (command, args, options = {}) => {
    // A script is known by its name, whatever runs it.
    const tool = /\.(mjs|py)$/.test(args[0] ?? '') ? path.basename(args[0]) : command;
    calls.push({ tool, command, args, options });
    if (tool === fail) throw new Error(`${tool} failed: exit 1`);
    if (tool === 'go') {
      mkdirSync(path.dirname(option(args, '-o')), { recursive: true });
      writeFileSync(option(args, '-o'), `binary for ${options.env.GOOS}/${options.env.GOARCH}`);
    } else if (tool === 'tar') {
      const staging = args[3];
      archives.set(path.basename(args[1]), readdirSync(staging).sort().map((name) => [name, statSync(path.join(staging, name)).mode & 0o777]));
      writeFileSync(args[1], JSON.stringify(archives.get(path.basename(args[1]))));
    } else if (tool === 'npm-release.mjs') {
      for (const name of PACKAGES) {
        mkdirSync(path.join(option(args, '--out'), name), { recursive: true });
        writeFileSync(path.join(option(args, '--out'), name, 'package.json'), JSON.stringify({ name, version: option(args, '--version') }));
      }
    } else if (tool === 'npm') {
      const { name, version } = JSON.parse(readFileSync(path.join(args[1], 'package.json'), 'utf8'));
      writeFileSync(path.join(option(args, '--pack-destination'), change.pack?.(name, version) ?? `${name}-${version}.tgz`), name);
    } else if (tool === 'homebrew-formula.mjs') {
      return `class TlsForge < Formula # ${option(args, '--version')}\nend\n`;
    } else {
      // The Python distributions, named as PyPI spells the version.
      const spelled = pep440(option(args, '--version'));
      mkdirSync(option(args, '--out'), { recursive: true });
      for (const name of required(option(args, '--version')).filter((name) => name.startsWith(`tls_forge-${spelled}`))) {
        writeFileSync(path.join(option(args, '--out'), name), name);
      }
    }
    return '';
  };
  return { exec, calls, archives };
}

test('a build makes the set of its version, from its commit, and it verifies', (t) => {
  const out = path.join(temporary(t), 'set');
  const tools = fakeTools();
  const lines = [];
  const dir = build({ version: VERSION, commit: COMMIT, out, python: '/opt/python' }, { exec: tools.exec, log: (line) => lines.push(line) });
  assert.equal(dir, out);
  assert.deepEqual(problems(dir, VERSION, COMMIT), []);
  assert.deepEqual(readdirSync(dir).sort(), [...required(VERSION), MANIFEST].sort());
  assert.equal(JSON.parse(readFileSync(path.join(dir, MANIFEST), 'utf8')).commit, COMMIT);

  // Each platform's binary is built as a release builds it, statically, with
  // the version it says.
  const builds = tools.calls.filter((call) => call.tool === 'go');
  assert.deepEqual(builds.map((call) => [call.options.env.GOOS, call.options.env.GOARCH]), TARGETS);
  for (const call of builds) {
    assert.deepEqual(call.args.slice(0, 4), ['build', '-trimpath', '-ldflags', '-s -w -X main.version=v4.0.0']);
    assert.equal(call.args.at(-1), './cmd/tls-forge');
    assert.equal(call.options.env.CGO_ENABLED, '0');
    assert.equal(call.options.cwd, undefined);
  }
  assert.ok(builds.at(-1).args.includes(path.join(path.dirname(option(builds[0].args, '-o')), 'tls-forge-windows-amd64.exe')));

  // Each archive holds its binary, executable, with the notices and the README.
  for (const [goos, goarch] of TARGETS) {
    const exe = goos === 'windows' ? 'tls-forge.exe' : 'tls-forge';
    assert.deepEqual(tools.archives.get(`tls-forge_4.0.0_${goos}_${goarch}.tar.gz`),
      [['LICENSE', 0o644], ['NOTICE', 0o644], ['README.md', 0o644], ['THIRD-PARTY-NOTICES.txt', 0o644], [exe, 0o755]]
        .map(([name, mode]) => [name, name === exe ? 0o755 : statSync(path.join(ROOT, name)).mode & 0o777])
        .sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  }
  for (const call of tools.calls.filter((c) => c.tool === 'tar')) assert.equal(call.options.env.COPYFILE_DISABLE, '1');

  // Every npm package is packed, scripts not run, and the Python ones built
  // with the Python it was told.
  const packs = tools.calls.filter((call) => call.tool === 'npm');
  assert.equal(packs.length, 6);
  for (const call of packs) assert.deepEqual([call.args[0], ...call.args.slice(2)], ['pack', '--pack-destination', dir, '--ignore-scripts']);
  assert.equal(tools.calls.find((call) => call.tool === 'pypi-release.py').command, '/opt/python');
  assert.equal(readFileSync(path.join(dir, 'tls-forge.rb'), 'utf8'), 'class TlsForge < Formula # 4.0.0\nend\n');
  for (const name of ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt']) {
    assert.deepEqual(readFileSync(path.join(dir, name)), readFileSync(path.join(ROOT, name)), name);
  }
  // In order: binaries and their archives, npm, Python, then the formula from
  // the archives.
  assert.deepEqual([...new Set(tools.calls.map((call) => call.tool))],
    ['go', 'tar', 'npm-release.mjs', 'npm', 'pypi-release.py', 'homebrew-formula.mjs']);
  assert.equal(lines.length, 6);
  assert.equal(lines.at(-1), `${dir}: the set of 4.0.0, built from ${COMMIT}`);
  // What it worked in is gone.
  assert.ok(!existsSync(path.dirname(path.dirname(option(builds[0].args, '-o')))));
});

test('a different engine version is refused before any build or filesystem output', (t) => {
  for (const version of ['0.1.0', '3.0.0', '4.0.1', '4.0.0-rc.1']) {
    const out = path.join(temporary(t), 'set');
    const tools = fakeTools();
    assert.throws(() => build({version, commit: COMMIT, out}, {exec:tools.exec}), /does not match compiled engine 4.0.0/);
    assert.deepEqual(tools.calls, []);
    assert.equal(existsSync(out), false);
  }
});

test('a set is made from nothing, of a release version and a whole commit', (t) => {
  const root = temporary(t);
  const tools = fakeTools();
  const held = path.join(root, 'held');
  mkdirSync(held);
  writeFileSync(path.join(held, 'old.tgz'), 'old');
  for (const [given, says] of [
    [{ version: 'v4.0.0', commit: COMMIT, out: path.join(root, 'a') }, /^Error: --version v4\.0\.0 is not a release version$/],
    [{ version: VERSION, commit: 'abc', out: path.join(root, 'b') }, /^Error: --commit abc is not a full commit$/],
    [{ version: VERSION, out: path.join(root, 'c') }, /^Error: --commit undefined is not a full commit$/],
    [{ version: VERSION, commit: COMMIT }, /^Error: --out is where the set is made, and is not said$/],
    [{ version: VERSION, commit: COMMIT, out: '' }, /^Error: --out is where the set is made, and is not said$/],
    [{ version: VERSION, commit: COMMIT, out: held }, /holds files already: a set is made from nothing$/],
  ]) {
    assert.throws(() => build(given, { exec: tools.exec }), says, JSON.stringify(given));
  }
  // Nothing was run, nothing made, and what was there is as it was.
  assert.deepEqual(tools.calls, []);
  assert.deepEqual(readdirSync(root).sort(), ['held']);
  assert.deepEqual(readdirSync(held), ['old.tgz']);
  // An empty directory there already is where it is made, and one named
  // from here is where it is, said whole.
  const empty = path.join(root, 'empty');
  mkdirSync(empty);
  assert.equal(build({ version: VERSION, commit: COMMIT, out: path.relative(process.cwd(), empty) }, { exec: fakeTools().exec }), empty);
  assert.deepEqual(problems(empty, VERSION, COMMIT), []);
});

test('a step that fails stops the build, and leaves nothing it worked in', (t) => {
  for (const tool of ['go', 'tar', 'npm-release.mjs', 'npm', 'pypi-release.py', 'homebrew-formula.mjs']) {
    const out = path.join(temporary(t), 'set');
    const tools = fakeTools({ fail: tool });
    assert.throws(() => build({ version: VERSION, commit: COMMIT, out }, { exec: tools.exec }), new RegExp(`^Error: ${tool} failed`), tool);
    const work = path.dirname(path.dirname(option(tools.calls[0].args, '-o')));
    assert.ok(!existsSync(work), tool);
    // No set: without a manifest, nothing would take it for one.
    assert.ok(!existsSync(path.join(out, MANIFEST)), tool);
  }
});

test('what is built that is not a release set stops it', (t) => {
  const out = path.join(temporary(t), 'set');
  const tools = fakeTools({ change: { pack: (name, version) => `${name}-v${version}.tgz` } });
  assert.throws(() => build({ version: VERSION, commit: COMMIT, out }, { exec: tools.exec }),
    /^Error: what was built is not a release's set:\nthe set has no tls-forge-4\.0\.0\.tgz\n/);
});

test('a command is run where it is told, and fails out loud', (t) => {
  const dir = temporary(t);
  assert.equal(run(process.execPath, ['-e', 'process.stdout.write(process.cwd() + " " + process.env.SAID)'], { cwd: dir, env: { SAID: 'yes' } }),
    `${realpath(dir)} yes`);
  // In the repository, wherever this process is.
  const cwd = process.cwd();
  process.chdir(dir);
  try {
    assert.equal(run(process.execPath, ['-e', 'process.stdout.write(process.cwd())']), ROOT);
  } finally {
    process.chdir(cwd);
  }
  assert.throws(() => run(process.execPath, ['-e', 'process.exit(3)']), /-e process\.exit\(3\) failed: exit 3$/);
  assert.throws(() => run(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM")']), /failed: SIGTERM$/);
  assert.throws(() => run(path.join(dir, 'no-such-tool'), []), /ENOENT/);
});

// realpath is dir as the process in it sees it: macOS's temporary directory
// is behind a link.
function realpath(dir) {
  return spawnSync(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], { cwd: dir, encoding: 'utf8' }).stdout;
}

test('the command builds a set with the real packaging, and says why it did not', { skip: process.platform === 'win32' }, (t) => {
  // Go and Python stand in, since a cross-compile is slow and a Python build
  // reaches the network for its backend. npm, tar and the packaging scripts
  // are the real ones.
  const root = temporary(t);
  const bin = path.join(root, 'bin');
  mkdirSync(bin);
  writeFileSync(path.join(bin, 'go'), [
    '#!/bin/sh',
    'while [ $# -gt 0 ]; do',
    '  if [ "$1" = -o ]; then mkdir -p "$(dirname "$2")"; printf "binary for %s/%s\\n" "$GOOS" "$GOARCH" > "$2"; fi',
    '  shift',
    'done',
  ].join('\n'), { mode: 0o755 });
  const wheels = required(VERSION).filter((name) => name.startsWith('tls_forge-'));
  writeFileSync(path.join(bin, 'python3'), [
    '#!/bin/sh',
    'out=""',
    'while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done',
    'mkdir -p "$out"',
    ...wheels.map((name) => `printf %s ${name} > "$out/${name}"`),
  ].join('\n'), { mode: 0o755 });
  const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}` };
  const runBuild = (...args) => spawnSync(process.execPath, [script, ...args], { env, encoding: 'utf8' });
  const out = path.join(root, 'set');
  const built = runBuild('--version', VERSION, '--commit', COMMIT, '--out', out);
  assert.equal(built.status, 0, built.stderr);
  assert.match(built.stdout, /^building tls-forge-darwin-arm64$/m);
  assert.ok(built.stdout.endsWith(`${out}: the set of 4.0.0, built from ${COMMIT}\n`));
  assert.deepEqual(problems(out, VERSION, COMMIT), []);
  // The formula names each archive by its checksum.
  const formula = readFileSync(path.join(out, 'tls-forge.rb'), 'utf8');
  const sums = Object.fromEntries(readFileSync(path.join(out, 'SHA256SUMS'), 'utf8').trim().split('\n').map((line) => line.split('  ').reverse()));
  for (const target of ['darwin_arm64', 'darwin_amd64', 'linux_arm64', 'linux_amd64']) {
    const archive = `tls-forge_4.0.0_${target}.tar.gz`;
    assert.ok(formula.includes(`/v4.0.0/${archive}"\n      sha256 "${sums[archive]}"`), archive);
  }
  // An archive holds the binary, executable, beside the notices.
  const listed = spawnSync('tar', ['-tvzf', path.join(out, 'tls-forge_4.0.0_linux_amd64.tar.gz')], { encoding: 'utf8' }).stdout;
  assert.match(listed, /^-rwxr-xr-x .* \.\/tls-forge$/m);
  for (const name of ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt', 'README.md']) assert.match(listed, new RegExp(`\\./${name}$`, 'm'));
  assert.doesNotMatch(listed, /\._/);
  // The npm packages are the real ones, stamped with the version.
  const packed = spawnSync('tar', ['-xzOf', path.join(out, 'tls-forge-4.0.0.tgz'), 'package/package.json'], { encoding: 'utf8' }).stdout;
  assert.equal(JSON.parse(packed).version, VERSION);
  assert.equal(JSON.parse(packed).optionalDependencies['tls-forge-linux-x64'], VERSION);

  // Over a set already there, or told too little, it builds nothing.
  const again = runBuild('--version', VERSION, '--commit', COMMIT, '--out', out);
  assert.equal(again.status, 1);
  assert.equal(again.stderr, `${out} holds files already: a set is made from nothing\n`);
  for (const args of [[], ['--version', VERSION, '--commit', COMMIT], ['--version', VERSION, '--out', out]]) {
    const usage = runBuild(...args);
    assert.equal(usage.status, 2, args.join(' '));
    assert.equal(usage.stderr, 'usage: release-build.mjs --version V --commit SHA --out DIR [--python PYTHON]\n');
  }
});
