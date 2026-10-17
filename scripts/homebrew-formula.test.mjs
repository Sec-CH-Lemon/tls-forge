import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const generator = fileURLToPath(new URL('./homebrew-formula.mjs', import.meta.url));
const TARGETS = [
  ['macos', 'arm', 'darwin_arm64'],
  ['macos', 'intel', 'darwin_amd64'],
  ['linux', 'arm', 'linux_arm64'],
  ['linux', 'intel', 'linux_amd64'],
];

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

// archives is a directory holding the four archives the formula names for
// version, each its own contents, and the Windows one it does not.
function archives(t, version = '1.2.3') {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-homebrew-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [, , target] of TARGETS) writeFileSync(path.join(dir, `tls-forge_${version}_${target}.tar.gz`), `archive ${target}`);
  writeFileSync(path.join(dir, `tls-forge_${version}_windows_amd64.tar.gz`), 'archive windows');
  return dir;
}

const generate = (args, options = {}) => spawnSync(process.execPath, [generator, ...args], { encoding: 'utf8', ...options });

test('each platform installs its own archive, by its URL and its checksum', (t) => {
  const dir = archives(t);
  const generated = generate(['--version', '1.2.3', '--archives', dir]);
  assert.equal(generated.status, 0, generated.stderr);
  const formula = generated.stdout;
  for (const [system, cpu, target] of TARGETS) {
    const name = `tls-forge_1.2.3_${target}.tar.gz`;
    // The archive's block, inside its system's: its URL, and the checksum of
    // exactly that archive under it.
    const block = [
      `    on_${cpu} do`,
      `      url "https://github.com/Sec-CH-Lemon/tls-forge/releases/download/v1.2.3/${name}"`,
      `      sha256 "${sha256(`archive ${target}`)}"`,
      '    end',
    ].join('\n');
    const system_ = formula.slice(formula.indexOf(`  on_${system} do\n`), formula.indexOf('\n  end\n', formula.indexOf(`  on_${system} do\n`)));
    assert.ok(system_.includes(block), `${system} ${cpu}:\n${formula}`);
  }
  // Windows has no formula, and the version is read from the URLs.
  assert.doesNotMatch(formula, /windows/);
  assert.doesNotMatch(formula, /^\s*version\s+"/m);
  assert.match(formula, /^class TlsForge < Formula$/m);
  assert.match(formula, /^ {4}bin\.install "tls-forge"$/m);
  assert.match(formula, /^ {4}pkgshare\.install "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES\.txt"$/m);
  // Four checksums, all different, one for each archive.
  const sums = [...formula.matchAll(/sha256 "([0-9a-f]{64})"/g)].map((match) => match[1]);
  assert.deepEqual(sums, TARGETS.map(([, , target]) => sha256(`archive ${target}`)));
});

test('a pre-release is named as its tag is', (t) => {
  const dir = archives(t, '1.2.3-rc.1');
  const generated = generate(['--version', '1.2.3-rc.1', '--archives', dir]);
  assert.equal(generated.status, 0, generated.stderr);
  assert.ok(generated.stdout.includes('/releases/download/v1.2.3-rc.1/tls-forge_1.2.3-rc.1_linux_amd64.tar.gz"'));
});

test('an archive that is not there, or a version that is none, writes no formula', (t) => {
  const dir = archives(t);
  rmSync(path.join(dir, 'tls-forge_1.2.3_linux_arm64.tar.gz'));
  const missing = generate(['--version', '1.2.3', '--archives', dir]);
  assert.notEqual(missing.status, 0);
  assert.equal(missing.stdout, '');
  assert.match(missing.stderr, new RegExp(`no archive at ${path.join(dir, 'tls-forge_1.2.3_linux_arm64.tar.gz').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  for (const version of ['v1.2.3', '1.2', '1.2.3+build', '1.2.3-']) {
    const refused = generate(['--version', version, '--archives', dir]);
    assert.notEqual(refused.status, 0, version);
    assert.match(refused.stderr, new RegExp(`--version ${version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} is not a semver version`), version);
  }
  // No version at all, or a flag with nothing after it.
  for (const args of [[], ['--archives', dir], ['--archives', dir, '--version']]) {
    const unnamed = generate(args);
    assert.notEqual(unnamed.status, 0, args.join(' '));
    assert.match(unnamed.stderr, /missing --version/, args.join(' '));
  }
});

test('the archives are in dist/release unless said', (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-homebrew-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'dist', 'release'), { recursive: true });
  for (const [, , target] of TARGETS) writeFileSync(path.join(root, 'dist', 'release', `tls-forge_1.2.3_${target}.tar.gz`), target);
  const generated = generate(['--version', '1.2.3'], { cwd: root });
  assert.equal(generated.status, 0, generated.stderr);
  assert.ok(generated.stdout.includes(`sha256 "${sha256('linux_amd64')}"`));
});
