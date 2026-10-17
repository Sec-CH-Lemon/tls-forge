import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { MANIFEST, SUMS, gates, make, pep440, problems, required, sha256, sums } from './release-set.mjs';

const script = fileURLToPath(new URL('./release-set.mjs', import.meta.url));
const VERSION = '1.2.3';
const COMMIT = 'a'.repeat(40);

const temporary = (t, prefix = 'tls-forge-set-') => {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// aSet is a directory holding every file a release of version has, each its
// own name for contents, made into a set when made is true.
function aSet(t, { made = true, version = VERSION } = {}) {
  const dir = temporary(t);
  for (const name of required(version).filter((name) => name !== SUMS)) writeFileSync(path.join(dir, name), name);
  if (made) make(dir, version, COMMIT);
  return dir;
}

const edit = (dir, name, change) => {
  const file = path.join(dir, name);
  writeFileSync(file, change(readFileSync(file, 'utf8')));
};

// aReference is a reference manifest naming builds, which only the gates read.
function aReference(t, builds) {
  const file = path.join(temporary(t, 'tls-forge-reference-'), 'chrome.json');
  writeFileSync(file, JSON.stringify({ schema: 1, version: '155.0.8059.80', builds }));
  return file;
}

const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });

test('PyPI spells a version its own way, and only a release version', () => {
  for (const [version, spelled] of [
    ['1.2.3', '1.2.3'],
    ['0.0.0', '0.0.0'],
    ['10.20.30', '10.20.30'],
    ['1.2.3-rc.1', '1.2.3rc1'],
    ['1.2.3-rc1', '1.2.3rc1'],
    ['1.2.3-rc', '1.2.3rc0'],
    ['1.2.3-c.3', '1.2.3rc3'],
    ['1.2.3-pre.1', '1.2.3rc1'],
    ['1.2.3-preview', '1.2.3rc0'],
    ['1.2.3-alpha.2', '1.2.3a2'],
    ['1.2.3-a', '1.2.3a0'],
    ['1.2.3-beta.10', '1.2.3b10'],
    ['1.2.3-b1', '1.2.3b1'],
    ['1.2.3-dev', '1.2.3.dev0'],
    ['1.2.3-dev.4', '1.2.3.dev4'],
    ['1.2.3-dev7', '1.2.3.dev7'],
  ]) {
    assert.equal(pep440(version), spelled, version);
  }
  // SemVer's -1 is a post-release on PyPI, and the rest is no version either.
  for (const version of ['v1.2.3', '1.2', '01.2.3', '1.2.3-1', '1.2.3-rc.01', '1.2.3-gamma', '1.2.3-rc.1.2', '1.2.3+build', '', undefined, null]) {
    assert.throws(() => pep440(version), { message: `--version ${version} is not a release version` }, String(version));
  }
});

test('a set made is one that verifies, and its identity is its manifest', (t) => {
  const dir = aSet(t);
  assert.deepEqual(problems(dir, VERSION, COMMIT), []);
  const manifest = JSON.parse(readFileSync(path.join(dir, MANIFEST), 'utf8'));
  assert.equal(manifest.schema, 1);
  assert.equal(manifest.version, VERSION);
  assert.equal(manifest.commit, COMMIT);
  // Every file but the manifest, by name: five archives, six npm packages, a
  // source distribution and five wheels, the formula, three legal files and
  // SHA256SUMS.
  assert.equal(manifest.files.length, 22);
  assert.deepEqual(manifest.files.map((file) => file.name), [...required(VERSION)].sort());
  assert.equal(readFileSync(path.join(dir, SUMS), 'utf8'), sums(manifest.files));
  // A pre-release's Python files are named as PyPI spells it, and the rest as the tag.
  const next = aSet(t, { version: '1.2.3-rc.1' });
  assert.deepEqual(problems(next, '1.2.3-rc.1', COMMIT), []);
  assert.ok(required('1.2.3-rc.1').includes('tls_forge-1.2.3rc1.tar.gz'));
  assert.ok(required('1.2.3-rc.1').includes('tls_forge-1.2.3rc1-py3-none-win_amd64.whl'));
  assert.ok(required('1.2.3-rc.1').includes('tls-forge_1.2.3-rc.1_linux_amd64.tar.gz'));
});

test('a set without what a release needs is no set', (t) => {
  for (const name of [
    `tls-forge_${VERSION}_windows_amd64.tar.gz`,
    'NOTICE',
    `tls-forge-linux-arm64-${VERSION}.tgz`,
    `tls-forge-${VERSION}.tgz`,
    `tls_forge-${VERSION}.tar.gz`,
    `tls_forge-${VERSION}-py3-none-win_amd64.whl`,
    'tls-forge.rb',
  ]) {
    const dir = aSet(t, { made: false });
    unlinkSync(path.join(dir, name));
    make(dir, VERSION, COMMIT);
    assert.deepEqual(problems(dir, VERSION, COMMIT), [`the set has no ${name}`], name);
  }
});

test('a set with a file a release does not have is no set', (t) => {
  // Made with it, so the manifest lists it: a wheel of another version, and
  // what a build left behind.
  const dir = aSet(t, { made: false });
  writeFileSync(path.join(dir, 'tls_forge-1.2.4-py3-none-win_amd64.whl'), 'another');
  writeFileSync(path.join(dir, 'build.log'), 'log');
  // A directory is not a file of the set, whatever is in it.
  mkdirSync(path.join(dir, 'staging'));
  make(dir, VERSION, COMMIT);
  assert.deepEqual(problems(dir, VERSION, COMMIT), [
    `build.log is no file a release of ${VERSION} has`,
    `tls_forge-1.2.4-py3-none-win_amd64.whl is no file a release of ${VERSION} has`,
  ]);
});

test('a set is held to its version and its commit', (t) => {
  const dir = aSet(t);
  const theirs = required('1.2.4');
  const ours = required(VERSION);
  assert.deepEqual(problems(dir, '1.2.4', COMMIT), [
    'the set is of version 1.2.3, not 1.2.4',
    ...theirs.filter((name) => !ours.includes(name)).map((name) => `the set has no ${name}`),
    ...ours.filter((name) => !theirs.includes(name)).sort().map((name) => `${name} is no file a release of 1.2.4 has`),
  ]);
  assert.deepEqual(problems(dir, VERSION, 'b'.repeat(40)), [`the set was built from ${COMMIT}, not ${'b'.repeat(40)}`]);
  assert.deepEqual(problems(dir, 'v1.2.3', COMMIT), ['--version v1.2.3 is not a release version']);
  assert.deepEqual(problems(dir, undefined, COMMIT), ['--version undefined is not a release version']);
});

test('a file that is not what the manifest says stops the release', (t) => {
  // Changed and the same size, it is found by its digest.
  const same = aSet(t);
  edit(same, 'NOTICE', (text) => text.toLowerCase());
  assert.deepEqual(problems(same, VERSION, COMMIT), [`NOTICE is not what the manifest says: its digest is ${sha256('notice')}`]);
  const dir = aSet(t);
  edit(dir, 'NOTICE', () => 'another notice');
  assert.deepEqual(problems(dir, VERSION, COMMIT), [
    `NOTICE is not what the manifest says: its digest is ${sha256('another notice')}`,
  ]);
  // The same digest and another size is not the file either.
  edit(dir, MANIFEST, (text) => {
    const manifest = JSON.parse(text);
    const notice = manifest.files.find((file) => file.name === 'NOTICE');
    notice.sha256 = sha256('another notice');
    notice.size += 1;
    return JSON.stringify(manifest);
  });
  assert.deepEqual(problems(dir, VERSION, COMMIT), [
    `NOTICE is not what the manifest says: its digest is ${sha256('another notice')}`,
    // Which SHA256SUMS, written for the first digest, no longer says.
    `${SUMS} is not what the manifest makes it`,
  ]);
});

test('a file listed and not there, or there and not listed, stops it', (t) => {
  const dir = aSet(t);
  unlinkSync(path.join(dir, 'tls-forge.rb'));
  writeFileSync(path.join(dir, 'stray.txt'), 'x');
  // A pinned gate's result joins the set later, and is no stray.
  writeFileSync(path.join(dir, 'pinned-linux-amd64.json'), '{}');
  assert.deepEqual(problems(dir, VERSION, COMMIT), ['tls-forge.rb is listed and not there', 'stray.txt is no file of the set']);
});

test('SHA256SUMS listed and not there is said once', (t) => {
  const dir = aSet(t);
  unlinkSync(path.join(dir, SUMS));
  assert.deepEqual(problems(dir, VERSION, COMMIT), [`${SUMS} is listed and not there`]);
});

test('SHA256SUMS is what the manifest makes it', (t) => {
  const dir = aSet(t);
  // Changed, and made to match the manifest again, it still says another set.
  edit(dir, SUMS, (text) => text.replace(/^[0-9a-f]{64}/, '0'.repeat(64)));
  edit(dir, MANIFEST, (text) => {
    const manifest = JSON.parse(text);
    const sumsFile = manifest.files.find((file) => file.name === SUMS);
    sumsFile.sha256 = sha256(readFileSync(path.join(dir, SUMS)));
    sumsFile.size = readFileSync(path.join(dir, SUMS)).length;
    return JSON.stringify(manifest);
  });
  assert.deepEqual(problems(dir, VERSION, COMMIT), [`${SUMS} is not what the manifest makes it`]);
});

test('a manifest that is lost, broken or of another kind stops it', (t) => {
  const dir = aSet(t);
  const files = (list) => `{"schema":1,"version":"1.2.3","commit":"${COMMIT}","files":${list}}`;
  for (const [manifest, says] of [
    ['{"schema":', /^manifest\.json is not JSON/],
    [`{"schema":2,"version":"1.2.3","commit":"${COMMIT}","files":[]}`, /^manifest\.json is of schema 2, not 1$/],
    [`{"schema":1,"version":"1.2.3","commit":"${COMMIT}"}`, /^manifest\.json lists no files$/],
    ['null', /^manifest\.json is of schema undefined, not 1$/],
    [files(`[{"name":"../LICENSE","sha256":"${'a'.repeat(64)}","size":1}]`), /lists \{"name":"\.\.\/LICENSE".*which is no file of a set$/],
    [files('[{"name":"LICENSE","sha256":"x","size":1}]'), /lists \{"name":"LICENSE".*which is no file of a set$/],
    [files(`[{"name":"LICENSE","sha256":"${'a'.repeat(64)}","size":"1"}]`), /lists \{"name":"LICENSE".*which is no file of a set$/],
    [files(`[{"name":".hidden","sha256":"${'a'.repeat(64)}","size":1}]`), /lists \{"name":"\.hidden".*which is no file of a set$/],
    [files(`[{"name":7,"sha256":"${'a'.repeat(64)}","size":1}]`), /lists \{"name":7.*which is no file of a set$/],
    [files('[null]'), /lists null, which is no file of a set$/],
  ]) {
    writeFileSync(path.join(dir, MANIFEST), manifest);
    assert.match(problems(dir, VERSION, COMMIT)[0], says, manifest);
  }
  const twice = aSet(t);
  edit(twice, MANIFEST, (text) => {
    const manifest = JSON.parse(text);
    manifest.files.push(manifest.files[0]);
    return JSON.stringify(manifest);
  });
  assert.deepEqual(problems(twice, VERSION, COMMIT), [`manifest.json lists ${required(VERSION).sort()[0]} twice`]);
  unlinkSync(path.join(dir, MANIFEST));
  assert.deepEqual(problems(dir, VERSION, COMMIT), [
    'no manifest.json: the set is lost or was never made, and a version is never built twice',
  ]);
});

test('the reference asks for a gate on every build it names', (t) => {
  assert.deepEqual(gates(aReference(t, [
    { platform: 'linux', arch: 'amd64' },
    { platform: 'linux', arch: 'arm64' },
    { platform: 'macos', arch: 'amd64' },
    { platform: 'macos', arch: 'arm64' },
    { platform: 'windows', arch: 'amd64' },
    { platform: 'windows', arch: 'arm64' },
  ])), [
    { platform: 'linux', arch: 'amd64', runner: 'ubuntu-24.04', result: 'pinned-linux-amd64.json' },
    { platform: 'linux', arch: 'arm64', runner: 'ubuntu-24.04-arm', result: 'pinned-linux-arm64.json' },
    { platform: 'macos', arch: 'amd64', runner: 'macos-15-intel', result: 'pinned-macos-amd64.json' },
    { platform: 'macos', arch: 'arm64', runner: 'macos-15', result: 'pinned-macos-arm64.json' },
    { platform: 'windows', arch: 'amd64', runner: 'windows-2025', result: 'pinned-windows-amd64.json' },
    { platform: 'windows', arch: 'arm64', runner: 'windows-11-arm', result: 'pinned-windows-arm64.json' },
  ]);
  const missing = path.join(temporary(t), 'chrome.json');
  assert.throws(() => gates(missing), new RegExp(`^Error: the reference ${missing} cannot be read, and a release is held to one: ENOENT`));
  const broken = aReference(t, []);
  writeFileSync(broken, '{"builds":');
  assert.throws(() => gates(broken), /cannot be read, and a release is held to one: .*JSON/);
  for (const builds of [[], null, {}, 'linux']) {
    assert.throws(() => gates(aReference(t, builds)), /names no builds to hold a release to$/, JSON.stringify(builds));
  }
  writeFileSync(broken, 'null');
  assert.throws(() => gates(broken), /names no builds to hold a release to$/);
  for (const [build, key] of [
    [{ platform: 'freebsd', arch: 'amd64' }, 'freebsd-amd64'],
    [{ platform: 'linux', arch: 'x64' }, 'linux-x64'],
    [{ platform: 'linux' }, 'linux-undefined'],
    [null, 'undefined-undefined'],
    [{ platform: 'constructor', arch: '' }, 'constructor-'],
  ]) {
    assert.throws(() => gates(aReference(t, [build])), new RegExp(`names a build for ${key}, which no runner is$`), key);
  }
});

test('a gate result is for this commit and this set, and passed', (t) => {
  const dir = aSet(t);
  const identity = sha256(readFileSync(path.join(dir, MANIFEST)));
  const reference = aReference(t, [{ platform: 'linux', arch: 'amd64' }, { platform: 'macos', arch: 'arm64' }]);
  const gate = (name, result) => writeFileSync(path.join(dir, name), JSON.stringify(result));
  gate('pinned-linux-amd64.json', { ok: true, commit: COMMIT, set: identity });
  // Every build of the reference needs its own.
  assert.deepEqual(problems(dir, VERSION, COMMIT, reference), [
    `the gate result pinned-macos-arm64.json cannot be read: ENOENT: no such file or directory, open '${path.join(dir, 'pinned-macos-arm64.json')}'`,
  ]);
  gate('pinned-macos-arm64.json', { ok: true, commit: COMMIT, set: identity });
  assert.deepEqual(problems(dir, VERSION, COMMIT, reference), []);
  // Without a reference, a set is not held to gates, and theirs are no strays.
  assert.deepEqual(problems(dir, VERSION, COMMIT), []);
  gate('pinned-macos-arm64.json', { ok: false, commit: 'b'.repeat(40), set: 'c'.repeat(64) });
  assert.deepEqual(problems(dir, VERSION, COMMIT, reference), [
    'the gate result pinned-macos-arm64.json did not pass',
    `the gate result pinned-macos-arm64.json is for ${'b'.repeat(40)}, not ${COMMIT}`,
    `the gate result pinned-macos-arm64.json is for the set ${'c'.repeat(64)}, not ${identity}`,
  ]);
  // Passed means true, and nothing else that might read as it.
  for (const ok of ['true', 1, null]) {
    gate('pinned-macos-arm64.json', { ok, commit: COMMIT, set: identity });
    assert.deepEqual(problems(dir, VERSION, COMMIT, reference), ['the gate result pinned-macos-arm64.json did not pass'], String(ok));
  }
  writeFileSync(path.join(dir, 'pinned-macos-arm64.json'), 'null');
  assert.deepEqual(problems(dir, VERSION, COMMIT, reference), [
    'the gate result pinned-macos-arm64.json did not pass',
    `the gate result pinned-macos-arm64.json is for undefined, not ${COMMIT}`,
    `the gate result pinned-macos-arm64.json is for the set undefined, not ${identity}`,
  ]);
  writeFileSync(path.join(dir, 'pinned-macos-arm64.json'), '{');
  assert.match(problems(dir, VERSION, COMMIT, reference)[0], /^the gate result pinned-macos-arm64\.json cannot be read: .*JSON/);
  // No reference to hold it to stops it as surely as a gate that failed.
  assert.deepEqual(problems(dir, VERSION, COMMIT, path.join(dir, 'none.json')), [
    `the reference ${path.join(dir, 'none.json')} cannot be read, and a release is held to one: ENOENT: no such file or directory, open '${path.join(dir, 'none.json')}'`,
  ]);
});

test('make refuses what is no version or commit', (t) => {
  const dir = aSet(t, { made: false });
  assert.throws(() => make(dir, 'v1.2.3', COMMIT), /--version v1\.2\.3 is not a release version/);
  assert.throws(() => make(dir, VERSION, 'abc'), /--commit abc is not a full commit/);
  assert.throws(() => make(dir, VERSION, 'A'.repeat(40)), /is not a full commit/);
  assert.throws(() => make(dir, undefined, COMMIT), /is not a release version/);
  assert.throws(() => make(dir, VERSION, undefined), /--commit undefined is not a full commit/);
});

test('make lists neither the manifest, SHA256SUMS nor a gate result as files', (t) => {
  const dir = aSet(t);
  writeFileSync(path.join(dir, 'pinned-linux-amd64.json'), '{}');
  // Made again over itself, it is the same set.
  const before = readFileSync(path.join(dir, MANIFEST), 'utf8');
  make(dir, VERSION, COMMIT);
  assert.equal(readFileSync(path.join(dir, MANIFEST), 'utf8'), before);
});

test('SHA256SUMS lists by name, whatever order the files come in', () => {
  const file = (name) => ({ name, sha256: sha256(name), size: name.length });
  assert.equal(sums([file('b'), file(SUMS), file('a')]), `${sha256('a')}  a\n${sha256('b')}  b\n`);
  assert.equal(sums([]), '');
});

test('the command says what is wrong, and exits by it', (t) => {
  const dir = aSet(t);
  assert.equal(run('verify', '--dir', dir, '--version', VERSION, '--commit', COMMIT).status, 0);
  const wrong = run('verify', '--dir', dir, '--version', VERSION, '--commit', 'b'.repeat(40));
  assert.equal(wrong.status, 1);
  assert.equal(wrong.stderr, `the set was built from ${COMMIT}, not ${'b'.repeat(40)}\n`);
  const digest = run('digest', '--dir', dir);
  assert.equal(digest.status, 0);
  assert.equal(digest.stdout, `${sha256(readFileSync(path.join(dir, MANIFEST)))}\n`);
  // A gate missing for a build of the reference stops it too.
  const reference = aReference(t, [{ platform: 'linux', arch: 'amd64' }]);
  const ungated = run('verify', '--dir', dir, '--version', VERSION, '--commit', COMMIT, '--reference', reference);
  assert.equal(ungated.status, 1);
  assert.match(ungated.stderr, /^the gate result pinned-linux-amd64\.json cannot be read/);
  const listed = run('gates', '--reference', reference);
  assert.equal(listed.status, 0);
  assert.deepEqual(JSON.parse(listed.stdout), [
    { platform: 'linux', arch: 'amd64', runner: 'ubuntu-24.04', result: 'pinned-linux-amd64.json' },
  ]);
  const unreferenced = run('gates', '--reference', path.join(dir, 'none.json'));
  assert.equal(unreferenced.status, 1);
  assert.match(unreferenced.stderr, /cannot be read, and a release is held to one/);
  const fresh = aSet(t, { made: false });
  assert.equal(run('make', '--dir', fresh, '--version', VERSION, '--commit', COMMIT).status, 0);
  assert.deepEqual(problems(fresh, VERSION, COMMIT), []);
  const refused = run('make', '--dir', fresh, '--version', 'v1', '--commit', COMMIT);
  assert.equal(refused.status, 1);
  assert.equal(refused.stderr, '--version v1 is not a release version\n');
  // What is no command, an inherited name included, and a command not told
  // what it needs, is a usage error, before anything is read or written.
  for (const args of [[], ['publish'], ['toString'], ['constructor', '--dir', dir], ['make', '--dir', fresh, '--version', VERSION],
    ['verify', '--dir'], ['digest'], ['gates']]) {
    const usage = run(...args);
    assert.equal(usage.status, 2, args.join(' '));
    assert.match(usage.stderr, /^usage: release-set\.mjs make\|verify\|digest\|gates /);
  }
});
