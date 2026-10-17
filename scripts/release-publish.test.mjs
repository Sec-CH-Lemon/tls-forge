import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { finish, github, homebrew, npm, plan, pypi, release, state } from './release-publish.mjs';
import { MANIFEST, make, required } from './release-set.mjs';

const script = fileURLToPath(new URL('./release-publish.mjs', import.meta.url));
const COMMIT = 'a'.repeat(40);
const REPO = 'owner/tls-forge';

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const sha512 = (file) => `sha512-${createHash('sha512').update(readFileSync(file)).digest('base64')}`;

const temporary = (t, prefix) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// aSet is a made set of version.
function aSet(t, version = '1.2.3') {
  const dir = temporary(t, 'tls-forge-publish-');
  for (const name of required(version).filter((name) => name !== 'SHA256SUMS')) writeFileSync(path.join(dir, name), name);
  make(dir, version, COMMIT);
  return dir;
}

const quiet = () => {};

// fakeGitHub keeps releases as GitHub would, and fails the upload after
// failAfter files when told to.
function fakeGitHub({ releases = [], failAfter = Infinity } = {}) {
  const calls = [];
  let uploaded = 0;
  const gh = (args) => {
    calls.push(args);
    if (args[0] === 'api') {
      assert.match(args.at(-1), /\| tojson$/);
      const tag = /tag_name == "([^"]+)"/.exec(args.at(-1))[1];
      return releases.filter((r) => r.tag_name === tag).map((r) => `${JSON.stringify(r)}\n`).join('');
    }
    const [, action, tag] = args;
    if (action === 'create') {
      releases.push({ tag_name: tag, draft: true, prerelease: args.includes('--prerelease'), assets: [] });
      return '';
    }
    const found = releases.find((r) => r.tag_name === tag);
    if (action === 'upload') {
      for (const file of args.slice(5)) {
        if (uploaded++ >= failAfter) throw new Error('HTTP 502: the upload failed');
        const name = path.basename(file);
        if (found.assets.some((asset) => asset.name === name)) throw new Error(`${name} exists: no --clobber`);
        found.assets.push({ name, digest: `sha256:${sha256(file)}` });
      }
      return '';
    }
    if (action === 'edit') {
      found.draft = false;
      return '';
    }
    throw new Error(`unexpected gh ${args.join(' ')}`);
  };
  return { gh, calls, releases };
}

// fakeNpm keeps packages by name@version, and fails a publish after failAfter.
function fakeNpm({ registry = new Map(), failAfter = Infinity, failView = null, packages = null } = {}) {
  const published = [];
  const npmRun = (args) => {
    if (args[0] === 'view') {
      if (failView) throw new Error(failView);
      const [name, version] = args[1].split('@');
      // npm says nothing of a version a package it has does not have, and
      // E404 of a package it does not have.
      const known = packages ?? new Set([...registry.keys()].map((key) => key.split('@')[0]));
      if (!known.has(name)) throw new Error('npm error code E404');
      if (!registry.has(args[1])) return '\n';
      return args[2] === 'version' ? `${version}\n` : `${registry.get(args[1])}\n`;
    }
    if (published.length >= failAfter) throw new Error('npm error code E503');
    const file = args[1];
    const name = path.basename(file).slice(0, -'-1.2.3.tgz'.length);
    registry.set(`${name}@1.2.3`, sha512(file));
    published.push(path.basename(file));
    assert.deepEqual(args.slice(2), ['--access', 'public', '--provenance', '--tag', 'latest']);
    return '';
  };
  return { npmRun, published, registry };
}

test('a plan publishes what is missing, passes what is there, and stops at what differs', () => {
  const local = new Map([['a', '1'], ['b', '2'], ['c', '3']]);
  assert.deepEqual(plan(local, new Map([['a', '1']])), { upload: ['b', 'c'], skip: ['a'] });
  assert.deepEqual(plan(local, new Map()), { upload: ['a', 'b', 'c'], skip: [] });
  assert.throws(() => plan(local, new Map([['a', '9'], ['b', null]])),
    /not the set; nothing more is published:\na is published as 9, and the set has 1\nb is published as something with no digest, and the set has 2/);
  assert.throws(() => plan(local, new Map([['stray', '0']])), /stray is published and is no file of the set/);
  assert.deepEqual(plan(local, new Map([['stray', '0']]), { extra: (name) => name === 'stray' }).upload, ['a', 'b', 'c']);
});

test('a release is a draft that holds the set, made once and completed after', (t) => {
  const dir = aSet(t);
  const files = readdirSync(dir);
  // The upload fails part of the way through, and the release is run again.
  const first = fakeGitHub({ failAfter: 5 });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: first.gh, log: quiet }), /HTTP 502/);
  assert.equal(first.releases[0].draft, true);
  assert.equal(first.releases[0].prerelease, false);
  assert.equal(first.releases[0].assets.length, 5);
  // The manifest goes last, so a draft without it is one not finished.
  assert.ok(first.releases[0].assets.every((asset) => asset.name !== MANIFEST));
  const again = fakeGitHub({ releases: first.releases });
  const lines = [];
  const uploaded = github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: again.gh, log: (line) => lines.push(line) });
  assert.equal(uploaded.length, files.length - 5);
  assert.deepEqual(lines, [`v1.2.3: uploaded ${files.length - 5}, had 5`]);
  assert.deepEqual(first.releases[0].assets.map((asset) => asset.name).sort(), files.sort());
  assert.equal(first.releases[0].assets.at(-1).name, MANIFEST);
  const uploads = again.calls.filter((call) => call[1] === 'upload');
  assert.deepEqual(uploads.at(-1), ['release', 'upload', 'v1.2.3', '--repo', REPO, path.join(dir, MANIFEST)]);
  assert.ok(uploads[0].every((arg) => !arg.endsWith(MANIFEST)));
  // Nothing was made twice, and nothing written over.
  assert.equal(again.calls.filter((call) => call[1] === 'create').length, 0);
  assert.ok(again.calls.every((call) => !call.includes('--clobber')));
  // Once whole, another attempt has nothing to do and uploads nothing.
  const done = fakeGitHub({ releases: first.releases });
  assert.deepEqual(github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: done.gh, log: quiet }), []);
  assert.equal(done.calls.filter((call) => call[0] !== 'api').length, 0);
});

test('a draft that has all but the manifest gets only the manifest', (t) => {
  const dir = aSet(t);
  const first = fakeGitHub({ failAfter: readdirSync(dir).length - 1 });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: first.gh, log: quiet }), /HTTP 502/);
  const again = fakeGitHub({ releases: first.releases });
  assert.deepEqual(github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: again.gh, log: quiet }), [MANIFEST]);
  assert.deepEqual(again.calls.filter((call) => call[1] === 'upload'), [
    ['release', 'upload', 'v1.2.3', '--repo', REPO, path.join(dir, MANIFEST)],
  ]);
});

test('a release holding another file of the same name stops before anything is uploaded', (t) => {
  const dir = aSet(t);
  const other = fakeGitHub({
    releases: [{ tag_name: 'v1.2.3', draft: true, assets: [{ name: 'NOTICE', digest: `sha256:${'0'.repeat(64)}` }] }],
  });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: other.gh, log: quiet }),
    /NOTICE is published as sha256:0{64}, and the set has sha256:[0-9a-f]{64}/);
  assert.equal(other.calls.filter((call) => call[1] === 'upload').length, 0);
  // A file that is not the set's stops it too, but a pinned gate's result is
  // the release's, beside the set.
  const stray = fakeGitHub({ releases: [{ tag_name: 'v1.2.3', draft: true, assets: [{ name: 'notes.txt', digest: 'sha256:x' }] }] });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: stray.gh, log: quiet }), /notes\.txt is published and is no file of the set/);
  // An asset with no digest to compare is not taken for the set's.
  const old = fakeGitHub({ releases: [{ tag_name: 'v1.2.3', draft: false, assets: [{ name: 'LICENSE' }] }] });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: old.gh, log: quiet }),
    /LICENSE is published as something with no digest/);
  const gated = fakeGitHub({ releases: [{ tag_name: 'v1.2.3', draft: true, assets: [{ name: 'pinned-linux-amd64.json', digest: 'sha256:x' }] }] });
  assert.equal(github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: gated.gh, log: quiet }).length, readdirSync(dir).length);
});

test('a dry run asks what is there and changes nothing', (t) => {
  const dir = aSet(t);
  const fake = fakeGitHub();
  const lines = [];
  const would = github({ dir, tag: 'v1.2.3', repo: REPO, dryRun: true }, { gh: fake.gh, log: (line) => lines.push(line) });
  assert.equal(would.length, readdirSync(dir).length);
  assert.deepEqual(lines, [`v1.2.3: would upload ${readdirSync(dir).length}, has 0`]);
  assert.deepEqual(fake.releases, []);
  assert.ok(fake.calls.every((call) => call[0] === 'api'));
  // And it stops where a release would, at what is not the set.
  const other = fakeGitHub({ releases: [{ tag_name: 'v1.2.3', draft: true, assets: [{ name: 'NOTICE', digest: 'sha256:0' }] }] });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO, dryRun: true }, { gh: other.gh, log: quiet }), /NOTICE is published as sha256:0/);
});

test('a pre-release is a pre-release, and a tag is a tag', (t) => {
  const dir = aSet(t, '1.2.3-rc.1');
  const fake = fakeGitHub();
  github({ dir, tag: 'v1.2.3-rc.1', repo: REPO }, { gh: fake.gh, log: quiet });
  assert.equal(fake.releases[0].prerelease, true);
  assert.deepEqual(fake.calls[1], ['release', 'create', 'v1.2.3-rc.1', '--repo', REPO, '--draft', '--verify-tag',
    '--title', 'v1.2.3-rc.1', '--generate-notes', '--prerelease']);
  assert.throws(() => release(fake.gh, REPO, '1.2.3'), /--tag 1\.2\.3 is not a release tag/);
  assert.throws(() => release(fake.gh, REPO, 'v1.2.3"; drop'), /is not a release tag/);
  assert.throws(() => release(fake.gh, REPO, undefined), /--tag undefined is not a release tag/);
  assert.equal(release(fake.gh, REPO, 'v9.9.9'), null);
  // Two of one tag cannot be, and the first is the one taken.
  const twice = fakeGitHub({ releases: [{ tag_name: 'v1.2.3', draft: true, assets: [], id: 1 }, { tag_name: 'v1.2.3', draft: true, assets: [], id: 2 }] });
  assert.equal(release(twice.gh, REPO, 'v1.2.3').id, 1);
});

test('a draft is published once, and a lost one stops the release', () => {
  const fake = fakeGitHub({ releases: [{ tag_name: 'v1.2.3', draft: true, assets: [] }] });
  const lines = [];
  assert.equal(finish({ tag: 'v1.2.3', repo: REPO }, { gh: fake.gh, log: (line) => lines.push(line) }), true);
  assert.equal(fake.releases[0].draft, false);
  assert.deepEqual(fake.calls.at(-1), ['release', 'edit', 'v1.2.3', '--repo', REPO, '--draft=false']);
  assert.equal(finish({ tag: 'v1.2.3', repo: REPO }, { gh: fake.gh, log: (line) => lines.push(line) }), false);
  assert.deepEqual(lines, ['v1.2.3: published', 'v1.2.3: published already']);
  assert.throws(() => finish({ tag: 'v9.9.9', repo: REPO }, { gh: fake.gh, log: quiet }), /no release of v9\.9\.9: its set is lost/);
});

test('a release stands where its draft and the registries say', async (t) => {
  const dir = aSet(t);
  const nowhere = { npmRun: fakeNpm().npmRun, fetchJSON: async () => null };
  const asked = [];
  const ask = async (url) => {
    asked.push(url);
    return null;
  };
  // No release, and no registry has the version: none, and it may be built.
  assert.equal(await state({ tag: 'v1.2.3-rc.1', repo: REPO }, { gh: fakeGitHub().gh, ...nowhere, fetchJSON: ask }), 'none');
  assert.deepEqual(asked, ['https://pypi.org/pypi/tls-forge/1.2.3rc1/json']);
  // A draft with the manifest holds the set; one without it was not finished.
  const first = fakeGitHub({ failAfter: 3 });
  assert.throws(() => github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: first.gh, log: quiet }), /HTTP 502/);
  assert.equal(await state({ tag: 'v1.2.3', repo: REPO }, { gh: first.gh, ...nowhere }), 'unfinished');
  github({ dir, tag: 'v1.2.3', repo: REPO }, { gh: fakeGitHub({ releases: first.releases }).gh, log: quiet });
  assert.equal(await state({ tag: 'v1.2.3', repo: REPO }, { gh: first.gh, ...nowhere }), 'stored');
  finish({ tag: 'v1.2.3', repo: REPO }, { gh: first.gh, log: quiet });
  assert.equal(await state({ tag: 'v1.2.3', repo: REPO }, { gh: first.gh, ...nowhere }), 'published');
  // No release, and a registry with the version: the set is lost, whichever
  // package or index has it.
  for (const registry of [
    new Map([['tls-forge-darwin-arm64@1.2.3', 'sha512-x']]),
    new Map([['tls-forge@1.2.3', 'sha512-x']]),
    new Map([['tls-forge-windows-x64@1.2.3', 'sha512-x']]),
  ]) {
    assert.equal(await state({ tag: 'v1.2.3', repo: REPO }, { gh: fakeGitHub().gh, npmRun: fakeNpm({ registry }).npmRun, fetchJSON: async () => null }),
      'lost', [...registry.keys()][0]);
  }
  assert.equal(await state({ tag: 'v1.2.3', repo: REPO }, { gh: fakeGitHub().gh, npmRun: fakeNpm().npmRun, fetchJSON: async () => ({ urls: [] }) }), 'lost');
  // A package npm has without this version is not this version.
  const older = fakeNpm({ registry: new Map([['tls-forge@1.2.2', 'sha512-x']]), packages: new Set(['tls-forge']) });
  assert.equal(await state({ tag: 'v1.2.3', repo: REPO }, { gh: fakeGitHub().gh, npmRun: older.npmRun, fetchJSON: async () => null }), 'none');
  // What npm or the index cannot answer is not taken for nothing published.
  await assert.rejects(state({ tag: 'v1.2.3', repo: REPO }, { gh: fakeGitHub().gh, npmRun: fakeNpm({ failView: 'npm error code ETIMEDOUT' }).npmRun, fetchJSON: async () => null }),
    /ETIMEDOUT/);
  await assert.rejects(state({ tag: 'v1.2.3', repo: REPO }, { gh: fakeGitHub().gh, ...nowhere, fetchJSON: async () => { throw new Error('HTTP 503'); } }),
    /HTTP 503/);
  await assert.rejects(state({ tag: 'latest', repo: REPO }, { gh: fakeGitHub().gh, ...nowhere }), /--tag latest is not a release tag/);
  await assert.rejects(state({ tag: 'v1.2', repo: REPO }, { gh: fakeGitHub().gh, ...nowhere }), /--version 1\.2 is not a release version/);
});

test('npm gets the platform packages first and the one that pins them last', (t) => {
  const dir = aSet(t);
  const fake = fakeNpm();
  const lines = [];
  npm({ dir, version: '1.2.3', tag: 'latest' }, { npmRun: fake.npmRun, log: (line) => lines.push(line) });
  assert.deepEqual(fake.published, [
    'tls-forge-darwin-arm64-1.2.3.tgz', 'tls-forge-darwin-x64-1.2.3.tgz', 'tls-forge-linux-arm64-1.2.3.tgz',
    'tls-forge-linux-x64-1.2.3.tgz', 'tls-forge-windows-x64-1.2.3.tgz', 'tls-forge-1.2.3.tgz',
  ]);
  assert.deepEqual(lines, ['npm: published 6 of 6']);
});

test('npm run again publishes what the last attempt did not, and nothing twice', (t) => {
  const dir = aSet(t);
  const first = fakeNpm({ failAfter: 2 });
  assert.throws(() => npm({ dir, version: '1.2.3', tag: 'latest' }, { npmRun: first.npmRun, log: quiet }), /E503/);
  const again = fakeNpm({ registry: first.registry });
  const published = npm({ dir, version: '1.2.3', tag: 'latest' }, { npmRun: again.npmRun, log: quiet });
  assert.equal(published.length, 4);
  assert.deepEqual([...first.published, ...again.published].sort(), readdirSync(dir).filter((n) => n.endsWith('-1.2.3.tgz')).sort());
});

test('npm stops at a package published as something else, before the one that pins it', (t) => {
  const dir = aSet(t);
  const fake = fakeNpm({ registry: new Map([['tls-forge-darwin-arm64@1.2.3', 'sha512-other']]) });
  assert.throws(() => npm({ dir, version: '1.2.3', tag: 'latest' }, { npmRun: fake.npmRun, log: quiet }),
    /tls-forge-darwin-arm64-1\.2\.3\.tgz is published as sha512-other/);
  assert.equal(fake.published.length, 0);
  // What npm cannot answer is not taken for nothing published.
  const broken = fakeNpm({ failView: 'npm error code ECONNRESET' });
  assert.throws(() => npm({ dir, version: '1.2.3', tag: 'latest' }, { npmRun: broken.npmRun, log: quiet }), /ECONNRESET/);
  // A dry run says what it would publish, and publishes nothing.
  const dry = fakeNpm({ registry: new Map([['tls-forge-darwin-arm64@1.2.3', sha512(path.join(dir, 'tls-forge-darwin-arm64-1.2.3.tgz'))]]) });
  const lines = [];
  assert.equal(npm({ dir, version: '1.2.3', tag: 'latest', dryRun: true }, { npmRun: dry.npmRun, log: (line) => lines.push(line) }).length, 5);
  assert.deepEqual(dry.published, []);
  assert.deepEqual(lines, ['npm: would publish 5 of 6']);
});

test('PyPI is given what it lacks, by the version it spells', async (t) => {
  const dir = aSet(t, '1.2.3-rc.1');
  const out = path.join(temporary(t, 'tls-forge-upload-'), 'upload');
  const distributions = readdirSync(dir).filter((name) => name.startsWith('tls_forge-')).sort();
  assert.equal(distributions.length, 6);
  assert.ok(distributions.includes('tls_forge-1.2.3rc1.tar.gz'));
  const asked = [];
  const pypiHas = (files) => async (url) => {
    asked.push(url);
    return files === null ? null : { urls: files.map((name) => ({ filename: name, digests: { sha256: sha256(path.join(dir, name)) } })) };
  };
  const lines = [];
  assert.deepEqual((await pypi({ dir, version: '1.2.3-rc.1', out }, { fetchJSON: pypiHas(null), log: (line) => lines.push(line) })).sort(), distributions);
  assert.equal(asked[0], 'https://pypi.org/pypi/tls-forge/1.2.3rc1/json');
  assert.deepEqual(lines, ['pypi: 6 to upload of 6']);
  assert.deepEqual(readdirSync(out).sort(), distributions);
  rmSync(out, { recursive: true, force: true });
  const rest = await pypi({ dir, version: '1.2.3-rc.1', out }, { fetchJSON: pypiHas(distributions.slice(0, 2)), log: quiet });
  assert.deepEqual(rest.sort(), distributions.slice(2));
  assert.deepEqual(readdirSync(out).sort(), distributions.slice(2));
  // Another index, as a test stands one in.
  await pypi({ dir, version: '1.2.3-rc.1', out, dryRun: true }, { fetchJSON: pypiHas(null), log: quiet, pypiURL: 'http://127.0.0.1:1' });
  assert.equal(asked.at(-1), 'http://127.0.0.1:1/pypi/tls-forge/1.2.3rc1/json');
  await assert.rejects(pypi({ dir, version: '1.2.3-rc.1', out }, {
    fetchJSON: async () => ({ urls: [{ filename: distributions[0], digests: { sha256: '0'.repeat(64) } }] }), log: quiet,
  }), /is published as 0{64}/);
  await assert.rejects(pypi({ dir, version: '1.2.3-rc.1', out }, {
    fetchJSON: async () => ({ urls: [{ filename: distributions[0] }] }), log: quiet,
  }), /is published as something with no digest/);
  // A release PyPI has that lists no files has none to compare.
  rmSync(out, { recursive: true, force: true });
  assert.equal((await pypi({ dir, version: '1.2.3-rc.1', out }, { fetchJSON: async () => ({}), log: quiet })).length, 6);
  // A set of another version has nothing to give.
  await assert.rejects(pypi({ dir, version: '1.2.3', out }, { fetchJSON: pypiHas(null), log: quiet }),
    /the set has no Python distributions of 1\.2\.3$/);
  await assert.rejects(pypi({ dir, version: 'v1', out }, { fetchJSON: pypiHas(null), log: quiet }), /--version v1 is not a release version/);
});

test('a dry run for PyPI copies nothing', async (t) => {
  const dir = aSet(t);
  const out = path.join(temporary(t, 'tls-forge-upload-'), 'upload');
  const lines = [];
  assert.equal((await pypi({ dir, version: '1.2.3', out, dryRun: true }, { fetchJSON: async () => null, log: (line) => lines.push(line) })).length, 6);
  assert.ok(!existsSync(out));
  assert.deepEqual(lines, ['pypi: 6 would be uploaded of 6']);
});

test('the tap gets a formula unless it has this one or a later one, and never over another of its version', () => {
  const of = (version, sum = '1') => `url "https://github.com/o/r/releases/download/v${version}/a.tar.gz"\nsha256 "${sum}"\n`;
  const files = {
    ours: of('1.2.3'),
    same: of('1.2.3'),
    older: of('1.2.2', '0'),
    clash: of('1.2.3', '9'),
    odd: 'class TlsForge < Formula\nend\n',
    odder: 'class TlsForge < Formula\n  desc "x"\nend\n',
    patch: of('1.2.4'),
    minor: of('1.3.0'),
    major: of('2.0.0'),
    // By number, not by letter: 1.10.0 is after 1.9.9.
    ten: of('1.10.0'),
    nine: of('1.9.9'),
    lowerMinor: of('1.1.9'),
    lowerMajor: of('0.9.9'),
    next: of('1.3.0-rc.1'),
    padded: of('1.03.0'),
  };
  const read = (name) => {
    if (!Object.hasOwn(files, name)) throw new Error('ENOENT');
    return files[name];
  };
  assert.equal(homebrew({ formula: 'ours', tap: 'none' }, { read }), 'write');
  assert.equal(homebrew({ formula: 'ours', tap: 'same' }, { read }), 'unchanged');
  for (const tap of ['older', 'lowerMinor', 'lowerMajor']) assert.equal(homebrew({ formula: 'ours', tap }, { read }), 'write', tap);
  // A release retried after a later one leaves the later one where it is.
  for (const tap of ['patch', 'minor', 'major']) assert.equal(homebrew({ formula: 'ours', tap }, { read }), 'newer', tap);
  assert.equal(homebrew({ formula: 'nine', tap: 'ten' }, { read }), 'newer');
  assert.equal(homebrew({ formula: 'ten', tap: 'nine' }, { read }), 'write');
  // A formula of no version, or of a pre-release, is not held against ours.
  assert.equal(homebrew({ formula: 'ours', tap: 'odd' }, { read }), 'write');
  assert.equal(homebrew({ formula: 'odd', tap: 'older' }, { read }), 'write');
  assert.equal(homebrew({ formula: 'ours', tap: 'next' }, { read }), 'write');
  assert.equal(homebrew({ formula: 'ours', tap: 'padded' }, { read }), 'write');
  // Two of no version are not two of one version.
  assert.equal(homebrew({ formula: 'odder', tap: 'odd' }, { read }), 'write');
  assert.throws(() => homebrew({ formula: 'ours', tap: 'clash' }, { read }), /the tap has another formula of 1\.2\.3/);
});

// runScript runs the command with env laid over this process's, and is what
// it printed and how it exited.
const runScript = (args, env = {}) => new Promise((resolve) => {
  const child = spawn(process.execPath, [script, ...args], { env: { ...process.env, ...env } });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('close', (status) => resolve({ status, stdout, stderr }));
});

test('the command asks gh, npm and the index, and says what it did', { skip: process.platform === 'win32' }, async (t) => {
  const dir = aSet(t);
  const bin = temporary(t, 'tls-forge-bin-');
  // A gh that has no release of the tag, makes one, and takes every upload,
  // and an npm that has no package: each writes down how it was called.
  writeFileSync(path.join(bin, 'gh'), '#!/bin/sh\necho "$@" >> "$(dirname "$0")/gh-calls"\nexit 0\n', { mode: 0o755 });
  writeFileSync(path.join(bin, 'npm'), '#!/bin/sh\necho "$@" >> "$(dirname "$0")/npm-calls"\necho "npm error code E404" >&2\nexit 1\n', { mode: 0o755 });
  const env = { PATH: `${bin}${path.delimiter}${process.env.PATH}` };
  const made = await runScript(['github', '--dir', dir, '--tag', 'v1.2.3', '--repo', REPO], env);
  assert.equal(made.status, 0, made.stderr);
  assert.equal(made.stdout, 'v1.2.3: uploaded 23, had 0\n');
  const calls = readFileSync(path.join(bin, 'gh-calls'), 'utf8').split('\n');
  assert.equal(calls[0], 'api --paginate repos/owner/tls-forge/releases?per_page=100 --jq .[] | select(.tag_name == "v1.2.3") | tojson');
  assert.equal(calls[1], 'release create v1.2.3 --repo owner/tls-forge --draft --verify-tag --title v1.2.3 --generate-notes');
  assert.equal(calls[3], `release upload v1.2.3 --repo owner/tls-forge ${path.join(dir, MANIFEST)}`);
  const dry = await runScript(['github', '--dry-run', '--dir', dir, '--tag', 'v1.2.4', '--repo', REPO], env);
  assert.equal(dry.stdout, 'v1.2.4: would upload 23, has 0\n');
  // An index that has not heard of the version, one that has, and one that fails.
  const server = createServer((request, response) => {
    if (request.url.includes('/9.9.9/')) {
      response.writeHead(500).end();
    } else if (request.url.includes('/1.2.3/')) {
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"urls":[]}');
    } else {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const index = { ...env, RELEASE_PYPI_URL: `http://127.0.0.1:${server.address().port}` };
  const out = path.join(bin, 'out');
  const listed = await runScript(['pypi', '--dir', dir, '--version', '1.2.3', '--out', out], index);
  assert.equal(listed.status, 0, listed.stderr);
  assert.equal(listed.stdout, 'pypi: 6 to upload of 6\n');
  // gh has no release of v1.2.4, npm no package and the index no version.
  const none = await runScript(['state', '--tag', 'v1.2.4', '--repo', REPO], index);
  assert.equal(none.status, 0, none.stderr);
  assert.equal(none.stdout, 'none\n');
  assert.match(readFileSync(path.join(bin, 'npm-calls'), 'utf8'), /^view tls-forge@1\.2\.4 version$/m);
  const lost = await runScript(['state', '--tag', 'v1.2.3', '--repo', REPO], index);
  assert.equal(lost.stdout, 'lost\n');
  const npmDry = await runScript(['npm', '--dry-run', '--dir', dir, '--version', '1.2.3', '--tag', 'latest'], env);
  assert.equal(npmDry.status, 0, npmDry.stderr);
  assert.equal(npmDry.stdout, 'npm: would publish 6 of 6\n');
  const failed = await runScript(['state', '--tag', 'v9.9.9', '--repo', REPO], index);
  assert.equal(failed.status, 1);
  assert.match(failed.stderr, /\/pypi\/tls-forge\/9\.9\.9\/json: HTTP 500/);
});

test('the command says what it did, or why it did not', async (t) => {
  const dir = temporary(t, 'tls-forge-tap-');
  const formula = path.join(dir, 'tls-forge.rb');
  writeFileSync(formula, 'url "x/releases/download/v1.2.3/a"');
  const later = path.join(dir, 'later.rb');
  writeFileSync(later, 'url "x/releases/download/v1.2.4/a"');
  assert.equal((await runScript(['homebrew', '--formula', formula, '--tap', path.join(dir, 'none.rb')])).stdout, 'write\n');
  assert.equal((await runScript(['homebrew', '--formula', formula, '--tap', formula])).stdout, 'unchanged\n');
  assert.equal((await runScript(['homebrew', '--formula', formula, '--tap', later])).stdout, 'newer\n');
  // What is no command, an inherited name included, is refused by name.
  for (const command of ['publish', 'toString', 'constructor', undefined]) {
    const usage = await runScript(command === undefined ? [] : [command]);
    assert.equal(usage.status, 1, String(command));
    assert.equal(usage.stderr, 'usage: release-publish.mjs github|finish|npm|pypi|homebrew|state ...\n');
  }
  assert.ok(!existsSync(path.join(dir, 'out')));
});
