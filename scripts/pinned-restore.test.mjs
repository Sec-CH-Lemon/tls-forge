import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildOf, installing, restore, run } from './pinned-restore.mjs';

const script = fileURLToPath(new URL('./pinned-restore.mjs', import.meta.url));
const sha256 = (data) => createHash('sha256').update(data).digest('hex');

const temporary = (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-restore-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// aReference is a reference manifest of builds, written in dir.
function aReference(dir, builds) {
  const file = path.join(dir, 'chrome.json');
  writeFileSync(file, JSON.stringify({ schema: 1, version: '155.0.8059.80', profile: 'chrome_155', builds }));
  return file;
}

const INSTALLER = Buffer.from('the installer of Google Chrome 155.0.8059.80');
const build = (platform, arch, installer, data = INSTALLER) => ({
  platform, arch, installer, installer_sha256: sha256(data), binary: 'opt/google/chrome/chrome', binary_sha256: '0'.repeat(64),
});

// anArchive answers fetch as an archive holding files would, noting what it
// was asked and with which headers.
function anArchive(files) {
  const asked = [];
  const fetch = async (url, { headers }) => {
    asked.push({ url, headers });
    const name = decodeURIComponent(url.slice(url.lastIndexOf('/') + 1));
    if (!Object.hasOwn(files, name)) return new Response('no such file', { status: 404 });
    return new Response(files[name]);
  };
  return { fetch, asked };
}

const ENV = { PINNED_ARCHIVE_URL: 'https://archive.example/chrome/' };

test('the reference names one build for this runner, by a bare name and a whole digest', (t) => {
  const dir = temporary(t);
  const reference = aReference(dir, [build('linux', 'amd64', 'chrome.deb'), build('macos', 'arm64', 'chrome.dmg')]);
  assert.equal(buildOf(reference, 'macos', 'arm64').installer, 'chrome.dmg');
  assert.equal(buildOf(reference, 'linux', 'amd64').installer, 'chrome.deb');
  assert.throws(() => buildOf(reference, 'linux', 'arm64'), { message: `the reference ${reference} has no build for linux/arm64` });
  assert.throws(() => buildOf(path.join(dir, 'none.json'), 'linux', 'amd64'), /^Error: the reference .*none\.json cannot be read: ENOENT/);
  writeFileSync(reference, '{"builds":');
  assert.throws(() => buildOf(reference, 'linux', 'amd64'), /cannot be read: .*JSON/);
  for (const builds of [null, {}, [null]]) {
    writeFileSync(reference, JSON.stringify({ builds }));
    assert.throws(() => buildOf(reference, 'linux', 'amd64'), /has no build for linux\/amd64$/, JSON.stringify(builds));
  }
  for (const installer of ['', '../chrome.deb', 'dir/chrome.deb', 'dir\\chrome.deb', '.', '..', 7, undefined]) {
    aReference(dir, [{ ...build('linux', 'amd64', 'x'), installer }]);
    assert.throws(() => buildOf(reference, 'linux', 'amd64'), { message: `the reference's installer ${JSON.stringify(installer)} is not a file name` },
      String(installer));
  }
  for (const digest of ['0'.repeat(63), 'A'.repeat(64), `${'0'.repeat(64)}\n`, undefined]) {
    aReference(dir, [{ ...build('linux', 'amd64', 'chrome.deb'), installer_sha256: digest }]);
    assert.throws(() => buildOf(reference, 'linux', 'amd64'),
      { message: `the reference's installer_sha256 ${JSON.stringify(digest)} is not a SHA-256 in lower-case hex` }, String(digest));
  }
});

test('each kind of installer is unpacked, never installed for the machine', () => {
  assert.deepEqual(installing('/a/c.deb', '/i', 'linux', '/s'), { steps: [['dpkg-deb', ['-x', '/a/c.deb', '/i']]], after: [] });
  assert.deepEqual(installing('/a/c.dmg', '/i', 'macos', '/s'), {
    steps: [['hdiutil', ['attach', '-nobrowse', '-readonly', '-noautoopen', '-mountpoint', path.join('/s', 'mount'), '/a/c.dmg']],
      ['ditto', [path.join('/s', 'mount'), '/i']]],
    after: [['hdiutil', ['detach', path.join('/s', 'mount')]]],
  });
  assert.deepEqual(installing('C:\\a\\c.msi', 'C:\\i', 'windows', 'C:\\s'),
    { steps: [['msiexec', ['/a', 'C:\\a\\c.msi', '/qn', '/norestart', 'TARGETDIR=C:\\i']]], after: [] });
  assert.deepEqual(installing('/a/c.zip', '/i', 'linux', '/s').steps, [['unzip', ['-q', '/a/c.zip', '-d', '/i']]]);
  assert.deepEqual(installing('/a/c.zip', '/i', 'macos', '/s').steps, [['tar', ['-xf', '/a/c.zip', '-C', '/i']]]);
  assert.deepEqual(installing('/a/c.zip', '/i', 'windows', '/s').steps, [['tar', ['-xf', '/a/c.zip', '-C', '/i']]]);
  for (const name of ['c.tar', 'c.tar.gz', 'c.tgz', 'c.tar.xz', 'c.tar.bz2']) {
    assert.deepEqual(installing(`/a/${name}`, '/i', 'linux', '/s'), { steps: [['tar', ['-xf', `/a/${name}`, '-C', '/i']]], after: [] }, name);
  }
  for (const name of ['c.exe', 'c.pkg', 'c.gz', 'c.tar.zst', 'deb', 'c.deb.part']) {
    assert.throws(() => installing(`/a/${name}`, '/i', 'linux', '/s'),
      { message: `${name} is no installer this knows how to unpack: a .deb, .dmg, .msi, .zip or tar archive` }, name);
  }
});

test('the installer is fetched, held to its digest, kept and unpacked', async (t) => {
  const dir = temporary(t);
  const reference = aReference(dir, [build('linux', 'amd64', 'google chrome+155.deb')]);
  const archive = anArchive({ 'google chrome+155.deb': INSTALLER });
  const ran = [];
  const lines = [];
  const kept = await restore({ reference, platform: 'linux', arch: 'amd64', archive: path.join(dir, 'archive'), installed: path.join(dir, 'installed') },
    { fetch: archive.fetch, exec: (command, args) => ran.push([command, ...args]), env: ENV, log: (line) => lines.push(line) });
  assert.equal(kept, path.join(dir, 'archive', 'google chrome+155.deb'));
  assert.deepEqual(readFileSync(kept), INSTALLER);
  // Asked for by its name, escaped, under the archive's address, and with no
  // token when none is set.
  assert.deepEqual(archive.asked, [{ url: 'https://archive.example/chrome/google%20chrome%2B155.deb', headers: {} }]);
  assert.deepEqual(ran, [['dpkg-deb', '-x', kept, path.join(dir, 'installed')]]);
  assert.ok(existsSync(path.join(dir, 'installed')));
  assert.deepEqual(lines, [`google chrome+155.deb restored and installed in ${path.join(dir, 'installed')}`]);
  // A token is sent as a bearer token, and an address without a slash works.
  const again = anArchive({ 'google chrome+155.deb': INSTALLER });
  await restore({ reference, platform: 'linux', arch: 'amd64', archive: path.join(dir, 'a2'), installed: path.join(dir, 'i2') },
    { fetch: again.fetch, exec: () => {}, env: { PINNED_ARCHIVE_URL: 'https://archive.example', PINNED_ARCHIVE_TOKEN: 's3cret' } });
  assert.deepEqual(again.asked, [{ url: 'https://archive.example/google%20chrome%2B155.deb', headers: { authorization: 'Bearer s3cret' } }]);
});

test('an archive that is not there, or not the reference, installs nothing and says nothing secret', async (t) => {
  const dir = temporary(t);
  const reference = aReference(dir, [build('linux', 'amd64', 'chrome.deb'), build('linux', 'arm64', 'chrome.pkg')]);
  const where = { reference, platform: 'linux', arch: 'amd64', archive: path.join(dir, 'archive'), installed: path.join(dir, 'installed') };
  const ran = [];
  const exec = (command, args) => ran.push([command, ...args]);
  for (const env of [{}, { PINNED_ARCHIVE_URL: '' }]) {
    await assert.rejects(restore(where, { fetch: anArchive({}).fetch, exec, env }),
      { message: 'PINNED_ARCHIVE_URL is not set: there is no archive to restore the reference from, and a release is held to it' });
  }
  const secret = { PINNED_ARCHIVE_URL: 'https://user:pass@archive.example/x', PINNED_ARCHIVE_TOKEN: 's3cret' };
  await assert.rejects(restore(where, { fetch: anArchive({}).fetch, exec, env: secret }),
    { message: 'the archive answered HTTP 404 for chrome.deb' });
  const other = Buffer.from('another installer');
  await assert.rejects(restore(where, { fetch: anArchive({ 'chrome.deb': other }).fetch, exec, env: secret }),
    { message: `chrome.deb from the archive hashes to ${sha256(other)}, not ${sha256(INSTALLER)}: it is not the reference's` });
  // An installer this cannot unpack is not even fetched.
  const unasked = anArchive({ 'chrome.pkg': INSTALLER });
  await assert.rejects(restore({ ...where, arch: 'arm64' }, { fetch: unasked.fetch, exec, env: ENV }), /chrome\.pkg is no installer/);
  assert.deepEqual(unasked.asked, []);
  // A network that fails is a failure.
  await assert.rejects(restore(where, { fetch: async () => { throw new Error('ECONNRESET'); }, exec, env: ENV }), /ECONNRESET/);
  assert.deepEqual(ran, []);
  assert.ok(!existsSync(path.join(dir, 'archive')));
  assert.ok(!existsSync(path.join(dir, 'installed')));
});

test('a mounted image is detached whatever happened, and the first failure is the one said', async (t) => {
  const dir = temporary(t);
  const reference = aReference(dir, [build('macos', 'arm64', 'chrome.dmg')]);
  const where = { reference, platform: 'macos', arch: 'arm64', archive: path.join(dir, 'archive'), installed: path.join(dir, 'installed') };
  const attempt = async (fails) => {
    const ran = [];
    let mount = null;
    const exec = (command, args) => {
      const step = command === 'hdiutil' ? `hdiutil ${args[0]}` : command;
      ran.push(step);
      if (step === 'hdiutil attach') mount = args[args.indexOf('-mountpoint') + 1];
      if (fails.includes(step)) throw new Error(`${step} failed: exit 1`);
    };
    let said = null;
    await restore(where, { fetch: anArchive({ 'chrome.dmg': INSTALLER }).fetch, exec, env: ENV }).catch((err) => { said = err.message; });
    // Where it mounted the image is gone, however it went.
    assert.ok(!existsSync(path.dirname(mount)), fails.join(' '));
    return { ran, said };
  };
  assert.deepEqual(await attempt([]), { ran: ['hdiutil attach', 'ditto', 'hdiutil detach'], said: null });
  assert.deepEqual(await attempt(['ditto']), { ran: ['hdiutil attach', 'ditto', 'hdiutil detach'], said: 'ditto failed: exit 1' });
  assert.deepEqual(await attempt(['hdiutil attach', 'hdiutil detach']),
    { ran: ['hdiutil attach', 'hdiutil detach'], said: 'hdiutil attach failed: exit 1' });
  assert.deepEqual(await attempt(['hdiutil detach']), { ran: ['hdiutil attach', 'ditto', 'hdiutil detach'], said: 'hdiutil detach failed: exit 1' });
});

test('a command runs with its output passed through, and fails out loud', () => {
  run(process.execPath, ['-e', '']);
  assert.throws(() => run(process.execPath, ['-e', 'process.exit(5)']), { message: `${process.execPath} failed: exit 5` });
  assert.throws(() => run(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM")']), { message: `${process.execPath} failed: SIGTERM` });
  assert.throws(() => run(path.join(os.tmpdir(), 'no-such-tool-for-restore'), []), /ENOENT/);
});

test('the command restores a reference from an archive over HTTP', { skip: process.platform === 'win32' }, async (t) => {
  const dir = temporary(t);
  // A browser as an archive of its installed tree, which tar unpacks.
  const tree = path.join(dir, 'tree');
  mkdirSync(path.join(tree, 'opt', 'google', 'chrome'), { recursive: true });
  writeFileSync(path.join(tree, 'opt', 'google', 'chrome', 'chrome'), 'chrome');
  const tarball = path.join(dir, 'chrome.tar.gz');
  spawnSync('tar', ['-czf', tarball, '-C', tree, '.'], { env: { ...process.env, COPYFILE_DISABLE: '1' } });
  const data = readFileSync(tarball);
  const reference = aReference(dir, [build('linux', 'amd64', 'chrome.tar.gz', data)]);
  const server = createServer((request, response) => {
    if (request.headers.authorization !== 'Bearer s3cret') return response.writeHead(401).end();
    if (request.url !== '/archive/chrome.tar.gz') return response.writeHead(404).end();
    return response.writeHead(200).end(data);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/archive`;
  const restoreRun = (env, ...args) => new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
  const where = ['--reference', reference, '--platform', 'linux', '--arch', 'amd64', '--archive', path.join(dir, 'archive'),
    '--installed', path.join(dir, 'installed')];
  const restored = await restoreRun({ PINNED_ARCHIVE_URL: url, PINNED_ARCHIVE_TOKEN: 's3cret' }, ...where);
  assert.equal(restored.status, 0, restored.stderr);
  assert.equal(readFileSync(path.join(dir, 'installed', 'opt', 'google', 'chrome', 'chrome'), 'utf8'), 'chrome');
  assert.equal(restored.stdout, `chrome.tar.gz restored and installed in ${path.join(dir, 'installed')}\n`);
  const refused = await restoreRun({ PINNED_ARCHIVE_URL: url, PINNED_ARCHIVE_TOKEN: 'wrong' }, ...where);
  assert.equal(refused.status, 1);
  assert.equal(refused.stderr, 'the archive answered HTTP 401 for chrome.tar.gz\n');
  assert.doesNotMatch(refused.stderr, /127\.0\.0\.1|wrong/);
  const usage = await restoreRun({}, '--reference', reference);
  assert.equal(usage.status, 2);
  assert.equal(usage.stderr, 'usage: pinned-restore.mjs --reference FILE --platform P --arch A --archive DIR --installed DIR\n');
});
