import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { TARGETS, check, packagesOf, run } from './check-release-packages.mjs';
import { required } from './release-set.mjs';

const script = fileURLToPath(new URL('./check-release-packages.mjs', import.meta.url));

const temporary = (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-check-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};

// aSet holds every file a set of version has, as names only.
function aSet(t, version = '1.2.3') {
  const dir = temporary(t);
  for (const name of required(version)) writeFileSync(path.join(dir, name), name);
  return dir;
}

const option = (args, name) => args[args.indexOf(name) + 1];

// fakeMachine stands in for tar, npm, Node.js and Python, each leaving what the
// real one would, and each binary saying says. leave changes what the archive
// holds, and fail names a command that fails.
function fakeMachine({ says = 'tls-forge v1.2.3', leave = null, fail = null } = {}) {
  const calls = [];
  const exec = (command, args, options) => {
    calls.push({ command, args, options });
    if (fail !== null && (command === fail || args.includes(fail))) throw new Error(`${fail} exited with status 1`);
    if (command === 'tar' || command.endsWith('tar.exe')) {
      const into = option(args, '-C');
      const windows = args[1].includes('windows');
      for (const name of leave ?? ['LICENSE', 'NOTICE', 'README.md', 'THIRD-PARTY-NOTICES.txt', windows ? 'tls-forge.exe' : 'tls-forge']) {
        writeFileSync(path.join(into, name), name);
      }
    } else if (args[0] === 'install' && !command.includes('python')) {
      const platform = path.basename(args.at(-1)).replace(/-1\.2\.3\.tgz$/, '');
      mkdirSync(path.join(options.cwd, 'node_modules', platform, 'bin'), { recursive: true });
    } else if (args[0] === 'version') {
      return `${says}\n`;
    }
    return '';
  };
  return { exec, calls };
}

test('a machine finds its own packages in a set, and every one has to be there', (t) => {
  const dir = aSet(t);
  assert.deepEqual(packagesOf(dir, '1.2.3', 'linux-x64'), {
    archive: path.join(dir, 'tls-forge_1.2.3_linux_amd64.tar.gz'),
    main: path.join(dir, 'tls-forge-1.2.3.tgz'),
    platform: path.join(dir, 'tls-forge-linux-x64-1.2.3.tgz'),
    wheel: path.join(dir, 'tls_forge-1.2.3-py3-none-manylinux2014_x86_64.musllinux_1_1_x86_64.whl'),
  });
  // Every machine a release is for has all four.
  for (const machine of Object.keys(TARGETS)) assert.equal(Object.keys(packagesOf(dir, '1.2.3', machine)).length, 4, machine);
  // A pre-release's wheel is named as PyPI spells it.
  const next = aSet(t, '1.2.3-rc.1');
  assert.equal(path.basename(packagesOf(next, '1.2.3-rc.1', 'win32-x64').wheel), 'tls_forge-1.2.3rc1-py3-none-win_amd64.whl');
  for (const name of ['tls-forge_1.2.3_darwin_arm64.tar.gz', 'tls-forge-1.2.3.tgz', 'tls-forge-darwin-arm64-1.2.3.tgz',
    'tls_forge-1.2.3-py3-none-macosx_12_0_arm64.whl']) {
    const missing = aSet(t);
    rmSync(path.join(missing, name));
    assert.throws(() => packagesOf(missing, '1.2.3', 'darwin-arm64'), { message: `the set has no ${name}` });
  }
  for (const machine of ['freebsd-x64', 'linux-ia32', 'win32-arm64', 'constructor-']) {
    assert.throws(() => packagesOf(dir, '1.2.3', machine), { message: `a release has nothing for ${machine}` });
  }
});

test('the archive, the npm package and the wheel are each installed and run', (t) => {
  const dir = aSet(t);
  const machine = fakeMachine();
  check({ version: '1.2.3', set: dir, python: '/usr/bin/python3.9' }, { exec: machine.exec, platform: 'linux', arch: 'x64' });
  const work = path.dirname(option(machine.calls[0].args, '-C'));
  assert.deepEqual(machine.calls.map(({ command, args }) => [command, ...args]), [
    ['tar', '-xzf', path.join(dir, 'tls-forge_1.2.3_linux_amd64.tar.gz'), '-C', path.join(work, 'archive')],
    [path.join(work, 'archive', 'tls-forge'), 'version'],
    ['npm', 'init', '-y'],
    ['npm', 'install', '--ignore-scripts', '--offline', '--no-package-lock', '--no-audit', '--no-fund',
      path.join(dir, 'tls-forge-1.2.3.tgz'), path.join(dir, 'tls-forge-linux-x64-1.2.3.tgz')],
    [process.execPath, '--input-type=module', '-e', "import { Client } from 'tls-forge'; new Client().close();"],
    [path.join(work, 'node', 'node_modules', 'tls-forge-linux-x64', 'bin', 'tls-forge'), 'version'],
    ['/usr/bin/python3.9', '-m', 'venv', path.join(work, 'venv')],
    [path.join(work, 'venv', 'bin', 'python'), '-m', 'pip', 'install', '--no-index',
      path.join(dir, 'tls_forge-1.2.3-py3-none-manylinux2014_x86_64.musllinux_1_1_x86_64.whl')],
    [path.join(work, 'venv', 'bin', 'python'), '-c', machine.calls.at(-1).args[1]],
  ]);
  // The wheel's binary says the version, and so does the package.
  assert.match(machine.calls.at(-1).args[1], /assert answer == "tls-forge v1\.2\.3", answer\nassert tlsforge\.__version__ == "1\.2\.3"/);
  // npm keeps its cache in the check, and runs without a shell off Windows.
  const install = machine.calls[3].options;
  assert.equal(install.env.NPM_CONFIG_CACHE, path.join(work, 'npm-cache'));
  assert.equal(install.env.NPM_CONFIG_UPDATE_NOTIFIER, 'false');
  assert.equal(install.shell, false);
  assert.equal(install.cwd, path.join(work, 'node'));
  // And what it worked in is gone.
  assert.ok(!existsSync(work));
});

test('on Windows, npm is its shim, run by a shell, and Python is python.exe', (t) => {
  const dir = aSet(t);
  const machine = fakeMachine();
  check({ version: '1.2.3', set: dir }, { exec: machine.exec, platform: 'win32', arch: 'x64' });
  const work = path.dirname(option(machine.calls[0].args, '-C'));
  const commands = machine.calls.map((call) => call.command);
  const systemTar = path.win32.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe');
  assert.deepEqual(commands, [systemTar, path.join(work, 'archive', 'tls-forge.exe'), 'npm.cmd', 'npm.cmd', process.execPath,
    path.join(work, 'node', 'node_modules', 'tls-forge-windows-x64', 'bin', 'tls-forge.exe'), 'python.exe',
    path.join(work, 'venv', 'Scripts', 'python.exe'), path.join(work, 'venv', 'Scripts', 'python.exe')]);
  assert.ok(machine.calls.filter((call) => call.command === 'npm.cmd').every((call) => call.options.shell === true));
  // Windows' own tar, wherever Windows is.
  const root = process.env.SystemRoot;
  process.env.SystemRoot = 'E:\\Win';
  try {
    const elsewhere = fakeMachine();
    check({ version: '1.2.3', set: dir }, { exec: elsewhere.exec, platform: 'win32', arch: 'x64' });
    assert.equal(elsewhere.calls[0].command, 'E:\\Win\\System32\\tar.exe');
  } finally {
    if (root === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = root;
  }
  // Elsewhere, Python is python3 when it is not said.
  const mac = fakeMachine();
  check({ version: '1.2.3', set: dir }, { exec: mac.exec, platform: 'darwin', arch: 'arm64' });
  assert.equal(mac.calls[6].command, 'python3');
});

test('a package that is not whole, or not this version, fails the check', (t) => {
  const dir = aSet(t);
  for (const [leave, missing] of [
    [['LICENSE', 'README.md', 'THIRD-PARTY-NOTICES.txt', 'tls-forge'], 'NOTICE'],
    [['LICENSE', 'NOTICE', 'README.md', 'THIRD-PARTY-NOTICES.txt'], 'tls-forge'],
    [['NOTICE', 'README.md', 'THIRD-PARTY-NOTICES.txt', 'tls-forge'], 'LICENSE'],
  ]) {
    const machine = fakeMachine({ leave });
    assert.throws(() => check({ version: '1.2.3', set: dir }, { exec: machine.exec, platform: 'linux', arch: 'arm64' }),
      { message: `tls-forge_1.2.3_linux_arm64.tar.gz has no ${missing}` });
    assert.ok(!existsSync(path.dirname(option(machine.calls[0].args, '-C'))));
  }
  const older = fakeMachine({ says: 'tls-forge v1.2.2' });
  assert.throws(() => check({ version: '1.2.3', set: dir }, { exec: older.exec, platform: 'linux', arch: 'x64' }),
    /tls-forge says "tls-forge v1\.2\.2", not "tls-forge v1\.2\.3"$/);
  // A step that fails stops the check where it is.
  for (const step of ['tar', 'init', '--input-type=module', 'venv', '--no-index']) {
    const machine = fakeMachine({ fail: step });
    assert.throws(() => check({ version: '1.2.3', set: dir }, { exec: machine.exec, platform: 'linux', arch: 'x64' }),
      { message: `${step} exited with status 1` }, step);
    assert.ok(!existsSync(path.dirname(option(machine.calls[0].args, '-C'))), step);
  }
  assert.throws(() => check({ version: '1.2.3', set: dir }, { exec: fakeMachine().exec, platform: 'aix', arch: 'ppc64' }),
    { message: 'a release has nothing for aix-ppc64' });
});

test('a command is shown, its output passed on, and its failure said', (t) => {
  const dir = temporary(t);
  const shown = [];
  const write = process.stdout.write;
  const log = console.log;
  process.stdout.write = (chunk) => shown.push(String(chunk));
  console.log = (line) => shown.push(`${line}\n`);
  try {
    assert.equal(run(process.execPath, ['-e', 'process.stdout.write(process.cwd() + " " + process.env.SAID)'],
      { cwd: dir, env: { ...process.env, SAID: 'yes' } }), `${spawnSync(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], { cwd: dir, encoding: 'utf8' }).stdout} yes`);
    assert.equal(run(process.execPath, ['-e', 'process.stdout.write(process.env.SAID ?? "unset")'], { cwd: dir }),
      process.env.SAID ?? 'unset');
    assert.throws(() => run(process.execPath, ['-e', 'process.stdout.write("half"); process.exit(4)'], { cwd: dir }),
      { message: `${process.execPath} exited with status 4` });
    assert.throws(() => run(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM")'], { cwd: dir }),
      { message: `${process.execPath} exited with SIGTERM` });
    assert.throws(() => run(path.join(dir, 'no-such-tool'), [], { cwd: dir }), /ENOENT/);
  } finally {
    process.stdout.write = write;
    console.log = log;
  }
  assert.equal(shown[0], `> ${process.execPath} -e process.stdout.write(process.cwd() + " " + process.env.SAID)\n`);
  // What a failing command printed is shown before its failure is said.
  assert.ok(shown.includes('half'));
});

test('the command needs a version and a set, and says what is missing', (t) => {
  const dir = aSet(t);
  rmSync(path.join(dir, 'tls-forge-1.2.3.tgz'));
  const runCheck = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  for (const args of [[], ['--version', '1.2.3'], ['--set', dir]]) {
    const usage = runCheck(...args);
    assert.equal(usage.status, 2, args.join(' '));
    assert.equal(usage.stderr, 'usage: check-release-packages.mjs --version V --set DIR [--python PYTHON]\n');
  }
  const missing = runCheck('--version', '1.2.3', '--set', path.relative(process.cwd(), dir), '--python', 'python3');
  assert.equal(missing.status, 1);
  assert.equal(missing.stderr, 'the set has no tls-forge-1.2.3.tgz\n');
});
