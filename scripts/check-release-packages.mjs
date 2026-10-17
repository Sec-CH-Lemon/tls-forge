#!/usr/bin/env node
// Installing and running what a release set has for this machine, exactly as
// it will be published: the Go archive, the npm package and the Python wheel.
// Each one's binary has to run and say the set's version. This is
// cross-platform JavaScript, so the same check runs on Linux, macOS and
// Windows without shell-specific paths.
//
//   node scripts/check-release-packages.mjs --version V --set DIR [--python PYTHON]

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { pep440 } from './release-set.mjs';

// What each machine installs, by Node.js's name for it.
export const TARGETS = {
  'darwin-arm64': { archive: 'darwin_arm64', npm: 'darwin-arm64', wheel: 'macosx_12_0_arm64.whl' },
  'darwin-x64': { archive: 'darwin_amd64', npm: 'darwin-x64', wheel: 'macosx_12_0_x86_64.whl' },
  'linux-arm64': { archive: 'linux_arm64', npm: 'linux-arm64', wheel: 'manylinux2014_aarch64.musllinux_1_1_aarch64.whl' },
  'linux-x64': { archive: 'linux_amd64', npm: 'linux-x64', wheel: 'manylinux2014_x86_64.musllinux_1_1_x86_64.whl' },
  'win32-x64': { archive: 'windows_amd64', npm: 'windows-x64', wheel: 'win_amd64.whl' },
};

// The files an archive holds beside the binary: the notices it has to travel
// with, and the README.
const BESIDE = ['LICENSE', 'NOTICE', 'README.md', 'THIRD-PARTY-NOTICES.txt'];

// run runs command in cwd, its output shown as it comes, and is what it wrote
// to stdout. One that cannot start or does not succeed throws.
export function run(command, args, { cwd, env = process.env, shell = false }) {
  console.log(`> ${command} ${args.join(' ')}`);
  const done = spawnSync(command, args, { cwd, env, shell, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  if (done.error) throw done.error;
  process.stdout.write(done.stdout);
  if (done.status !== 0) throw new Error(`${command} exited with ${done.signal ?? `status ${done.status}`}`);
  return done.stdout;
}

// packagesOf are this machine's files in the set of version in dir, each of
// which has to be there.
export function packagesOf(dir, version, machine) {
  const target = TARGETS[machine];
  if (!Object.hasOwn(TARGETS, machine)) throw new Error(`a release has nothing for ${machine}`);
  const files = {
    archive: path.join(dir, `tls-forge_${version}_${target.archive}.tar.gz`),
    main: path.join(dir, `tls-forge-${version}.tgz`),
    platform: path.join(dir, `tls-forge-${target.npm}-${version}.tgz`),
    wheel: path.join(dir, `tls_forge-${pep440(version)}-py3-none-${target.wheel}`),
  };
  for (const file of Object.values(files)) {
    if (!existsSync(file)) throw new Error(`the set has no ${path.basename(file)}`);
  }
  return files;
}

// check installs and runs this machine's packages of the set of version in
// dir, each in a directory of its own that is gone afterwards, the wheel with
// python, or the platform's usual one.
export function check({ version, set, python }, { exec = run, platform = process.platform, arch = process.arch } = {}) {
  const files = packagesOf(set, version, `${platform}-${arch}`);
  const target = TARGETS[`${platform}-${arch}`];
  const windows = platform === 'win32';
  const interpreter = python ?? (windows ? 'python.exe' : 'python3');
  const said = `tls-forge v${version}`;
  const saysTheVersion = (binary, cwd) => {
    const answer = exec(binary, ['version'], { cwd }).trim();
    if (answer !== said) throw new Error(`${binary} says ${JSON.stringify(answer)}, not ${JSON.stringify(said)}`);
  };
  const work = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-packages-'));
  try {
    // The archive, unpacked as a user would, and its binary run. On Windows
    // by its own tar, which reads D:\ as a drive: Git's GNU tar, when it is
    // first on PATH, takes it for a remote host.
    const unpacked = path.join(work, 'archive');
    mkdirSync(unpacked);
    const tar = windows ? path.win32.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
    exec(tar, ['-xzf', files.archive, '-C', unpacked], { cwd: work });
    for (const name of [...BESIDE, windows ? 'tls-forge.exe' : 'tls-forge']) {
      if (!existsSync(path.join(unpacked, name))) throw new Error(`${path.basename(files.archive)} has no ${name}`);
    }
    saysTheVersion(path.join(unpacked, windows ? 'tls-forge.exe' : 'tls-forge'), unpacked);

    // npm is a .cmd shim on Windows and needs cmd.exe for it. Every argument
    // is a path or a flag made here, never anything a user gave.
    const npm = windows ? 'npm.cmd' : 'npm';
    const project = path.join(work, 'node');
    mkdirSync(project);
    const env = { ...process.env, NPM_CONFIG_CACHE: path.join(work, 'npm-cache'), NPM_CONFIG_UPDATE_NOTIFIER: 'false' };
    exec(npm, ['init', '-y'], { cwd: project, env, shell: windows });
    exec(npm, ['install', '--ignore-scripts', '--offline', '--no-package-lock', '--no-audit', '--no-fund', files.main, files.platform],
      { cwd: project, env, shell: windows });
    exec(process.execPath, ['--input-type=module', '-e', "import { Client } from 'tls-forge'; new Client().close();"], { cwd: project });
    saysTheVersion(path.join(project, 'node_modules', `tls-forge-${target.npm}`, 'bin', windows ? 'tls-forge.exe' : 'tls-forge'), project);

    // The wheel, installed with nothing else into a fresh environment.
    const venv = path.join(work, 'venv');
    exec(interpreter, ['-m', 'venv', venv], { cwd: work });
    const venvPython = windows ? path.join(venv, 'Scripts', 'python.exe') : path.join(venv, 'bin', 'python');
    exec(venvPython, ['-m', 'pip', 'install', '--no-index', files.wheel], { cwd: work });
    exec(venvPython, ['-c', `import subprocess, tlsforge
binary = tlsforge.resolve_binary()
assert 'site-packages' in binary.lower(), binary
answer = subprocess.run([binary, 'version'], capture_output=True, text=True, check=True).stdout.strip()
assert answer == ${JSON.stringify(said)}, answer
assert tlsforge.__version__ == ${JSON.stringify(version)}, tlsforge.__version__`], { cwd: work });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function options(argv) {
  const named = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) named[argv[i].replace(/^--/, '')] = argv[i + 1];
  return named;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const named = options(process.argv.slice(2));
  if (typeof named.version !== 'string' || typeof named.set !== 'string') {
    console.error('usage: check-release-packages.mjs --version V --set DIR [--python PYTHON]');
    process.exitCode = 2;
  } else {
    try {
      check({ version: named.version, set: path.resolve(named.set), python: named.python });
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  }
}
