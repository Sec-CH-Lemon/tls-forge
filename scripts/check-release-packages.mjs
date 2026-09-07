#!/usr/bin/env node
// Install the assembled npm package and Python wheel for this machine, then
// run the binary from each. This is intentionally cross-platform JavaScript:
// the same check runs on Linux, macOS and Windows without shell-specific paths.

import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const TARGETS = {
  'darwin-arm64': { npm: 'darwin-arm64', wheel: 'macosx_12_0_arm64.whl' },
  'darwin-x64': { npm: 'darwin-x64', wheel: 'macosx_12_0_x86_64.whl' },
  'linux-arm64': { npm: 'linux-arm64', wheel: 'manylinux2014_aarch64.musllinux_1_1_aarch64.whl' },
  'linux-x64': { npm: 'linux-x64', wheel: 'manylinux2014_x86_64.musllinux_1_1_x86_64.whl' },
  'win32-x64': { npm: 'win32-x64', wheel: 'win_amd64.whl' },
};

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  if (index >= 0 && process.argv[index + 1]) return process.argv[index + 1];
  if (fallback !== undefined) return fallback;
  throw new Error(`missing --${name}`);
}

function requireFile(file) {
  if (!existsSync(file)) throw new Error(`missing release artifact ${file}`);
  return file;
}

function run(command, args, cwd, env = process.env, shell = false) {
  console.log(`> ${command} ${args.join(' ')}`);
  const completed = spawnSync(command, args, { cwd, env, shell, stdio: 'inherit' });
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    throw new Error(`${command} exited with status ${completed.status}`);
  }
}

const version = arg('version');
const dist = path.resolve(arg('dist', 'dist'));
const python = arg('python', process.platform === 'win32' ? 'python.exe' : 'python3');
const targetName = `${process.platform}-${process.arch}`;
const target = TARGETS[targetName];
if (!target) throw new Error(`no packaged distribution for ${targetName}`);

const mainTarball = requireFile(path.join(dist, 'npm-packages', `tls-forge-${version}.tgz`));
const platformTarball = requireFile(
  path.join(dist, 'npm-packages', `tls-forge-${target.npm}-${version}.tgz`),
);
const wheels = readdirSync(path.join(dist, 'pypi'))
  .filter((name) => name.startsWith('tls_forge-') && name.endsWith(target.wheel));
if (wheels.length !== 1) {
  throw new Error(`expected one ${target.wheel} wheel, found ${JSON.stringify(wheels)}`);
}
const wheel = path.join(dist, 'pypi', wheels[0]);

const check = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-packages-'));
try {
  const nodeProject = path.join(check, 'node');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  // npm is a .cmd shim on Windows and therefore needs cmd.exe. Every argument
  // here is a path or fixed flag created by this script, never user input.
  const npmNeedsShell = process.platform === 'win32';
  const npmEnv = {
    ...process.env,
    NPM_CONFIG_CACHE: path.join(check, 'npm-cache'),
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
  };
  mkdirSync(nodeProject);
  run(npm, ['init', '-y'], nodeProject, npmEnv, npmNeedsShell);
  run(
    npm,
    [
      'install', '--ignore-scripts', '--offline', '--no-package-lock', '--no-audit', '--no-fund',
      mainTarball, platformTarball,
    ],
    nodeProject,
    npmEnv,
    npmNeedsShell,
  );
  run(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      "import { Client } from 'tls-forge'; const client = new Client(); client.close();",
    ],
    nodeProject,
  );
  const npmBinary = path.join(
    nodeProject,
    'node_modules',
    `tls-forge-${target.npm}`,
    'bin',
    process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge',
  );
  run(requireFile(npmBinary), ['version'], nodeProject);

  const venv = path.join(check, 'venv');
  run(python, ['-m', 'venv', venv], check);
  const venvPython = process.platform === 'win32'
    ? path.join(venv, 'Scripts', 'python.exe')
    : path.join(venv, 'bin', 'python');
  run(venvPython, ['-m', 'pip', 'install', '--no-index', wheel], check);
  run(
    venvPython,
    [
      '-c',
      `import subprocess, tlsforge
binary = tlsforge.resolve_binary()
assert 'site-packages' in binary.lower(), binary
completed = subprocess.run([binary, 'version'], capture_output=True, text=True)
print(binary, completed.stdout.strip())
assert completed.returncode == 0, completed.stderr
assert tlsforge.__version__ == ${JSON.stringify(version)}, tlsforge.__version__`,
    ],
    check,
  );
} finally {
  rmSync(check, { recursive: true, force: true });
}
