#!/usr/bin/env node
// Install one published SDK into an empty directory and make a real request.
//
// This is deliberately separate from check-release-packages.mjs. That script
// proves the bytes about to be uploaded; this one starts with public package
// names and proves that registries, platform selection and packaged binaries
// produce a working installation for an end user.

import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const RELEASE_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:a|alpha|b|beta|c|rc|pre|preview|dev)(?:\.?(?:0|[1-9]\d*))?)?$/;
const SDKS = new Set(['go', 'node', 'python']);
const REQUEST_URL = 'https://example.com/';

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index >= 0 && process.argv[index + 1]) return process.argv[index + 1];
  throw new Error(`missing --${name}`);
}

const sdk = arg('sdk');
const version = arg('version').replace(/^v/, '');
if (!SDKS.has(sdk)) throw new Error(`unsupported SDK ${JSON.stringify(sdk)}`);
if (!RELEASE_VERSION.test(version)) {
  throw new Error(`version ${JSON.stringify(version)} is not a release version`);
}

const workspace = mkdtempSync(path.join(os.tmpdir(), `tls-forge-${sdk}-published-`));
const cleanEnvironment = { ...process.env };
delete cleanEnvironment.TLSFORGE_BIN;

function commandLine(command, args) {
  return [command, ...args].map((part) => JSON.stringify(part)).join(' ');
}

function run(command, args, cwd, options = {}) {
  console.log(`> ${commandLine(command, args)}`);
  const shell = process.platform === 'win32' && command.endsWith('.cmd');
  const completed = spawnSync(command, args, {
    cwd,
    env: options.env ?? cleanEnvironment,
    encoding: 'utf8',
    shell,
    stdio: options.capture ? 'pipe' : 'inherit',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (options.capture) {
    if (completed.stdout) process.stdout.write(completed.stdout);
    if (completed.stderr) process.stderr.write(completed.stderr);
  }
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    throw new Error(`${command} exited with status ${completed.status}`);
  }
  return completed.stdout ?? '';
}

function assertIncludes(value, expected, description) {
  if (!value.includes(expected)) {
    throw new Error(`${description} does not contain ${JSON.stringify(expected)}: ${JSON.stringify(value)}`);
  }
}

async function retry(label, action) {
  let lastError;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      return action();
    } catch (error) {
      lastError = error;
      if (attempt === 4) break;
      console.warn(`${label} failed on attempt ${attempt}; retrying in 15 seconds: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, 15_000));
    }
  }
  throw lastError;
}

async function checkGo() {
  const moduleDir = path.join(workspace, 'module');
  const binaryDir = path.join(workspace, 'bin');
  mkdirSync(moduleDir);
  mkdirSync(binaryDir);

  run('go', ['mod', 'init', 'tls-forge-published-smoke'], moduleDir);
  await retry('downloading the Go module', () =>
    run('go', ['get', `github.com/Sec-CH-Lemon/tls-forge@v${version}`], moduleDir));
  writeFileSync(
    path.join(moduleDir, 'main.go'),
    `package main

import (
  "fmt"

  tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

func main() {
  client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
  if err != nil { panic(err) }
  defer client.Close()

  response, err := client.Get(${JSON.stringify(REQUEST_URL)})
  if err != nil { panic(err) }
  if response.Status != 200 { panic(fmt.Sprintf("status = %d, want 200", response.Status)) }
  fmt.Println("Go SDK fetched", response.URL)
}
`,
  );
  await retry('running the Go SDK request', () => run('go', ['run', '.'], moduleDir));

  const goEnvironment = { ...cleanEnvironment, GOBIN: binaryDir };
  await retry('installing the Go CLI', () =>
    run(
      'go',
      ['install', `github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@v${version}`],
      workspace,
      { env: goEnvironment },
    ));
  const binary = path.join(binaryDir, process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge');
  const buildInfo = run('go', ['version', '-m', binary], workspace, { capture: true });
  assertIncludes(
    buildInfo,
    `\tmod\tgithub.com/Sec-CH-Lemon/tls-forge\tv${version}\t`,
    'Go CLI build info',
  );
  run(binary, ['profiles'], workspace);
}

async function checkNode() {
  const project = path.join(workspace, 'project');
  mkdirSync(project);
  writeFileSync(path.join(project, 'package.json'), '{"private":true,"type":"module"}\n');

  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const npmEnvironment = {
    ...cleanEnvironment,
    NPM_CONFIG_CACHE: path.join(workspace, 'npm-cache'),
    NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
  };
  await retry('installing the npm package', () =>
    run(
      npm,
      [
        'install', '--ignore-scripts', '--no-package-lock', '--no-audit', '--no-fund',
        `tls-forge@${version}`,
      ],
      project,
      { env: npmEnvironment },
    ));

  const manifest = JSON.parse(readFileSync(path.join(project, 'node_modules', 'tls-forge', 'package.json')));
  if (manifest.version !== version) {
    throw new Error(`npm installed tls-forge ${manifest.version}, want ${version}`);
  }
  const packagePlatform = process.platform === 'win32' ? 'windows' : process.platform;
  const platformPackage = `tls-forge-${packagePlatform}-${process.arch}`;
  const platformManifest = JSON.parse(
    readFileSync(path.join(project, 'node_modules', platformPackage, 'package.json')),
  );
  if (platformManifest.version !== version) {
    throw new Error(`npm installed ${platformPackage} ${platformManifest.version}, want ${version}`);
  }

  const program = `
    import { Client } from 'tls-forge';
    const client = new Client({ profile: 'chrome' });
    try {
      const response = await client.get(${JSON.stringify(REQUEST_URL)});
      if (response.status !== 200) throw new Error(\`status = \${response.status}, want 200\`);
      console.log('Node SDK fetched', response.url);
    } finally {
      client.close();
    }
  `;
  await retry('running the Node SDK request', () =>
    run(process.execPath, ['--input-type=module', '-e', program], project));
}

async function checkPython() {
  const venv = path.join(workspace, 'venv');
  const python = process.platform === 'win32' ? 'python.exe' : 'python3';
  run(python, ['-m', 'venv', venv], workspace);
  const venvPython = process.platform === 'win32'
    ? path.join(venv, 'Scripts', 'python.exe')
    : path.join(venv, 'bin', 'python');
  const pipEnvironment = {
    ...cleanEnvironment,
    PIP_DISABLE_PIP_VERSION_CHECK: '1',
    PIP_INDEX_URL: 'https://pypi.org/simple',
  };
  await retry('installing the PyPI package', () =>
    run(
      venvPython,
      ['-m', 'pip', 'install', '--no-cache-dir', `tls-forge==${version}`],
      workspace,
      { env: pipEnvironment },
    ));

  const program = `
import subprocess
import tlsforge

expected = ${JSON.stringify(version)}
assert tlsforge.__version__ == expected, (tlsforge.__version__, expected)
binary = tlsforge.resolve_binary()
reported = subprocess.run([str(binary), "version"], check=True, capture_output=True, text=True).stdout
assert "v" + expected in reported, reported
with tlsforge.Client(profile="chrome") as client:
    response = client.get(${JSON.stringify(REQUEST_URL)})
assert response.status == 200, response.status
print("Python SDK fetched", response.url)
`;
  await retry('running the Python SDK request', () =>
    run(venvPython, ['-c', program], workspace));
}

try {
  if (sdk === 'go') await checkGo();
  if (sdk === 'node') await checkNode();
  if (sdk === 'python') await checkPython();
  console.log(`published ${sdk} ${version} passed on ${process.platform}-${process.arch}`);
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
