#!/usr/bin/env node
// A release's set: every file a release publishes, made once, and a manifest
// that binds them, by digest, to the version and the commit they were built
// from. Every attempt at publishing a version publishes this set and nothing
// rebuilt: a set that is lost, incomplete or not what its manifest says stops
// the release.
//
//   node scripts/release-set.mjs make   --dir DIR --version V --commit SHA
//   node scripts/release-set.mjs verify --dir DIR --version V --commit SHA
//   node scripts/release-set.mjs gated  --dir DIR --version V --commit SHA
//   node scripts/release-set.mjs digest --dir DIR
//   node scripts/release-set.mjs gates
//
// make writes SHA256SUMS and manifest.json into DIR, over the files there.
// verify holds DIR to its manifest: the version and the commit, every file there
// and as its digest says, exactly the files a release of V has, and SHA256SUMS
// as the manifest makes it. gated holds DIR to all of that and to the result of
// every pinned gate, passed for this commit and this set. digest prints the
// set's identity: the SHA-256 of its manifest. gates prints, as JSON, the gates
// a release waits for and where each runs.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const MANIFEST = 'manifest.json';
export const SUMS = 'SHA256SUMS';

// The platforms a release builds for, as each kind of file names them.
const ARCHIVES = ['darwin_arm64', 'darwin_amd64', 'linux_arm64', 'linux_amd64', 'windows_amd64'];
const NPM_PLATFORMS = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'windows-x64'];
const WHEELS = [
  'macosx_12_0_arm64.whl',
  'macosx_12_0_x86_64.whl',
  'manylinux2014_aarch64.musllinux_1_1_aarch64.whl',
  'manylinux2014_x86_64.musllinux_1_1_x86_64.whl',
  'win_amd64.whl',
];
const LEGAL = ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt'];

// A pinned gate's result, which joins the set after it is made.
const GATE = /^pinned-[a-z]+-[a-z0-9]+\.json$/;

// The pinned gates a release waits for: one on each platform, on a runner of
// it, which installs Google Chrome Stable from Google and holds the profile to
// it (docs/pinned.md).
const GATES = [
  { platform: 'macos', arch: 'arm64', runner: 'macos-15' },
  { platform: 'linux', arch: 'amd64', runner: 'ubuntu-24.04' },
  { platform: 'windows', arch: 'amd64', runner: 'windows-2025' },
];

// The versions a release may have: SemVer that npm and PyPI order alike, as the
// release workflow's check of the tag has it. SemVer's -1 would be a PyPI
// post-release, so a pre-release is one of these words and a number.
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(a|alpha|b|beta|c|rc|pre|preview|dev)(?:\.?(0|[1-9]\d*))?)?$/;

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

// pep440 is version as PyPI spells it, which names the Python distributions:
// 1.2.3-rc.1 is 1.2.3rc1 there, and 1.2.3-dev is 1.2.3.dev0.
export function pep440(version) {
  const [, major, minor, patch, pre, number = '0'] = VERSION.exec(version ?? '') ?? [];
  if (major === undefined) throw new Error(`--version ${version} is not a release version`);
  const release = `${major}.${minor}.${patch}`;
  if (pre === undefined) return release;
  if (pre === 'dev') return `${release}.dev${number}`;
  return `${release}${{ a: 'a', alpha: 'a', b: 'b', beta: 'b' }[pre] ?? 'rc'}${number}`;
}

// required are the files a set of version has, and no others.
export function required(version) {
  const python = pep440(version);
  return [
    ...ARCHIVES.map((target) => `tls-forge_${version}_${target}.tar.gz`),
    `tls-forge-${version}.tgz`,
    ...NPM_PLATFORMS.map((platform) => `tls-forge-${platform}-${version}.tgz`),
    `tls_forge-${python}.tar.gz`,
    ...WHEELS.map((suffix) => `tls_forge-${python}-py3-none-${suffix}`),
    'tls-forge.rb',
    ...LEGAL,
    SUMS,
  ];
}

// sums is SHA256SUMS for files, as sha256sum writes it, by name.
export function sums(files) {
  return [...files]
    .filter((file) => file.name !== SUMS)
    .sort((a, b) => (a.name < b.name ? -1 : 1))
    .map((file) => `${file.sha256}  ${file.name}\n`)
    .join('');
}

// make writes SHA256SUMS and the manifest over every file in dir, and is the
// manifest.
export function make(dir, version, commit) {
  pep440(version);
  checkCommit(commit);
  const read = (name) => {
    const data = readFileSync(path.join(dir, name));
    return { name, sha256: sha256(data), size: data.length };
  };
  // Files only: a directory is nothing a release publishes.
  const names = readdirSync(dir).filter((name) => name !== MANIFEST && name !== SUMS && !GATE.test(name)
    && statSync(path.join(dir, name)).isFile());
  const files = names.map(read);
  writeFileSync(path.join(dir, SUMS), sums(files));
  files.push(read(SUMS));
  files.sort((a, b) => (a.name < b.name ? -1 : 1));
  const manifest = { schema: 1, version, commit, files };
  writeFileSync(path.join(dir, MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

// gates are the pinned gates a release waits for: the platform, the machine,
// the runner it is measured on and the name its result is kept under in the
// set.
export function gates() {
  return GATES.map((gate) => ({ ...gate, result: `pinned-${gate.platform}-${gate.arch}.json` }));
}

// problems are what is wrong with the set in dir, held to version and commit,
// and, when gated, to a passed result of every pinned gate: none, when it can
// be published.
export function problems(dir, version, commit, gated = false) {
  let names;
  try {
    names = required(version);
  } catch (err) {
    return [err.message];
  }
  let raw;
  try {
    raw = readFileSync(path.join(dir, MANIFEST));
  } catch {
    return [`no ${MANIFEST}: the set is lost or was never made, and a version is never built twice`];
  }
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (err) {
    return [`${MANIFEST} is not JSON: ${err.message}`];
  }
  const found = [];
  if (manifest?.schema !== 1) found.push(`${MANIFEST} is of schema ${manifest?.schema}, not 1`);
  if (manifest?.version !== version) found.push(`the set is of version ${manifest?.version}, not ${version}`);
  if (manifest?.commit !== commit) found.push(`the set was built from ${manifest?.commit}, not ${commit}`);
  if (!Array.isArray(manifest?.files)) return [...found, `${MANIFEST} lists no files`];

  const listed = new Map();
  for (const file of manifest.files) {
    const named = typeof file?.name === 'string' && /^[A-Za-z0-9._+-]+$/.test(file.name) && !file.name.startsWith('.');
    if (!named || !/^[0-9a-f]{64}$/.test(file?.sha256) || !Number.isInteger(file?.size)) {
      found.push(`${MANIFEST} lists ${JSON.stringify(file)}, which is no file of a set`);
      continue;
    }
    if (listed.has(file.name)) found.push(`${MANIFEST} lists ${file.name} twice`);
    listed.set(file.name, file);
  }
  for (const name of names) {
    if (!listed.has(name)) found.push(`the set has no ${name}`);
  }
  for (const name of listed.keys()) {
    if (!names.includes(name)) found.push(`${name} is no file a release of ${version} has`);
  }

  for (const file of listed.values()) {
    let data;
    try {
      data = readFileSync(path.join(dir, file.name));
    } catch {
      found.push(`${file.name} is listed and not there`);
      continue;
    }
    if (data.length !== file.size || sha256(data) !== file.sha256) {
      found.push(`${file.name} is not what the manifest says: its digest is ${sha256(data)}`);
    }
  }
  for (const name of readdirSync(dir)) {
    if (name !== MANIFEST && !listed.has(name) && !GATE.test(name) && statSync(path.join(dir, name)).isFile()) {
      found.push(`${name} is no file of the set`);
    }
  }
  if (listed.has(SUMS)) {
    let written = null;
    try {
      written = readFileSync(path.join(dir, SUMS), 'utf8');
    } catch {
      // Said above, as a file that is listed and not there.
    }
    if (written !== null && written !== sums([...listed.values()])) {
      found.push(`${SUMS} is not what the manifest makes it`);
    }
  }
  if (gated) found.push(...gateProblems(dir, commit, sha256(raw)));
  return found;
}

// gateProblems are what is wrong with the gate results in dir: one missing,
// or one that did not pass, is for another commit or was measured with
// another set.
function gateProblems(dir, commit, identity) {
  const found = [];
  for (const { result: name } of gates()) {
    let result;
    try {
      result = JSON.parse(readFileSync(path.join(dir, name), 'utf8'));
    } catch (err) {
      found.push(`the gate result ${name} cannot be read: ${err.message}`);
      continue;
    }
    if (result?.ok !== true) found.push(`the gate result ${name} did not pass`);
    if (result?.commit !== commit) found.push(`the gate result ${name} is for ${result?.commit}, not ${commit}`);
    if (result?.set !== identity) found.push(`the gate result ${name} is for the set ${result?.set}, not ${identity}`);
  }
  return found;
}

function checkCommit(commit) {
  if (!/^[0-9a-f]{40}$/.test(commit ?? '')) throw new Error(`--commit ${commit} is not a full commit`);
}

function options(argv) {
  const named = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) named[argv[i].replace(/^--/, '')] = argv[i + 1];
  return named;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [command, ...rest] = process.argv.slice(2);
  const named = options(rest);
  // Each command, what it has to be told, and what it does: a list of what is
  // wrong, empty when nothing is.
  const commands = {
    make: [['dir', 'version', 'commit'], () => {
      make(named.dir, named.version, named.commit);
      return [];
    }],
    verify: [['dir', 'version', 'commit'], () => problems(named.dir, named.version, named.commit)],
    gated: [['dir', 'version', 'commit'], () => problems(named.dir, named.version, named.commit, true)],
    digest: [['dir'], () => {
      console.log(sha256(readFileSync(path.join(named.dir, MANIFEST))));
      return [];
    }],
    gates: [[], () => {
      console.log(JSON.stringify(gates()));
      return [];
    }],
  };
  const [needs, run] = Object.hasOwn(commands, command) ? commands[command] : [null];
  if (needs === null || needs.some((name) => typeof named[name] !== 'string')) {
    console.error(`usage: release-set.mjs ${Object.keys(commands).join('|')} --dir DIR --version V --commit SHA`);
    process.exitCode = 2;
  } else {
    let found;
    try {
      found = run();
    } catch (err) {
      found = [err.message];
    }
    for (const problem of found) console.error(problem);
    process.exitCode = found.length > 0 ? 1 : 0;
  }
}
