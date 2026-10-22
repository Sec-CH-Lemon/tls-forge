#!/usr/bin/env node
// Building a release's set: the one path from a commit to every file a release
// publishes. The release workflow, CI's packaging job and `make dist` all take
// it, so that what is tried before a tag is what the tag builds.
//
//   node scripts/release-build.mjs --version V --commit SHA --out DIR [--python PYTHON]
//
// It cross-compiles the binary for each platform, packs each with the licence
// files and the README into an archive, assembles and packs the npm packages,
// builds the Python distributions, writes the Homebrew formula and copies the
// licence files. Then it makes the set, SHA256SUMS and manifest.json, and
// verifies it. DIR is made if it is not there, and must hold nothing: a set is
// made from nothing, never over what is there.

import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { make, pep440, problems } from './release-set.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// The platforms a release builds for, as Go names them.
export const TARGETS = [
  ['darwin', 'arm64'],
  ['darwin', 'amd64'],
  ['linux', 'arm64'],
  ['linux', 'amd64'],
  ['windows', 'amd64'],
];

// Apache-2.0 section 4 has these travel with every redistribution, and a
// compiled binary with its dependencies linked in is one.
const LEGAL = ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt'];

// run runs command in the repository, or in cwd, with env laid over this
// process's, its errors passed through, and is what it printed. One that
// cannot start or does not succeed throws.
export function run(command, args, { cwd = ROOT, env = {} } = {}) {
  const done = spawnSync(command, args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
    maxBuffer: 64 * 1024 * 1024,
  });
  if (done.error) throw done.error;
  if (done.status !== 0) throw new Error(`${command} ${args.join(' ')} failed: ${done.signal ?? `exit ${done.status}`}`);
  return done.stdout;
}

// build makes the set of version, from the checkout at commit, in out, and is
// where it is.
export function build({ version, commit, out, python = 'python3' }, { exec = run, log = () => {} } = {}) {
  pep440(version);
  const identity = JSON.parse(readFileSync(path.join(ROOT, 'engine/version.json'), 'utf8')).version;
  if (version !== identity) throw new Error(`release version ${version} does not match compiled engine ${identity}`);
  if (!/^[0-9a-f]{40}$/.test(commit ?? '')) throw new Error(`--commit ${commit} is not a full commit`);
  if (typeof out !== 'string' || out === '') throw new Error('--out is where the set is made, and is not said');
  const dir = path.resolve(out);
  mkdirSync(dir, { recursive: true });
  if (readdirSync(dir).length > 0) throw new Error(`${dir} holds files already: a set is made from nothing`);

  const work = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-build-'));
  try {
    const bin = path.join(work, 'bin');
    for (const [goos, goarch] of TARGETS) {
      const exe = goos === 'windows' ? '.exe' : '';
      const binary = path.join(bin, `tls-forge-${goos}-${goarch}${exe}`);
      log(`building ${path.basename(binary)}`);
      exec('go', ['build', '-trimpath', '-ldflags', `-s -w -X main.version=v${version}`, '-o', binary, './cmd/tls-forge'],
        { env: { CGO_ENABLED: '0', GOOS: goos, GOARCH: goarch } });

      // A tarball, not a bare binary: whoever downloads it gets the notices
      // the binary has to travel with in the same file.
      const staging = path.join(work, `archive-${goos}-${goarch}`);
      mkdirSync(staging);
      copyFileSync(binary, path.join(staging, `tls-forge${exe}`));
      chmodSync(path.join(staging, `tls-forge${exe}`), 0o755);
      for (const name of [...LEGAL, 'README.md']) copyFileSync(path.join(ROOT, name), path.join(staging, name));
      // COPYFILE_DISABLE keeps macOS's tar from adding ._ files of extended
      // attributes when a set is made there; tar elsewhere ignores it.
      exec('tar', ['-czf', path.join(dir, `tls-forge_${version}_${goos}_${goarch}.tar.gz`), '-C', staging, '.'],
        { env: { COPYFILE_DISABLE: '1' } });
    }

    // Packed here: npm publishes tarballs, and a tarball keeps the binaries'
    // modes, which a copy between jobs does not.
    const npm = path.join(work, 'npm');
    exec(process.execPath, [path.join(ROOT, 'scripts', 'npm-release.mjs'), '--version', version, '--binaries', bin, '--out', npm]);
    for (const name of readdirSync(npm).sort()) {
      exec('npm', ['pack', path.join(npm, name), '--pack-destination', dir, '--ignore-scripts']);
    }

    const pypi = path.join(work, 'pypi');
    exec(python, [path.join(ROOT, 'scripts', 'pypi-release.py'), '--version', version, '--binaries', bin, '--out', pypi]);
    for (const name of readdirSync(pypi)) copyFileSync(path.join(pypi, name), path.join(dir, name));

    // The formula points at the archives by their checksums, so it is written
    // after them, from them.
    writeFileSync(path.join(dir, 'tls-forge.rb'),
      exec(process.execPath, [path.join(ROOT, 'scripts', 'homebrew-formula.mjs'), '--version', version, '--archives', dir]));
    for (const name of LEGAL) copyFileSync(path.join(ROOT, name), path.join(dir, name));

    make(dir, version, commit);
    const found = problems(dir, version, commit);
    if (found.length > 0) throw new Error(`what was built is not a release's set:\n${found.join('\n')}`);
    log(`${dir}: the set of ${version}, built from ${commit}`);
    return dir;
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
  if (['version', 'commit', 'out'].some((name) => typeof named[name] !== 'string')) {
    console.error('usage: release-build.mjs --version V --commit SHA --out DIR [--python PYTHON]');
    process.exitCode = 2;
  } else {
    try {
      build(named, { log: (line) => console.log(line) });
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  }
}
