#!/usr/bin/env node
// Restoring the reference a release is held to from the private archive: the
// installer of the build for this runner, fetched, held to its SHA-256 before
// anything opens it, and installed where the pinned gate looks for it.
//
//   node scripts/pinned-restore.mjs --reference reference/chrome.json \
//     --platform linux|macos|windows --arch amd64|arm64 --archive DIR --installed DIR
//
// The archive is wherever PINNED_ARCHIVE_URL says, each installer at
// <PINNED_ARCHIVE_URL>/<installer>, asked for with PINNED_ARCHIVE_TOKEN as a
// bearer token when that is set. An archive that is not configured, or does
// not have the installer, is a failure, never a reason to measure another
// browser. docs/pinned.md says how the archive is kept.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// buildOf is the build the reference at file names for platform and arch, its
// installer a bare file name and its digest whole, as internal/reference
// holds them.
export function buildOf(file, platform, arch) {
  let reference;
  try {
    reference = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`the reference ${file} cannot be read: ${err.message}`);
  }
  const build = (Array.isArray(reference?.builds) ? reference.builds : [])
    .find((candidate) => candidate?.platform === platform && candidate?.arch === arch);
  if (build === undefined) throw new Error(`the reference ${file} has no build for ${platform}/${arch}`);
  const installer = build.installer;
  if (typeof installer !== 'string' || installer === '' || /[/\\]/.test(installer) || installer === '.' || installer === '..') {
    throw new Error(`the reference's installer ${JSON.stringify(installer)} is not a file name`);
  }
  if (!/^[0-9a-f]{64}$/.test(build.installer_sha256)) {
    throw new Error(`the reference's installer_sha256 ${JSON.stringify(build.installer_sha256)} is not a SHA-256 in lower-case hex`);
  }
  return build;
}

// installing is how the installer at file is installed into dir on platform:
// the commands, in order, and those that run whatever came before failed.
// Each kind of installer is unpacked rather than run, so that nothing is
// installed for the whole machine: a .deb by dpkg-deb, a .dmg mounted and
// copied, an .msi by an administrative install, an archive of an installed
// browser by tar, or unzip on Linux, whose tar reads no zip.
export function installing(file, dir, platform, scratch) {
  const name = path.basename(file);
  if (name.endsWith('.deb')) return { steps: [['dpkg-deb', ['-x', file, dir]]], after: [] };
  if (name.endsWith('.dmg')) {
    const mount = path.join(scratch, 'mount');
    return {
      steps: [['hdiutil', ['attach', '-nobrowse', '-readonly', '-noautoopen', '-mountpoint', mount, file]], ['ditto', [mount, dir]]],
      after: [['hdiutil', ['detach', mount]]],
    };
  }
  if (name.endsWith('.msi')) return { steps: [['msiexec', ['/a', file, '/qn', '/norestart', `TARGETDIR=${dir}`]]], after: [] };
  if (name.endsWith('.zip')) {
    return { steps: [platform === 'linux' ? ['unzip', ['-q', file, '-d', dir]] : ['tar', ['-xf', file, '-C', dir]]], after: [] };
  }
  if (/\.(tar|tar\.gz|tgz|tar\.xz|tar\.bz2)$/.test(name)) return { steps: [['tar', ['-xf', file, '-C', dir]]], after: [] };
  throw new Error(`${name} is no installer this knows how to unpack: a .deb, .dmg, .msi, .zip or tar archive`);
}

// run runs a command, its output passed through, and throws when it fails.
export function run(command, args) {
  const done = spawnSync(command, args, { stdio: 'inherit' });
  if (done.error) throw done.error;
  if (done.status !== 0) throw new Error(`${command} failed: ${done.signal ?? `exit ${done.status}`}`);
}

// restore fetches the reference's installer for platform and arch into
// archive, holds it to its digest, and installs it into installed.
export async function restore({ reference, platform, arch, archive, installed }, { fetch, exec = run, env = process.env, log = () => {} }) {
  const build = buildOf(reference, platform, arch);
  const base = env.PINNED_ARCHIVE_URL ?? '';
  if (base === '') {
    throw new Error('PINNED_ARCHIVE_URL is not set: there is no archive to restore the reference from, and a release is held to it');
  }
  const file = path.resolve(archive, build.installer);
  const into = path.resolve(installed);
  const scratch = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-restore-'));
  try {
    // Said before the download: an installer this cannot unpack is not worth
    // fetching.
    const { steps, after } = installing(file, into, platform, scratch);
    const headers = env.PINNED_ARCHIVE_TOKEN ? { authorization: `Bearer ${env.PINNED_ARCHIVE_TOKEN}` } : {};
    // Neither the address nor the token is said: either may be the secret.
    const response = await fetch(`${base.replace(/\/+$/, '')}/${encodeURIComponent(build.installer)}`, { headers });
    if (!response.ok) throw new Error(`the archive answered HTTP ${response.status} for ${build.installer}`);
    const data = Buffer.from(await response.arrayBuffer());
    const digest = createHash('sha256').update(data).digest('hex');
    if (digest !== build.installer_sha256) {
      throw new Error(`${build.installer} from the archive hashes to ${digest}, not ${build.installer_sha256}: it is not the reference's`);
    }
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, data);
    mkdirSync(into, { recursive: true });
    // What has to run after, a mounted image detached, runs whatever came
    // before, and its own failure never hides the first.
    let failure = null;
    try {
      for (const [command, args] of steps) exec(command, args);
    } catch (err) {
      failure = err;
    }
    for (const [command, args] of after) {
      try {
        exec(command, args);
      } catch (err) {
        failure ??= err;
      }
    }
    if (failure !== null) throw failure;
    log(`${build.installer} restored and installed in ${into}`);
    return file;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function options(argv) {
  const named = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) named[argv[i].replace(/^--/, '')] = argv[i + 1];
  return named;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const named = options(process.argv.slice(2));
  if (['reference', 'platform', 'arch', 'archive', 'installed'].some((name) => typeof named[name] !== 'string')) {
    console.error('usage: pinned-restore.mjs --reference FILE --platform P --arch A --archive DIR --installed DIR');
    process.exitCode = 2;
  } else {
    try {
      await restore(named, { fetch, log: (line) => console.log(line) });
    } catch (err) {
      console.error(err.message);
      process.exitCode = 1;
    }
  }
}
