#!/usr/bin/env node
// Publishing a release's set, once or again: what a registry already has is
// held to the set by digest, and only what it lacks is published. A file it
// has with the same digest is done; one with another digest stops the release,
// since a version is never published as two different things.
//
//   node scripts/release-publish.mjs state    --tag vV --repo OWNER/NAME
//   node scripts/release-publish.mjs github   --dir SET --tag vV --repo OWNER/NAME [--dry-run]
//   node scripts/release-publish.mjs npm      --dir SET --version V --tag latest|next [--dry-run]
//   node scripts/release-publish.mjs pypi     --dir SET --version V --out DIR [--dry-run]
//   node scripts/release-publish.mjs finish   --tag vV --repo OWNER/NAME
//   node scripts/release-publish.mjs homebrew --formula FILE --tap FILE
//
// state prints where the tag's release stands: none, stored, unfinished,
// published or lost. github makes the tag's release a draft holding the set,
// or completes the draft or release there. npm publishes the packages it
// lacks, the platform packages before the one that pins them. pypi copies to
// DIR the distributions PyPI lacks, for the upload to take. finish publishes
// the draft. homebrew says whether the tap's formula is to be written: not
// when it is this one, and never over another of the same version. With
// --dry-run, a command asks what it would and says what it would do, and
// changes nothing.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MANIFEST, pep440, required } from './release-set.mjs';

// plan is what to publish of local, a map of name to digest, given remote, what
// the registry has: the names it lacks, and those it has as they are. A name it
// has with another digest, or none to compare, throws, and so does a file it
// has that the set does not, unless extra says it may.
export function plan(local, remote, { extra = () => false } = {}) {
  const upload = [];
  const skip = [];
  const wrong = [];
  for (const [name, digest] of local) {
    if (!remote.has(name)) upload.push(name);
    else if (remote.get(name) === digest) skip.push(name);
    else wrong.push(`${name} is published as ${remote.get(name) ?? 'something with no digest'}, and the set has ${digest}`);
  }
  for (const name of remote.keys()) {
    if (!local.has(name) && !extra(name)) wrong.push(`${name} is published and is no file of the set`);
  }
  if (wrong.length > 0) throw new Error(`not the set; nothing more is published:\n${wrong.join('\n')}`);
  return { upload, skip };
}

const digestOf = (file, algorithm = 'sha256', encoding = 'hex') =>
  createHash(algorithm).update(readFileSync(file)).digest(encoding);

// setFiles are the names in a set's manifest.
export function setFiles(dir) {
  return JSON.parse(readFileSync(path.join(dir, MANIFEST), 'utf8')).files.map((file) => file.name);
}

// A pinned gate's result, which joins a release beside its set.
const isGate = (name) => /^pinned-[a-z]+-[a-z0-9]+\.json$/.test(name);

// release is the release of tag, a draft or not, or null: by the list of them,
// since the release of a tag is only found by its tag once it is published.
export function release(gh, repo, tag) {
  if (!/^v[0-9A-Za-z.-]+$/.test(tag ?? '')) throw new Error(`--tag ${tag} is not a release tag`);
  // tojson, so that each release is one line however gh would print it.
  const found = gh(['api', '--paginate', `repos/${repo}/releases?per_page=100`,
    '--jq', `.[] | select(.tag_name == "${tag}") | tojson`]).trim();
  return found === '' ? null : JSON.parse(found.split('\n')[0]);
}

// state is where the release of tag stands: published; a draft holding its
// whole set, stored; a draft its set was not finished being stored in,
// unfinished; or none. No release is lost when a registry has the version
// already: a set was published from, and is gone.
export async function state({ tag, repo }, { gh, npmRun, fetchJSON, pypiURL = 'https://pypi.org' }) {
  const found = release(gh, repo, tag);
  if (found !== null) {
    if (!found.draft) return 'published';
    // The manifest is stored last, so a draft that holds it holds the rest.
    return found.assets.some((asset) => asset.name === MANIFEST) ? 'stored' : 'unfinished';
  }
  const version = tag.slice(1);
  for (const file of required(version).filter((name) => name.endsWith(`-${version}.tgz`))) {
    const name = file.slice(0, -`-${version}.tgz`.length);
    let said = '';
    try {
      said = npmRun(['view', `${name}@${version}`, 'version']).trim();
    } catch (err) {
      if (!/E404/.test(String(err.message))) throw err;
    }
    if (said !== '') return 'lost';
  }
  return (await fetchJSON(`${pypiURL}/pypi/tls-forge/${pep440(version)}/json`)) === null ? 'none' : 'lost';
}

// github makes the release of tag a draft that holds the set, or completes the
// draft or the release that is there, and says what it uploaded.
export function github({ dir, tag, repo, dryRun = false }, { gh, log }) {
  const names = [...setFiles(dir), MANIFEST];
  const local = new Map(names.map((name) => [name, `sha256:${digestOf(path.join(dir, name))}`]));
  let found = release(gh, repo, tag);
  const { upload, skip } = plan(local, new Map((found?.assets ?? []).map((asset) => [asset.name, asset.digest ?? null])),
    { extra: isGate });
  if (dryRun) {
    log(`${tag}: would upload ${upload.length}, has ${skip.length}`);
    return upload;
  }
  if (found === null) {
    // The tag's own draft, which publishing fills: the store of the set from
    // here on, which every later attempt reads.
    gh(['release', 'create', tag, '--repo', repo, '--draft', '--verify-tag', '--title', tag, '--generate-notes',
      ...(tag.includes('-') ? ['--prerelease'] : [])]);
    found = { assets: [] };
  }
  // Never --clobber: a file there is the set's, or the release stopped. The
  // manifest goes last, on its own, so that a draft holding it holds the set.
  const files = upload.filter((name) => name !== MANIFEST);
  if (files.length > 0) gh(['release', 'upload', tag, '--repo', repo, ...files.map((name) => path.join(dir, name))]);
  if (upload.includes(MANIFEST)) gh(['release', 'upload', tag, '--repo', repo, path.join(dir, MANIFEST)]);
  log(`${tag}: uploaded ${upload.length}, had ${skip.length}`);
  return upload;
}

// finish publishes the draft of tag, which is then the release, and does
// nothing to one published already.
export function finish({ tag, repo }, { gh, log }) {
  const found = release(gh, repo, tag);
  if (found === null) throw new Error(`there is no release of ${tag}: its set is lost`);
  if (!found.draft) {
    log(`${tag}: published already`);
    return false;
  }
  gh(['release', 'edit', tag, '--repo', repo, '--draft=false']);
  log(`${tag}: published`);
  return true;
}

// npm publishes the packages of the set the registry lacks, the platform
// packages first: the main one pins them by exact version, and a window in
// which it is there and they are not would install nothing.
export function npm({ dir, version, tag, dryRun = false }, { npmRun, log }) {
  const main = `tls-forge-${version}.tgz`;
  const packages = setFiles(dir).filter((name) => name.startsWith('tls-forge-') && name.endsWith(`-${version}.tgz`));
  const ordered = [...packages.filter((name) => name !== main).sort(), ...packages.filter((name) => name === main)];
  const published = [];
  for (const file of ordered) {
    const name = file.slice(0, -`-${version}.tgz`.length);
    const local = new Map([[file, `sha512-${digestOf(path.join(dir, file), 'sha512', 'base64')}`]]);
    let integrity = '';
    try {
      integrity = npmRun(['view', `${name}@${version}`, 'dist.integrity']).trim();
    } catch (err) {
      if (!/E404/.test(String(err.message))) throw err;
    }
    const remote = integrity === '' ? new Map() : new Map([[file, integrity]]);
    const { upload } = plan(local, remote);
    if (upload.length > 0) {
      if (!dryRun) npmRun(['publish', path.join(dir, file), '--access', 'public', '--provenance', '--tag', tag]);
      published.push(file);
    }
  }
  log(`npm: ${dryRun ? 'would publish' : 'published'} ${published.length} of ${ordered.length}`);
  return published;
}

// pypi copies to out the distributions of the set PyPI does not have, for the
// upload to take, and says which.
export async function pypi({ dir, version, out, dryRun = false }, { fetchJSON, log, pypiURL = 'https://pypi.org' }) {
  // As PyPI spells the version, which names the files: 1.0.0-rc.1 is 1.0.0rc1.
  const spelled = pep440(version);
  const distributions = setFiles(dir).filter((name) => name === `tls_forge-${spelled}.tar.gz`
    || (name.startsWith(`tls_forge-${spelled}-`) && name.endsWith('.whl')));
  if (distributions.length === 0) throw new Error(`the set has no Python distributions of ${spelled}`);
  const local = new Map(distributions.map((name) => [name, digestOf(path.join(dir, name))]));
  const published = await fetchJSON(`${pypiURL}/pypi/tls-forge/${spelled}/json`);
  const remote = new Map((published?.urls ?? []).map((file) => [file.filename, file.digests?.sha256 ?? null]));
  const { upload } = plan(local, remote);
  if (!dryRun) {
    mkdirSync(out, { recursive: true });
    for (const name of upload) copyFileSync(path.join(dir, name), path.join(out, name));
  }
  log(`pypi: ${upload.length} ${dryRun ? 'would be uploaded' : 'to upload'} of ${distributions.length}`);
  return upload;
}

// homebrew is whether the tap's formula is to be written with formula: not when
// it is that formula, and never over another of the same version, which would
// be another set's.
export function homebrew({ formula, tap }, { read }) {
  const ours = read(formula);
  let theirs = null;
  try {
    theirs = read(tap);
  } catch {
    return true;
  }
  if (theirs === ours) return false;
  const versionOf = (text) => /\/releases\/download\/v([^/]+)\//.exec(text)?.[1];
  if (versionOf(theirs) !== undefined && versionOf(theirs) === versionOf(ours)) {
    throw new Error(`the tap has another formula of ${versionOf(ours)}; nothing is written over it`);
  }
  return true;
}

// options are the named arguments: --name value, and --dry-run on its own.
function options(argv) {
  const named = Object.create(null);
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i].replace(/^--/, '');
    if (name === 'dry-run') named.dryRun = true;
    else named[name] = argv[++i];
  }
  return named;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [command, ...rest] = process.argv.slice(2);
  const named = options(rest);
  const run = (program) => (args) => execFileSync(program, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const log = (line) => console.log(line);
  const deps = {
    gh: run('gh'),
    npmRun: run('npm'),
    log,
    read: (file) => readFileSync(file, 'utf8'),
    // Another index than PyPI's, for a test to stand one in.
    pypiURL: process.env.RELEASE_PYPI_URL ?? 'https://pypi.org',
    fetchJSON: async (url) => {
      const response = await fetch(url);
      if (response.status === 404) return null;
      if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
      return response.json();
    },
  };
  const commands = { github, finish, npm, pypi, homebrew, state };
  try {
    if (!Object.hasOwn(commands, command)) throw new Error(`usage: release-publish.mjs ${Object.keys(commands).join('|')} ...`);
    const result = await commands[command](named, deps);
    if (command === 'homebrew') console.log(result ? 'write' : 'unchanged');
    if (command === 'state') console.log(result);
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  }
}
