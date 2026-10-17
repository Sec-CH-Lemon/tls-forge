#!/usr/bin/env node
// Every action a workflow uses is pinned to the commit of a release, with the
// release named beside it, the way Dependabot keeps it:
//
//   - uses: owner/name@<40 hex digits> # vX.Y.Z
//
// A tag or a branch moves, and what runs would be what someone pushed there
// last; a commit does not. A local action or workflow (./...) is part of the
// checkout, and a Docker image is pinned by its digest.
//
//   node scripts/check-actions.mjs [DIR]
//
// It reads every workflow in DIR, .github/workflows by default, and says each
// `uses:` that is not pinned, exiting 1 if there is one.

import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PINNED = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(\/[^@\s]+)?@[0-9a-f]{40}$/;
const RELEASE = /^#\s*v\d+(\.\d+){0,2}$/;

// unpinned are the `uses:` in a workflow's text that are not pinned, each with
// its line and why.
export function unpinned(text) {
  const found = [];
  text.split('\n').forEach((line, index) => {
    const match = /^\s*(?:-\s+)?uses:\s*(.*?)\s*$/.exec(line);
    if (match === null) return;
    const [value, ...rest] = match[1].split(/\s+(?=#)/);
    const uses = value.replace(/^(['"])(.*)\1$/, '$2');
    const comment = rest.join(' ').trim();
    let why = null;
    if (uses.startsWith('./')) why = null;
    else if (uses.startsWith('docker://')) why = /@sha256:[0-9a-f]{64}$/.test(uses) ? null : 'is an image not pinned by its digest';
    else if (!PINNED.test(uses)) why = 'is not pinned to a commit';
    else if (!RELEASE.test(comment)) why = 'does not name the release its commit is, as # vX.Y.Z';
    if (why !== null) found.push({ line: index + 1, uses, why });
  });
  return found;
}

// problems are what is not pinned in every workflow in dir.
export function problems(dir) {
  return readdirSync(dir)
    .filter((name) => /\.ya?ml$/.test(name))
    .sort()
    .flatMap((name) => unpinned(readFileSync(path.join(dir, name), 'utf8'))
      .map(({ line, uses, why }) => `${path.join(dir, name)}:${line}: ${uses} ${why}`));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.github', 'workflows');
  let found;
  try {
    found = problems(dir);
  } catch (err) {
    found = [err.message];
  }
  for (const problem of found) console.error(problem);
  process.exitCode = found.length > 0 ? 1 : 0;
}
