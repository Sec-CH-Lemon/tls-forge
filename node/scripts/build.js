#!/usr/bin/env node
// Build the Go transport into node/vendor/, for working on this repository.
//
// Released packages do not run this. The binary reaches users through a
// platform-specific optional dependency, built and published by the release
// workflow — see scripts/npm-release.mjs. This is the path for someone who has
// the sources checked out and wants the Node client to talk to the code they
// are editing.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, '..');
const moduleRoot = path.resolve(packageRoot, '..');

// The name binary.js looks for, which is the command's name.
const output = path.join(packageRoot, 'vendor', process.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge');

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (!existsSync(path.join(moduleRoot, 'go.mod'))) {
  fail(
    'tls-forge: no Go sources found next to this package.\n' +
      '  This script builds from a checkout. To use a release, install the\n' +
      '  tls-forge package from npm and let it pull the binary for your platform.',
  );
}

try {
  execFileSync('go', ['version'], { stdio: 'ignore' });
} catch {
  fail(
    'tls-forge: Go is not installed, so the transport was not built.\n' +
      '  Install Go 1.26.7+ and run:  npm run build\n' +
      '  Or point at a binary you already have:  TLSFORGE_BIN=/path/to/tls-forge',
  );
}

mkdirSync(path.dirname(output), { recursive: true });
try {
  execFileSync('go', ['build', '-o', output, './cmd/tls-forge'], { cwd: moduleRoot, stdio: 'inherit' });
} catch (err) {
  fail(`tls-forge: building the transport failed: ${err.message}`);
}
console.log(`tls-forge: built ${output}`);
