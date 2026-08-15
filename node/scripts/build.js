#!/usr/bin/env node
// Build the Go transport into node/vendor/.
//
// Run with --optional during install: a machine without Go should get a usable
// package and a clear message, not a failed `npm install`. The error surfaces
// later, from resolveBinary, with instructions attached.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, '..');
const moduleRoot = path.resolve(packageRoot, '..');
const optional = process.argv.includes('--optional');

const output = path.join(packageRoot, 'vendor', process.platform === 'win32' ? 'tlsforge.exe' : 'tlsforge');

function fail(message) {
  const where = optional ? console.warn : console.error;
  where(message);
  process.exit(optional ? 0 : 1);
}

// A published tarball has no Go sources next to it, so there is nothing to
// build and nothing to warn about.
if (!existsSync(path.join(moduleRoot, 'go.mod'))) {
  if (!optional) fail('tlsforge: no Go sources found; install the binary separately or set TLSFORGE_BIN.');
  process.exit(0);
}

try {
  execFileSync('go', ['version'], { stdio: 'ignore' });
} catch {
  fail(
    'tlsforge: Go is not installed, so the transport was not built.\n' +
      '  Install Go 1.24+ and run:  npm explore tls-forge -- npm run build\n' +
      '  Or point at a prebuilt binary:  TLSFORGE_BIN=/path/to/tlsforge',
  );
}

mkdirSync(path.dirname(output), { recursive: true });
try {
  execFileSync('go', ['build', '-o', output, './cmd/tls-forge'], { cwd: moduleRoot, stdio: 'inherit' });
} catch (err) {
  fail(`tlsforge: building the transport failed: ${err.message}`);
}
console.log(`tlsforge: built ${output}`);
