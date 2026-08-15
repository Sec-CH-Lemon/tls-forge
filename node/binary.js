// Where is the tlsforge binary?
//
// Three answers, in order, and the order is the point: an explicit override
// beats a local build beats whatever is on PATH. A package that silently
// preferred a system-wide binary over the one it just built would run a
// different version from the one under test.

import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

/** The default place `npm run build` puts the binary. */
export const builtBinary = path.join(here, 'vendor', process.platform === 'win32' ? 'tlsforge.exe' : 'tlsforge');

/**
 * Resolve the transport binary.
 *
 * @param {string} [explicit] a path to use as given
 * @returns {string}
 */
export function resolveBinary(explicit) {
  const candidate = explicit || process.env.TLSFORGE_BIN;
  if (candidate) {
    if (!existsSync(candidate)) {
      throw new Error(`tlsforge: no binary at ${candidate}`);
    }
    return candidate;
  }
  if (existsSync(builtBinary)) return builtBinary;

  const onPath = lookPath('tlsforge');
  if (onPath) return onPath;

  throw new Error(
    'tlsforge: no transport binary found.\n' +
      '  Build it:   npm explore tls-forge -- npm run build   (needs Go 1.24+)\n' +
      '  Or point at one:   TLSFORGE_BIN=/path/to/tlsforge',
  );
}

function lookPath(name) {
  // `which` is not on every Windows image and `where` is not on every Unix one,
  // so a failure here means "not found", not "broken install".
  try {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const found = execFileSync(finder, [name], { encoding: 'utf8' }).split(/\r?\n/)[0].trim();
    return found && existsSync(found) ? found : null;
  } catch {
    return null;
  }
}
