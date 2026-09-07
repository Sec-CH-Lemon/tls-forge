// Where is the tls-forge binary?
//
// Four answers, in order, and the order is the point: an explicit override beats
// the platform package beats a local build beats whatever is on PATH. A package
// that silently preferred a system-wide binary over the one it shipped with
// would run a different version from the one it was tested against.
//
// The binary itself arrives through an optional dependency — one small package
// per platform, each declaring `os` and `cpu`, so npm installs exactly the one
// that matches and skips the rest. That is the arrangement esbuild and swc use,
// and it is here for the reason they chose it: no Go on the machine, no download
// during install, and it survives `npm ci --ignore-scripts`, which a postinstall
// step does not.

import { statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

/** The platform package for the machine this is running on. */
// npm calls the Windows `os` value win32, but that spelling triggered the
// registry's package-name spam detector. Only the package name uses windows;
// its manifest still declares `os: ["win32"]`, so npm selects it correctly.
export function platformPackageName(platform, arch) {
  const packagePlatform = platform === 'win32' ? 'windows' : platform;
  return `tls-forge-${packagePlatform}-${arch}`;
}

export const platformPackage = platformPackageName(process.platform, process.arch);

/** The executable's name, which is the command's name, not the package's. */
export const exeName = {
  darwin: 'tls-forge',
  linux: 'tls-forge',
  win32: 'tls-forge.exe',
}[process.platform];

/** The default place `npm run build` puts a locally built binary. */
// String(undefined) is intentional: on an unsupported platform this becomes a
// harmless non-existent candidate rather than making path.join throw during
// module import, so an explicit path or TLSFORGE_BIN can still work.
export const builtBinary = path.join(here, 'vendor', String(exeName));

/**
 * Resolve the transport binary.
 *
 * @param {string} [explicit] a path to use as given
 * @returns {string}
 */
export function resolveBinary(explicit) {
  const candidate = explicit || process.env.TLSFORGE_BIN;
  if (candidate) {
    if (!isFile(candidate)) {
      throw new Error(`tls-forge: no binary at ${candidate}`);
    }
    return candidate;
  }

  const shipped = fromPlatformPackage();
  if (shipped) return shipped;

  if (isFile(builtBinary)) return builtBinary;

  const onPath = lookPath('tls-forge');
  if (onPath) return onPath;

  throw new Error(
    `tls-forge: no binary for ${process.platform}-${process.arch}.\n` +
      `  The platform package ${platformPackage} is not installed. If this was an\n` +
      '  install with --no-optional, re-run without it. Otherwise this platform has\n' +
      '  no prebuilt binary yet — build one with Go 1.26.7+\n' +
      '    go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest\n' +
      '  or point at one you already have\n' +
      '    TLSFORGE_BIN=/path/to/tls-forge',
  );
}

/**
 * The binary from the optional dependency for this platform, if npm installed
 * one.
 *
 * Two resolution bases are tried, and the second is not defensive padding. A
 * `file:` dependency, `npm link` and most monorepo layouts install this package
 * as a SYMLINK, and `import.meta.url` then points into the original checkout
 * rather than into the tree the platform package was installed in — so
 * module-relative resolution looks in the wrong place and finds nothing. That
 * was measured, not imagined: installing the assembled packages into a scratch
 * project failed exactly this way before the cwd base was added.
 */
function fromPlatformPackage() {
  const bases = [require, createRequire(path.join(process.cwd(), 'package.json'))];
  for (const resolver of bases) {
    try {
      // The package's manifest is resolved rather than the binary itself: a
      // binary is not a module, and resolving an extensionless file is not
      // portable. The manifest says where the package landed, which is what is
      // actually needed.
      const manifest = resolver.resolve(`${platformPackage}/package.json`);
      const binary = path.join(path.dirname(manifest), 'bin', String(exeName));
      if (isFile(binary)) return binary;
    } catch {
      // Not installed under this base: npm skipped it because `os`/`cpu` did
      // not match, the install ran without optional dependencies, or this is
      // simply the wrong tree. Try the next one.
    }
  }
  return null;
}

function lookPath(name) {
  // `which` is not on every Windows image and `where` is not on every Unix one,
  // so a failure here means "not found", not "broken install".
  try {
    const finder = { darwin: 'which', linux: 'which', win32: 'where' }[process.platform];
    const found = execFileSync(finder, [name], { encoding: 'utf8' })
      .split('\n')[0]
      .replace('\r', '')
      .trim();
    return found && isFile(found) ? found : null;
  } catch {
    return null;
  }
}

function isFile(candidate) {
  try {
    return statSync(candidate).isFile();
  } catch {
    return false;
  }
}
