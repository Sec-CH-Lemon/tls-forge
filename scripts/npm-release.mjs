#!/usr/bin/env node
// Assemble the npm packages for a release.
//
// One package per platform, each carrying a single binary and declaring `os`
// and `cpu`, plus the main `tls-forge` package that lists them all as optional
// dependencies. npm installs the one that matches the machine and skips the
// rest — the arrangement esbuild and swc use. It needs no Go on the user's
// machine, downloads nothing during install, and works under
// `npm ci --ignore-scripts`.
//
//   node scripts/npm-release.mjs --version 0.1.0 --binaries dist/bin --out dist/npm
//
// The binaries are expected to be named tls-forge-<goos>-<goarch>[.exe].

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const SCOPE = '@sec-ch-lemon';

// npm's platform/arch names are process.platform and process.arch, which are
// not Go's. The mapping lives here, once, so nothing downstream has to know
// about both spellings.
const TARGETS = [
  { platform: 'darwin', arch: 'arm64', goos: 'darwin', goarch: 'arm64' },
  { platform: 'darwin', arch: 'x64', goos: 'darwin', goarch: 'amd64' },
  { platform: 'linux', arch: 'arm64', goos: 'linux', goarch: 'arm64' },
  { platform: 'linux', arch: 'x64', goos: 'linux', goarch: 'amd64' },
  { platform: 'win32', arch: 'x64', goos: 'windows', goarch: 'amd64' },
];

// Apache-2.0 section 4 requires these to travel with any redistribution, and a
// package containing a compiled binary is a redistribution — of this project
// and of everything statically linked into it.
const LEGAL = ['LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.txt'];

// Keep the tag acceptable to both npm's SemVer parser and Python's PEP 440
// normalizer. Build metadata is deliberately excluded: PyPI normalizes it
// differently, so the two registries would no longer expose the same version.
const RELEASE_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$/;

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  if (fallback !== undefined) return fallback;
  throw new Error(`missing --${name}`);
}

const version = arg('version');
const binaries = path.resolve(arg('binaries', 'dist/bin'));
const out = path.resolve(arg('out', 'dist/npm'));

if (!RELEASE_VERSION.test(version)) {
  throw new Error(`--version ${version} is not a registry-compatible SemVer version`);
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

function copyLegal(dir) {
  for (const file of LEGAL) {
    const from = path.join(root, file);
    if (!existsSync(from)) {
      throw new Error(`${file} is missing; a published binary must carry it`);
    }
    cpSync(from, path.join(dir, file));
  }
}

const published = [];

for (const target of TARGETS) {
  const name = `${SCOPE}/tls-forge-${target.platform}-${target.arch}`;
  const exe = target.platform === 'win32' ? 'tls-forge.exe' : 'tls-forge';
  const source = path.join(binaries, `tls-forge-${target.goos}-${target.goarch}${target.platform === 'win32' ? '.exe' : ''}`);
  if (!existsSync(source)) {
    throw new Error(`no binary at ${source}`);
  }

  const dir = path.join(out, `tls-forge-${target.platform}-${target.arch}`);
  mkdirSync(path.join(dir, 'bin'), { recursive: true });
  cpSync(source, path.join(dir, 'bin', exe));
  // cpSync preserves the mode, but a binary that arrives from an artifact
  // download may have lost its exec bit; npm packs the mode it finds.
  chmodSync(path.join(dir, 'bin', exe), 0o755);
  copyLegal(dir);

  writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify(
      {
        name,
        version,
        description: `tls-forge binary for ${target.platform}-${target.arch}`,
        // npm reads these and installs the package only where they match, which
        // is what keeps four of the five off any given machine.
        os: [target.platform],
        cpu: [target.arch],
        files: ['bin/', ...LEGAL],
        author: 'Ihar Kazlouski',
        license: 'Apache-2.0',
        repository: { type: 'git', url: 'git+https://github.com/Sec-CH-Lemon/tls-forge.git' },
      },
      null,
      2,
    ) + '\n',
  );

  writeFileSync(
    path.join(dir, 'README.md'),
    `# ${name}\n\n` +
      `The tls-forge binary for ${target.platform}-${target.arch}.\n\n` +
      'This package is not meant to be installed directly. Install\n' +
      '[`tls-forge`](https://www.npmjs.com/package/tls-forge), which depends on it\n' +
      'optionally and picks the one matching your machine.\n',
  );

  published.push({ name, dir });
}

// The main package: the JavaScript, and optional dependencies pinned to exactly
// this version. Pinned rather than ranged because a mismatch between the client
// and its binary is not something a range should be allowed to produce.
const mainDir = path.join(out, 'tls-forge');
mkdirSync(mainDir, { recursive: true });
for (const file of ['index.js', 'binary.js', 'README.md']) {
  cpSync(path.join(root, 'node', file), path.join(mainDir, file));
}
copyLegal(mainDir);

const manifest = JSON.parse(readFileSync(path.join(root, 'node', 'package.json'), 'utf8'));
manifest.version = version;
manifest.optionalDependencies = Object.fromEntries(
  TARGETS.map((t) => [`${SCOPE}/tls-forge-${t.platform}-${t.arch}`, version]),
);
// Scripts and dev-only fields have no meaning in the published tarball.
delete manifest.scripts;
writeFileSync(path.join(mainDir, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
published.push({ name: manifest.name, dir: mainDir });

for (const { name, dir } of published) {
  console.log(`${name}\t${dir}`);
}
