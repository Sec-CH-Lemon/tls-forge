// The package as it is published: what scripts/compile.ts makes of the
// sources, laid out as package.json says, and that it is the package the
// sources are. A module left out of dist/ is missing where the package is
// installed, and a declaration naming a source no caller has is one their
// TypeScript cannot read.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { compile, installedCompiler, outOf } from '../scripts/compile.ts';
import * as tlsforge from '../src/index.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
// This file's extension: .ts as it is written, .js compiled in place, which
// the script it runs is too.
const extension = path.extname(fileURLToPath(import.meta.url));
const script = path.join(root, 'scripts', `compile${extension}`);

// scratch is a directory of the test's own, gone after it.
function scratch(t: TestContext): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tls-forge-compile-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// published lays the package out in a directory of the test's own as it is
// published: its manifest, and what compiling it makes, in dist/.
function published(t: TestContext): { dir: string; files: string[] } {
  const dir = scratch(t);
  copyFileSync(path.join(root, 'package.json'), path.join(dir, 'package.json'));
  return { dir, files: compile(path.join(dir, 'dist')) };
}

// relative is every module a compiled file names by a relative path.
const relative = (source: string) =>
  [...source.matchAll(/(?:\bfrom\s+|\bimport\s*\(\s*)['"](\.\.?\/[^'"]+)['"]/g)].map(([, name]) => name!);

test('the package compiles into dist/, each source a module and its declarations', (t) => {
  const { dir, files } = published(t);
  const sources = readdirSync(path.join(root, 'src')).filter((name) => name.endsWith('.ts')).sort();
  assert.deepEqual(files, sources.flatMap((name) => [name.replace(/\.ts$/, '.d.ts'), name.replace(/\.ts$/, '.js')]).sort());
  // Every module a file names is one of them, by the name it is published
  // as: none is left out, and none is named by its source.
  for (const file of files) {
    const named = relative(readFileSync(path.join(dir, 'dist', file), 'utf8'));
    for (const name of named) {
      assert.match(name, /^\.\/[\w-]+\.js$/, `${file} names ${name}`);
      assert.ok(files.includes(name.slice(2)), `${file} names ${name}, which is not compiled`);
    }
    if (file.startsWith('index.')) assert.ok(named.length > 0, `${file} names no module`);
  }
});

test('package.json publishes dist/ and points at the modules in it', (t) => {
  const { dir, files } = published(t);
  const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.ok(manifest.files.includes('dist/'));
  assert.equal(manifest.main, './dist/index.js');
  assert.equal(manifest.types, './dist/index.d.ts');
  assert.deepEqual(manifest.exports, { '.': { types: './dist/index.d.ts', default: './dist/index.js' } });
  for (const file of [manifest.main, manifest.types]) {
    assert.ok(files.includes(path.basename(file)), file);
    assert.ok(existsSync(path.join(dir, file)), file);
  }
});

test('the compiled package is the package the sources are', async (t) => {
  const { dir } = published(t);
  const compiled = await import(pathToFileURL(path.join(dir, 'dist', 'index.js')).href);
  const exported = (module: object) =>
    Object.entries(module).map(([name, value]) => [name, typeof value === 'function' ? `function ${value.name}` : value]);
  assert.deepEqual(exported(compiled), exported(tlsforge));
  assert.equal(compiled.default, compiled.Client);
  // Its version read from the manifest beside dist/, as it is installed.
  assert.equal(compiled.ENGINE_MAJOR, Number(JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version.split('.')[0]));
});

test('the declarations name every value the package exports, with the doc comments the reference reads', (t) => {
  const { dir } = published(t);
  const read = (name: string) => readFileSync(path.join(dir, 'dist', name), 'utf8');
  const index = read('index.d.ts');
  const declared = [...index.matchAll(/^export declare (?:const|function|class) (\w+)/gm)].map(([, name]) => name!);
  for (const [, names, from] of index.matchAll(/^export \{ ([^}]+) \} from '\.\/([\w-]+)\.js';$/gm)) {
    const module = read(`${from}.d.ts`);
    for (const name of names!.split(', ')) {
      assert.match(module, new RegExp(`^export declare (?:const|function|class) ${name}\\b`, 'm'), `${from} declares ${name}`);
      declared.push(name);
    }
  }
  assert.deepEqual(declared.sort(), Object.keys(tlsforge).filter((name) => name !== 'default').sort());
  assert.match(index, /^export default Client;$/m);
  assert.match(index, /\/\*\* One browser identity:(?:(?!\*\/)[\s\S])*\*\/\nexport declare class Client \{/);
  assert.match(index, /@throws \{BinaryNotFound\} no transport binary was found/);
});

test('it compiles only into dist/ or a directory outside the package', (t) => {
  const outside = scratch(t);
  for (const out of [root, path.dirname(root), path.join(root, 'src'), path.join(root, 'src', 'deeper'), path.join(root, 'test'), path.join(root, 'node_modules')]) {
    assert.throws(() => compile(out, { tsc: path.join(outside, 'never-run.js') }), {
      message: `will not compile into ${out}: emptying it would take the package's own files`,
    });
  }
  // Refused before anything went.
  assert.ok(existsSync(path.join(root, 'src', 'index.ts')));
  assert.ok(existsSync(path.join(root, 'test', 'compile.test.ts')));
});

test('a compiler that fails is said, with what it said', (t) => {
  const dir = scratch(t);
  const out = path.join(dir, 'out');
  mkdirSync(out);
  writeFileSync(path.join(out, 'stale.js'), 'gone');
  const failing = path.join(dir, 'tsc.js');
  writeFileSync(failing, "process.stdout.write('error TS1: out\\n'); process.stderr.write('and err\\n'); process.exit(2);");
  assert.throws(() => compile(out, { tsc: failing }), { message: 'compiling the package failed:\nerror TS1: out\nand err' });
  // Emptied first, whatever followed.
  assert.ok(!existsSync(path.join(out, 'stale.js')));
});

test("the compiler is the one the package's lockfile installed", (t) => {
  // As Node resolves it, links and all.
  assert.equal(installedCompiler(), realpathSync(path.join(root, 'node_modules', 'typescript', 'bin', 'tsc')));
  const bare = scratch(t);
  writeFileSync(path.join(bare, 'package.json'), '{"name":"bare","version":"0.0.0"}');
  assert.throws(() => installedCompiler(bare), (err: Error) => {
    assert.equal(err.message, `TypeScript is not installed in ${bare}: run npm ci there first`);
    assert.ok(err.cause instanceof Error);
    return true;
  });
});

test('the command line names its directory, dist/ when it names none', () => {
  assert.equal(outOf([]), path.join(root, 'dist'));
  assert.equal(outOf(['--out', 'somewhere']), path.resolve('somewhere'));
  assert.throws(() => outOf(['--out']), { message: '--out needs a directory' });
  assert.throws(() => outOf(['--out', '']), { message: '--out needs a directory' });
});

test('the command compiles, and says why it did not', (t) => {
  const out = path.join(scratch(t), 'dist');
  const run = (...args: string[]) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  const compiled = run('--out', out);
  assert.equal(compiled.status, 0, compiled.stderr);
  // Two of each source: its module and its declarations.
  const sources = readdirSync(path.join(root, 'src')).filter((name) => name.endsWith('.ts')).length;
  assert.equal(compiled.stdout, `tls-forge: compiled ${sources * 2} files into ${out}\n`);
  assert.ok(existsSync(path.join(out, 'index.d.ts')));
  for (const [args, says] of [
    [['--out'], 'tls-forge: --out needs a directory\n'],
    [['--out', root], `tls-forge: will not compile into ${root}: emptying it would take the package's own files\n`],
  ] as [string[], string][]) {
    const refused = run(...args);
    assert.equal(refused.status, 1, args.join(' '));
    assert.equal(refused.stderr, says);
    assert.equal(refused.stdout, '');
  }
});
