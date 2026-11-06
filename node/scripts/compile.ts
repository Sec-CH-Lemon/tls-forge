#!/usr/bin/env node
// Compile the package's TypeScript into the JavaScript and declarations it is
// published as.
//
//   node scripts/compile.ts [--out DIR]
//
// DIR, dist/ of the package when omitted, is emptied first: tsc writes what
// the sources make and leaves the rest, so a module that went would stay in it
// and be published. The sources import one another by their own names,
// ./binary.ts, as Node runs them; tsc writes those as .js in the JavaScript,
// and as they were in the declarations, which TypeScript before 5.0 cannot
// read. They are written as .js there too, as every TypeScript reads them.

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// A relative module a declaration names by its source's name.
const SOURCE_NAMED = /(\bfrom\s+|\bimport\s*\(\s*)(['"])(\.\.?\/[^'"]+)\.ts\2/g;

// compile compiles the package into out, emptied first, and returns the names
// of the files written. out may be dist/ or a directory outside the package,
// and nothing else: emptying the package, what holds it or another directory
// in it would take its own files. tsc is the compiler's script, the one
// installed in the package's node_modules when omitted.
export function compile(out: string, { tsc }: { tsc?: string } = {}): string[] {
  const target = path.resolve(out);
  if (within(target, root) || (within(root, target) && !within(path.join(root, 'dist'), target))) {
    throw new Error(`will not compile into ${target}: emptying it would take the package's own files`);
  }
  const compiler = tsc ?? installedCompiler();
  rmSync(target, { recursive: true, force: true });
  const run = spawnSync(process.execPath, [compiler, '-p', path.join(root, 'tsconfig.build.json'), '--outDir', target], {
    cwd: root,
    encoding: 'utf8',
  });
  if (run.status !== 0) {
    throw new Error(`compiling the package failed:\n${run.stdout}${run.stderr}`.trimEnd());
  }
  const files = readdirSync(target).sort();
  for (const name of files.filter((file) => file.endsWith('.d.ts'))) {
    const file = path.join(target, name);
    const declared = readFileSync(file, 'utf8');
    writeFileSync(
      file,
      declared.replace(SOURCE_NAMED, (_, keyword: string, quote: string, module: string) => `${keyword}${quote}${module}.js${quote}`),
    );
  }
  return files;
}

// within says whether dir is parent or below it.
function within(parent: string, dir: string): boolean {
  const below = path.relative(parent, dir);
  return below === '' || (below !== '..' && !below.startsWith(`..${path.sep}`) && !path.isAbsolute(below));
}

// installedCompiler is the script of the TypeScript the lockfile of the
// package at at pins, as `npm ci` there installs it.
export function installedCompiler(at = root): string {
  try {
    return createRequire(path.join(at, 'package.json')).resolve('typescript/bin/tsc');
  } catch (err) {
    throw new Error(`TypeScript is not installed in ${at}: run npm ci there first`, { cause: err });
  }
}

// outOf is the directory a command line names, dist/ when it names none.
export function outOf(args: string[]): string {
  const at = args.indexOf('--out');
  if (at < 0) return path.join(root, 'dist');
  const out = args[at + 1];
  if (!out) throw new Error('--out needs a directory');
  return path.resolve(out);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const out = outOf(process.argv.slice(2));
    console.log(`tls-forge: compiled ${compile(out).length} files into ${out}`);
  } catch (err) {
    console.error(`tls-forge: ${(err as Error).message}`);
    process.exit(1);
  }
}
