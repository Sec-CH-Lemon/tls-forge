#!/usr/bin/env node
// Every relative link in a Markdown file git tracks names a file git tracks, or
// a directory of them, and every #fragment a heading in the Markdown it points
// into. A link to a file kept out of git works in the checkout it was written
// in and nowhere else, which is why the files are git's and not the disk's.
// Links to the web are not followed.
//
//   node scripts/check-links.mjs

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// slug is a heading's fragment as GitHub makes it: lower case, its punctuation
// dropped but for hyphens and underscores, and each space a hyphen.
export function slug(heading) {
  return heading
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, '')
    .replace(/ /g, '-');
}

// withoutFences is markdown with its fenced blocks blanked out: a line in one
// that begins with # is a comment in a shell, and no heading.
function withoutFences(markdown) {
  return markdown.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, '');
}

// withoutCode is markdown without its code, fenced or inline, where a link is
// an example and not a link.
function withoutCode(markdown) {
  return withoutFences(markdown).replace(/`[^`\n]*`/g, '');
}

// anchorsOf are the fragments the headings of markdown make: the second of one
// slug is that slug with -1, the third with -2.
export function anchorsOf(markdown) {
  const seen = new Map();
  const anchors = new Set();
  for (const [, text] of withoutFences(markdown).matchAll(/^#{1,6}[ \t]+(.+?)[ \t#]*$/gm)) {
    const base = slug(text);
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  return anchors;
}

// linksOf are the targets markdown links to, inline and by reference.
export function linksOf(markdown) {
  const text = withoutCode(markdown);
  const targets = [];
  // A target in angle brackets may hold spaces; a bare one ends at the first.
  for (const [, angled, bare] of text.matchAll(/\]\(\s*(?:<([^>\n]+)>|([^)\s]+))(?:\s+"[^"]*")?\s*\)/g)) {
    targets.push(angled ?? bare);
  }
  for (const [, target] of text.matchAll(/^\s*\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+"[^"]*")?\s*$/gm)) targets.push(target);
  return targets;
}

// problems are what is wrong with each link of each file: files maps the path
// of every tracked file to a reader of it.
export function problems(files, read) {
  const tracked = new Set(files);
  const isDirectory = (dir) => files.some((file) => file.startsWith(`${dir}/`));
  const anchorCache = new Map();
  const anchors = (file) => {
    if (!anchorCache.has(file)) anchorCache.set(file, anchorsOf(read(file)));
    return anchorCache.get(file);
  };
  const found = [];
  for (const file of files.filter((name) => name.endsWith('.md'))) {
    for (const target of linksOf(read(file))) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      const [rawPath, fragment] = target.split('#', 2);
      const linked = rawPath.replace(/\?.*$/, '');
      if (linked.startsWith('/')) {
        found.push(`${file}: ${target} is a path on one machine`);
        continue;
      }
      let resolved = linked === '' ? file : path.posix.normalize(path.posix.join(path.posix.dirname(file), linked));
      resolved = resolved.replace(/\/$/, '');
      if (!tracked.has(resolved) && !isDirectory(resolved)) {
        // A line of a source file, as an editor links one: the file is what has
        // to be there.
        const withoutLine = resolved.replace(/:\d+$/, '');
        if (withoutLine === resolved || !tracked.has(withoutLine)) {
          found.push(`${file}: ${target} names nothing git tracks`);
          continue;
        }
      }
      if (fragment !== undefined && resolved.endsWith('.md') && !anchors(resolved).has(fragment)) {
        found.push(`${file}: ${target} names no heading of ${resolved}`);
      }
    }
  }
  return found;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
  const files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
  const found = problems(files, (file) => readFileSync(path.join(root, file), 'utf8'));
  for (const problem of found) console.error(problem);
  process.exit(found.length > 0 ? 1 : 0);
}
