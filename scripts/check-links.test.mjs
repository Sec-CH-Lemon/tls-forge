import assert from 'node:assert/strict';
import { test } from 'node:test';

import { anchorsOf, linksOf, problems, slug } from './check-links.mjs';

test('a heading is the fragment GitHub makes of it', () => {
  for (const [heading, want] of [
    ['Where a request came out', 'where-a-request-came-out'],
    ['`fetch --output`: what a kept page is called', 'fetch---output-what-a-kept-page-is-called'],
    ['Logging a run', 'logging-a-run'],
    ['R06 Секреты и `--proxy-env`', 'r06-секреты-и---proxy-env'],
    ['The [init line](docs/protocol.md) and more', 'the-init-line-and-more'],
    ['snake_case stays, emoji 🎉 go', 'snake_case-stays-emoji--go'],
  ]) {
    assert.equal(slug(heading), want, heading);
  }
});

test('the anchors of a file are its headings, the repeated ones numbered', () => {
  const anchors = anchorsOf([
    '# Title',
    '## Usage',
    '```bash',
    '# a comment, not a heading',
    '```',
    '## Usage',
    '### Usage ##',
    '#not a heading',
  ].join('\n'));
  assert.deepEqual([...anchors].sort(), ['title', 'usage', 'usage-1', 'usage-2']);
});

test('the links of a file, inline and by reference, but not in code', () => {
  const links = linksOf([
    'See [the protocol](docs/protocol.md#the-init-line) and [Go](GO.md "the Go library").',
    'An image ![chart](docs/images/chart.png) and [angled](<docs/a b.md>).',
    '[ref]: example/README.md',
    '`[not a link](nowhere.md)` and',
    '```',
    '[nor this](nowhere.md)',
    '```',
  ].join('\n'));
  assert.deepEqual(links, [
    'docs/protocol.md#the-init-line', 'GO.md', 'docs/images/chart.png', 'docs/a b.md', 'example/README.md',
  ]);
});

test('a link to what git does not track, or to no heading, is a problem', () => {
  const docs = {
    'README.md': [
      '# Readme',
      '## Commands',
      '[changes](CHANGELOG.md) [protocol](docs/protocol.md#the-init-line) [here](#commands)',
      '[examples](example/) [a line](cmd/main.go:12) [web](https://example.com/x.md) [mail](mailto:a@b.c)',
      '[gone](RELEASING.md) [no heading](docs/protocol.md#no-such) [not here](#nowhere)',
      '[mine](/Users/me/notes.md) [a line of nothing](cmd/other.go:3)',
    ].join('\n'),
    'CHANGELOG.md': '# Changelog',
    'docs/protocol.md': '# The daemon protocol\n\n## The init line\n',
    'example/go/main.go': 'package main',
    'cmd/main.go': 'package main',
  };
  const found = problems(Object.keys(docs), (file) => docs[file]);
  assert.deepEqual(found, [
    'README.md: RELEASING.md names nothing git tracks',
    'README.md: docs/protocol.md#no-such names no heading of docs/protocol.md',
    'README.md: #nowhere names no heading of README.md',
    'README.md: /Users/me/notes.md is a path on one machine',
    'README.md: cmd/other.go:3 names nothing git tracks',
  ]);
});

test('a link relative to a file in a directory resolves from there', () => {
  const docs = {
    'docs/protocol.md': '[up](../GO.md#client-options) [beside](profiles.md) [lost](../nowhere.md)',
    'docs/profiles.md': '# Profiles',
    'GO.md': '# Go\n\n## Client options\n',
  };
  assert.deepEqual(problems(Object.keys(docs), (file) => docs[file]), [
    'docs/protocol.md: ../nowhere.md names nothing git tracks',
  ]);
});
