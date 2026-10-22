// index.d.ts holds to what the package does: the names it exports, the
// client's methods, the options the constructor reads, the response it
// resolves to, and the request and browser context the Go daemon reads off
// the wire. example/typescript type-checks a program against the
// declarations; this keeps them from drifting from the code without a
// compiler.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import * as tlsforge from '../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (...parts) => readFileSync(path.join(here, '..', ...parts), 'utf8');
const declarations = read('index.d.ts');

// block is the body of the declaration that opens with head, whatever it
// extends, to its closing brace at the start of a line.
function block(source, head) {
  const opening = new RegExp(`^${head}(?: extends \\w+)? \\{$`, 'm').exec(source);
  assert.ok(opening, `no ${head}`);
  return source.slice(opening.index, source.indexOf('\n}', opening.index));
}

// fields are the names an interface declares, in order.
const fields = (name) => [...block(declarations, `export interface ${name}`).matchAll(/^ {2}(\w+)\??:/gm)]
  .map(([, field]) => field);

// union is the string literals a field of an interface may be.
function union(name, field) {
  const body = block(declarations, `export interface ${name}`);
  const start = body.search(new RegExp(`^ {2}${field}\\??:`, 'm'));
  const declared = body.slice(start, body.indexOf(';', start));
  return [...declared.matchAll(/'([^']+)'/g)].map(([, value]) => value).sort();
}

// goTags are the JSON names of a Go struct's fields.
const goTags = (source, struct) => [...block(source, `type ${struct} struct`).matchAll(/json:"(\w+)/g)]
  .map(([, tag]) => tag);

test('the declarations export what the package does, and nothing else', () => {
  const declared = [...declarations.matchAll(/^export (?:const|function|class) (\w+)/gm)].map(([, name]) => name);
  assert.deepEqual(declared.sort(), Object.keys(tlsforge).filter((name) => name !== 'default').sort());
  assert.match(declarations, /^export default Client;$/m);
  assert.equal(tlsforge.default, tlsforge.Client);
});

test('the declared classes extend what the runtime ones do', () => {
  // Structurally alike, the error classes would fit one another under any
  // hierarchy, so a compiler cannot tell: this does.
  const declared = [...declarations.matchAll(/^export class (\w+)(?: extends (\w+))? \{/gm)];
  const classes = Object.keys(tlsforge).filter((name) => /^[A-Z]/.test(name) && typeof tlsforge[name] === 'function');
  assert.deepEqual(declared.map(([, name]) => name).sort(), classes.sort());
  for (const [, name, parent] of declared) {
    const runtime = parent === undefined ? Function.prototype : parent === 'Error' ? Error : tlsforge[parent];
    assert.equal(Object.getPrototypeOf(tlsforge[name]), runtime, name);
  }
});

test('the declared client has the methods the runtime has', () => {
  const declared = [...block(declarations, 'export class Client').matchAll(/^ {2}(\w+)\(/gm)].map(([, name]) => name);
  assert.deepEqual(declared.sort(), Object.getOwnPropertyNames(tlsforge.Client.prototype).sort());
});

test('the declared options are the ones the constructor reads', () => {
  const source = read('index.js');
  const start = source.indexOf('  constructor(options = {}) {');
  assert.notEqual(start, -1, 'no constructor');
  const constructor = source.slice(start, source.indexOf('\n  }\n', start));
  const used = new Set([...constructor.matchAll(/options\.(\w+)/g)].map(([, name]) => name));
  assert.deepEqual(fields('ClientOptions').sort(), [...used].sort());
});

test('the declared response is the one the client resolves to, in order', () => {
  const normalise = block(read('index.js'), 'function normaliseResponse\\(response\\)');
  const built = [...normalise.matchAll(/^ {2}return \{ (.+) \};$/gm)].at(-1);
  assert.ok(built, 'normaliseResponse builds its response field by field');
  assert.deepEqual(fields('Response'), built[1].split(', ').map((field) => field.split(':')[0]));
});

test('the declared request is the wire request a caller sets, by its own names', () => {
  // Kept by the client: the line's id, how its body is encoded, a question
  // for the transport, and the proxy of an init line. Renamed: cookies go as
  // setCookie, a browser context as browser.
  const kept = ['id', 'bodyEncoding', 'control', 'proxy', 'engine_major'];
  const renamed = { setCookie: 'cookies', browser: 'browserContext' };
  const wire = goTags(read('..', 'daemon', 'daemon.go'), 'Request')
    .filter((tag) => !kept.includes(tag))
    .map((tag) => renamed[tag] ?? tag);
  assert.deepEqual([...fields('Request'), ...fields('RequestOptions')].sort(), wire.sort());
});

// constants are the string constants a Go source declares, by name.
const constants = (source) => Object.fromEntries(
  [...source.matchAll(/^\t(\w+) += "([^"]*)"/gm)].map(([, name, value]) => [name, value]),
);

// listed are the values of the constants a Go list names, sorted.
function listed(source, list) {
  const named = list.exec(source);
  assert.ok(named, String(list));
  const values = constants(source);
  return named[1].split(/[\s,]+/).filter(Boolean).map((name) => values[name]).sort();
}

test('the declared browser context is the one the daemon reads, value for value', () => {
  assert.deepEqual(fields('BrowserContext'), goTags(read('..', 'daemon', 'daemon.go'), 'BrowserContext'));
  const browser = read('..', 'browser.go');
  const kinds = [...browser.matchAll(/^\tKind\w+ RequestKind = "([^"]+)"/gm)].map(([, kind]) => kind).sort();
  assert.deepEqual(union('BrowserContext', 'kind'), kinds);
  assert.deepEqual(union('BrowserContext', 'referrerPolicy'),
    listed(read('..', 'site.go'), /^var referrerPolicies = \[\]string\{([^}]*)\}/m));
  assert.deepEqual(union('BrowserContext', 'mode'), listed(browser, /\[\]string\{([^}]*)\}, r\.mode\)/));
  assert.deepEqual(union('BrowserContext', 'credentials'),
    listed(browser, /\[\]string\{([^}]*)\}, r\.credentials\)/));
});
