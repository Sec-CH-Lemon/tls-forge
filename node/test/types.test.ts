// The package's types are written in its sources, and the compiler holds the
// code and the declarations it emits to them. What it cannot hold them to is
// held here: the options the constructor reads, the response it resolves to,
// in order, and the request and browser context the Go daemon reads off the
// wire. example/typescript type-checks a program against the declarations as
// a caller sees them; compile.test.ts holds them to what the package exports.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (...parts: string[]) => readFileSync(path.join(here, '..', ...parts), 'utf8');
const source = read('src', 'index.ts');

// block is the body of the declaration that opens with head, whatever it
// extends, to its closing brace at the start of a line.
function block(source: string, head: string): string {
  const opening = new RegExp(`^${head}(?: extends \\w+)? \\{$`, 'm').exec(source);
  assert.ok(opening, `no ${head}`);
  return source.slice(opening.index, source.indexOf('\n}', opening.index));
}

// fields are the names an interface declares, in order.
const fields = (name: string) => [...block(source, `export interface ${name}`).matchAll(/^ {2}(\w+)\??:/gm)]
  .map(([, field]) => field);

// union is the string literals a field of an interface may be.
function union(name: string, field: string): string[] {
  const body = block(source, `export interface ${name}`);
  const start = body.search(new RegExp(`^ {2}${field}\\??:`, 'm'));
  const declared = body.slice(start, body.indexOf(';', start));
  return [...declared.matchAll(/'([^']+)'/g)].map(([, value]) => value).sort();
}

// goTags are the JSON names of a Go struct's fields.
const goTags = (go: string, struct: string) => [...block(go, `type ${struct} struct`).matchAll(/json:"(\w+)/g)]
  .map(([, tag]) => tag);

test('the declared options are the ones the constructor reads', () => {
  const start = source.indexOf('  constructor(options: ClientOptions = {}) {');
  assert.notEqual(start, -1, 'no constructor');
  const constructor = source.slice(start, source.indexOf('\n  }\n', start));
  const used = new Set([...constructor.matchAll(/options\.(\w+)/g)].map(([, name]) => name));
  assert.deepEqual(fields('ClientOptions').sort(), [...used].sort());
});

test('the declared response is the one the client resolves to, in order', () => {
  const normalise = block(source, 'function normaliseResponse\\(response: Answer\\): Response');
  const built = [...normalise.matchAll(/^ {2}return \{ (.+) \};$/gm)].at(-1);
  assert.ok(built, 'normaliseResponse builds its response field by field');
  assert.deepEqual(fields('Response'), built[1]!.split(', ').map((field) => field.split(':')[0]));
});

test('the declared request is the wire request a caller sets, by its own names', () => {
  // Kept by the client: the line's id, how its body is encoded, a question
  // for the transport, and the proxy of an init line. Renamed: cookies go as
  // setCookie, a browser context as browser.
  const kept = ['id', 'bodyEncoding', 'control', 'proxy', 'engine_major'];
  const renamed: Record<string, string> = { setCookie: 'cookies', browser: 'browserContext', network: 'networkContext' };
  const wire = goTags(read('..', 'daemon', 'daemon.go'), 'Request')
    .filter((tag) => !kept.includes(tag))
    .map((tag) => renamed[tag] ?? tag);
  assert.deepEqual([...fields('Request'), ...fields('RequestOptions')].sort(), wire.sort());
});

// constants are the string constants a Go source declares, by name.
const constants = (go: string): Record<string, string> => Object.fromEntries(
  [...go.matchAll(/^\t(\w+) += "([^"]*)"/gm)].map(([, name, value]) => [name, value]),
);

// listed are the values of the constants a Go list names, sorted.
function listed(go: string, list: RegExp): string[] {
  const named = list.exec(go);
  assert.ok(named, String(list));
  const values = constants(go);
  return named[1]!.split(/[\s,]+/).filter(Boolean).map((name) => values[name]!).sort();
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

test('the declared network context is the one the daemon reads, value for value', () => {
  const go = read('..', 'networkquality', 'context.go');
  assert.deepEqual(fields('NetworkContext'), goTags(go, 'Context'));
  const names = /var connectionTypes = \[\]string\{([^}]+)\}/.exec(go);
  assert.ok(names);
  const types = [...names[1]!.matchAll(/"([^"]+)"/g)].map(([, name]) => name).sort();
  assert.deepEqual(union('NetworkContext', 'type'), types);
  // And the client refuses any other, by the same list.
  const refused = /^const CONNECTION_TYPES: readonly NetworkContext\['type'\]\[\] = \[([^\]]+)\];$/m.exec(source);
  assert.ok(refused, 'the client checks a connection type against a list of its own');
  assert.deepEqual([...refused[1]!.matchAll(/'([^']+)'/g)].map(([, name]) => name).sort(), types);
});
