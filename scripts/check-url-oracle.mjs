#!/usr/bin/env node
// Explicit WHATWG reference check. Ordinary Go tests only read the fixture.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { values } = parseArgs({ options: {
  browser: { type: 'string' }, output: { type: 'string' }, help: { type: 'boolean' },
} });
if (values.help) {
  console.log('Usage: node scripts/check-url-oracle.mjs [--browser CHROME] [--output PRIVATE_DIRECTORY]\nChecks the pinned Node/Ada fixture; --browser also checks two fresh headless Chrome URL constructors. No navigation or external origin requests.');
  process.exit(0);
}
process.umask(0o077);
const source = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../testdata/whatwg-url-components.json'));
const fixture = JSON.parse(source);
if (process.versions.node !== fixture.oracle.node || process.versions.ada !== fixture.oracle.ada) {
  throw Error(`Oracle version differs: require Node ${fixture.oracle.node}/Ada ${fixture.oracle.ada}; got ${process.versions.node}/${process.versions.ada}`);
}
function evaluate(cases) {
  return cases.map(c => {
    let u;
    try { u = new URL(c.input, c.base); } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      return { invalid: true };
    }
    u.hash = '';
    const canonical = u.href;
    const bytes = s => btoa(s.replace(/%([a-f0-9]{2})/gi, (_, x) => String.fromCharCode(parseInt(x, 16))));
    return { canonical, scheme: u.protocol.slice(0, -1), authority: u.host,
      target: canonical.slice(canonical.indexOf('/', u.protocol.length + 2)),
      username: u.username, password: u.password,
      username_bytes: bytes(u.username), password_bytes: bytes(u.password) };
  });
}
const expected = fixture.cases.map(c => c.expected);
function check(actual, actor) {
  if (!isDeepStrictEqual(actual, expected)) {
    const ids = fixture.cases.filter((_, i) => !isDeepStrictEqual(actual[i], expected[i])).map(c => c.id);
    throw Error(`${actor}: URL fixture drift in ${ids.join(', ')}`);
  }
}
check(evaluate(fixture.cases), 'Node/Ada');
if (values.output) mkdirSync(values.output, { recursive: false, mode: 0o700 });
const report = { node: process.versions.node, ada: process.versions.ada, cases: fixture.cases.length,
  fixture_sha256: createHash('sha256').update(source).digest('hex'), chrome: [], scope: fixture.scope };
if (values.browser) {
  const version = spawnSync(values.browser, ['--version'], { encoding: 'utf8', timeout: 10000 });
  if (version.status !== 0) throw Error('Cannot read Chrome version');
  for (let cohort = 1; cohort <= 2; cohort++) {
    const dir = mkdtempSync(path.join(tmpdir(), 'tls-forge-url-oracle-'));
    try {
      const code = `document.body.textContent=JSON.stringify({ua:navigator.userAgent,results:(${evaluate.toString()})(${JSON.stringify(fixture.cases)})})`.replaceAll('</', '<\\/');
      const html = '<body><script>' + code + '</script>';
      const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => k.toLowerCase() !== 'sslkeylogfile'));
      const run = spawnSync(values.browser, ['--headless=new', '--no-first-run', '--no-default-browser-check',
        '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions',
        '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND', '--user-data-dir=' + dir,
        '--dump-dom', 'data:text/html;charset=utf-8,' + encodeURIComponent(html)],
      { encoding: 'utf8', env, timeout: 30000, maxBuffer: 2e6 });
      if (values.output) writeFileSync(path.join(values.output, `chrome-${cohort}.log`), run.stderr ?? '');
      if (run.status !== 0) throw Error(`Chrome cohort ${cohort} failed: ${run.status} ${run.error ?? ''}`);
      const content = run.stdout.match(/<body>([\s\S]*?)<\/body>/)?.[1];
      if (!content) throw Error('Chrome returned no body');
      const actual = JSON.parse(content.replace(/<script>[\s\S]*?<\/script>/g, '')
        .replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&'));
      if (values.output) writeFileSync(path.join(values.output, `chrome-${cohort}.json`), JSON.stringify(actual, null, 2) + '\n');
      check(actual.results, 'Chrome cohort ' + cohort);
      report.chrome.push({ cohort, version: version.stdout.trim(), ua: actual.ua, matched: true });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}
if (values.output) writeFileSync(path.join(values.output, 'result.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report));
