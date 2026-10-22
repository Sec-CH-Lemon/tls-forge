#!/usr/bin/env node
// macOS, Node >= 20, Google Chrome and Wireshark. No npm dependencies.
// node scripts/chrome-first-get.mjs [--interface any] [--timeout 45] [URL] [NEW_DIRECTORY]
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import {
  accessSync, appendFileSync, closeSync, constants, existsSync, mkdirSync,
  mkdtempSync, openSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';

const defaultURL = 'https://www.lowes.com/pd/CRAFTSMAN-20-volt-Max-1-2-in-Keyless-Brushless-Cordless-Drill-1-Batteries-Included-Soft-Bag-Included/5016412045';
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { interface: { type: 'string', default: 'any' }, timeout: { type: 'string', default: '45' }, help: { type: 'boolean' } },
});
if (values.help) {
  console.log(`Usage: node scripts/chrome-first-get.mjs [--interface any] [--timeout 45] [URL] [NEW_DIRECTORY]
Defaults: the Lowe's drill URL; a new directory in the system temporary directory.
Requires macOS, Node >= 20, Google Chrome and Wireshark (tshark, editcap).
CHROME, TSHARK, EDITCAP and TCPDUMP may name alternative executables.
The default interface 'any' requires sudo for tcpdump only; Chrome runs as you.
On an interface such as en0, Wireshark's ChmodBPF may allow capture without sudo.
Outputs: first-get.pcapng (embedded TLS keys), first-get.txt (full packet trees
and hex), request.txt (GET packet trees), tls.keys, metadata.json and capture.log.
The private output directory must not exist. Redirects and page resources are blocked.
Chrome uses a fresh profile, a visible window and a direct connection; QUIC is left enabled.`);
  process.exit(0);
}

process.umask(0o077);
if (process.platform !== 'darwin') throw new Error('This script is for macOS.');
if (process.getuid() === 0) throw new Error('Run as your normal user, not with sudo. Only tcpdump may need sudo.');
if (positionals.length > 2) throw new Error('Expected at most URL and NEW_DIRECTORY; see --help.');
const url = new URL(positionals[0] ?? defaultURL);
if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
  throw new Error('Use an HTTPS URL without credentials or a fragment.');
}
const seconds = Number(values.timeout);
if (!Number.isFinite(seconds) || seconds < 1 || seconds > 600) throw new Error('--timeout must be 1..600 seconds.');

function executable(env, name, extra = []) {
  const candidates = process.env[env] ? [process.env[env]] : [
    ...process.env.PATH.split(path.delimiter).map(p => path.join(p, name)), ...extra,
  ];
  for (const candidate of candidates) {
    try { accessSync(candidate, constants.X_OK); return candidate; } catch {}
  }
  throw new Error(`Cannot find ${name}. Install Google Chrome / Wireshark or set ${env}.`);
}
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024, timeout: 120_000, ...options });
  if (result.error || result.status !== 0) {
    throw new Error(`${path.basename(command)}: ${result.error?.message ?? result.stderr ?? `exit ${result.status}`}`);
  }
  return result.stdout;
}
const chrome = executable('CHROME', 'google-chrome', ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']);
const tshark = executable('TSHARK', 'tshark', ['/Applications/Wireshark.app/Contents/MacOS/tshark']);
const editcap = executable('EDITCAP', 'editcap', ['/Applications/Wireshark.app/Contents/MacOS/editcap']);
const tcpdump = executable('TCPDUMP', 'tcpdump', ['/usr/sbin/tcpdump']);
let needsSudo = values.interface === 'any';
try { accessSync('/dev/bpf0', constants.R_OK | constants.W_OK); } catch { needsSudo = true; }
if (needsSudo) run('/usr/bin/sudo', ['-v'], { stdio: 'inherit' });

const out = positionals[1] ? path.resolve(positionals[1]) : mkdtempSync(path.join(tmpdir(), 'chrome-first-get-'));
if (positionals[1]) mkdirSync(out, { mode: 0o700 }); // Deliberately refuses an existing directory.
const scratch = mkdtempSync(path.join(out, '.working-'));
const allKeys = path.join(scratch, 'all.keys');
const raw = path.join(scratch, 'wire.pcap');
const selected = path.join(scratch, 'connection.pcapng');
const captureLog = path.join(out, 'capture.log');
const meta = { url: url.href, started: new Date().toISOString(), platform: process.platform,
  interface: values.interface, timeoutSeconds: seconds, freshProfile: true, direct: true,
  blockedRequests: [], responseComplete: false };
const saveMeta = () => writeFileSync(path.join(out, 'metadata.json'), JSON.stringify(meta, null, 2) + '\n');
let browser, capture, cdp, captureExited;
let interrupted = false;
const onSignal = () => { interrupted = true; };
process.on('SIGINT', onSignal);
process.on('SIGTERM', onSignal);

// Chrome's native debugging pipe uses fd 3 for input, fd 4 for output and
// NUL-delimited JSON. It needs neither an open debugging port nor npm packages.
function debuggingPipe(child) {
  let next = 0, buffer = '', handler = () => {};
  const pending = new Map();
  child.stdio[4].setEncoding('utf8');
  child.stdio[4].on('data', chunk => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf('\0')) !== -1) {
      const message = JSON.parse(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      if (message.id) {
        const waiting = pending.get(message.id);
        if (!waiting) continue;
        pending.delete(message.id);
        clearTimeout(waiting.timer);
        if (message.error) waiting.reject(new Error(JSON.stringify(message.error)));
        else waiting.resolve(message.result);
      } else handler(message);
    }
  });
  const disconnected = () => {
    for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new Error('Chrome debugging pipe closed')); }
    pending.clear();
  };
  child.stdio[3].on('error', disconnected);
  child.stdio[4].on('end', disconnected);
  return {
    onEvent(fn) { handler = fn; },
    send(method, params = {}, sessionId) {
      return new Promise((resolve, reject) => {
        const id = ++next;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Timed out: ${method}`)); }, seconds * 1000);
        pending.set(id, { resolve, reject, timer });
        child.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
      });
    },
  };
}

async function closeBrowser() {
  if (!browser || browser.exitCode !== null || browser.signalCode !== null) return;
  const exited = once(browser, 'exit');
  void cdp?.send('Browser.close').catch(() => {});
  if (await Promise.race([exited.then(() => true), delay(3000, undefined, { ref: false }).then(() => false)])) return;
  browser.kill('SIGTERM');
  if (await Promise.race([exited.then(() => true), delay(2000, undefined, { ref: false }).then(() => false)])) return;
  browser.kill('SIGKILL');
  await exited;
}
async function stopCapture() {
  if (!capture || capture.exitCode !== null || capture.signalCode !== null) return;
  if (needsSudo) run('/usr/bin/sudo', ['-n', '/bin/kill', '-INT', String(capture.pid)]);
  else capture.kill('SIGINT');
  if (!await Promise.race([captureExited.then(() => true), delay(5000, undefined, { ref: false }).then(() => false)])) {
    throw new Error(`tcpdump did not stop (PID ${capture.pid}); private raw capture retained in ${scratch}`);
  }
}

try {
  console.log(`Output: ${out}\nCapturing before Chrome starts...`);
  writeFileSync(raw, ''); // Keep the file owned by the caller even when tcpdump is root.
  const captureArgs = ['-i', values.interface, '-s', '0', '-U', '--immediate-mode', '-w', raw,
    `tcp port ${url.port || 443} or udp port ${url.port || 443}`];
  capture = spawn(needsSudo ? '/usr/bin/sudo' : tcpdump, needsSudo ? ['-n', tcpdump, ...captureArgs] : captureArgs,
    { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, LC_ALL: 'C' } });
  captureExited = once(capture, 'exit');
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('tcpdump did not become ready; see capture.log')), 10_000);
    let text = '';
    capture.stderr.on('data', data => {
      appendFileSync(captureLog, data);
      text += data.toString();
      if (text.includes('listening on')) { clearTimeout(timer); resolve(); }
    });
    capture.once('error', error => { clearTimeout(timer); reject(error); });
    capture.once('exit', () => { clearTimeout(timer); reject(new Error('tcpdump exited; see capture.log')); });
  });

  const chromeArgs = [`--user-data-dir=${path.join(scratch, 'profile')}`, '--remote-debugging-pipe',
    `--ssl-key-log-file=${allKeys}`, '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--no-proxy-server', 'about:blank'];
  meta.chromeExecutable = chrome;
  meta.chromeArguments = chromeArgs;
  const chromeLog = openSync(path.join(scratch, 'chrome.log'), 'w', 0o600);
  try { browser = spawn(chrome, chromeArgs, { stdio: ['ignore', 'ignore', chromeLog, 'pipe', 'pipe'] }); }
  finally { closeSync(chromeLog); }
  browser.on('error', error => { meta.browserError = error.message; });
  cdp = debuggingPipe(browser);
  meta.browser = await cdp.send('Browser.getVersion');
  meta.tshark = run(tshark, ['--version']).split('\n')[0];
  const { targetInfos } = await cdp.send('Target.getTargets');
  const page = targetInfos.find(t => t.type === 'page' && t.url === 'about:blank');
  if (!page) throw new Error('Chrome did not open its blank page.');
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: page.targetId, flatten: true });
  let allowed = false, finished = false;
  let eventWork = Promise.resolve();
  cdp.onEvent(message => {
    if (message.sessionId !== sessionId || message.method !== 'Fetch.requestPaused') return;
    eventWork = eventWork.then(async () => {
      const p = message.params;
      if (p.responseStatusCode !== undefined || p.responseErrorReason !== undefined) {
        meta.response = { status: p.responseStatusCode, headers: p.responseHeaders, error: p.responseErrorReason };
        // Leave the response paused: no document, scripts or redirect can run.
        // getResponseBody drains the response without releasing it to the page.
        if (p.responseStatusCode && !(p.responseStatusCode >= 300 && p.responseStatusCode < 400)) {
          try {
            const body = await cdp.send('Fetch.getResponseBody', { requestId: p.requestId }, sessionId);
            writeFileSync(path.join(out, 'response.body'), Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8'));
            meta.responseComplete = true;
          } catch (error) { meta.responseBodyError = error.message; }
        }
        finished = true;
      } else if (!allowed && p.resourceType === 'Document' && p.request.method === 'GET' && p.request.url === url.href) {
        allowed = true;
        meta.request = p.request;
        await cdp.send('Fetch.continueRequest', { requestId: p.requestId }, sessionId);
      } else {
        meta.blockedRequests.push({ method: p.request.method, url: p.request.url });
        await cdp.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'Aborted' }, sessionId);
      }
    }).catch(error => { meta.browserError = error.message; finished = true; });
  });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Fetch.enable', { patterns: [
    { urlPattern: '*', requestStage: 'Request' }, { urlPattern: '*', requestStage: 'Response' },
  ] }, sessionId);
  console.log(`Chrome: ${meta.browser.product}\nAllowing one GET: ${url.href}`);
  void cdp.send('Page.navigate', { url: url.href, transitionType: 'typed' }, sessionId)
    .catch(error => { meta.navigationError = error.message; });
  const deadline = Date.now() + seconds * 1000;
  while (!finished && !interrupted && Date.now() < deadline && browser.exitCode === null && capture.exitCode === null) await delay(100);
  if (!finished) meta.stopped = interrupted ? 'interrupted' : 'timeout or child process exited';
  await closeBrowser();
  await eventWork;
  await delay(300);
  await stopCapture();
  const drops = readFileSync(captureLog, 'utf8').match(/(\d+) packets dropped by kernel/);
  meta.captureDrops = drops ? Number(drops[1]) : null;
  if (meta.captureDrops > 0) throw new Error(`tcpdump dropped ${meta.captureDrops} packets; raw capture retained.`);

  if (!existsSync(allKeys) || !readFileSync(allKeys, 'utf8').trim()) throw new Error('Chrome wrote no TLS keys; raw capture retained.');
  const quotedURL = JSON.stringify(url.href);
  const match = `((http.request.method == "GET" && http.request.full_uri == ${quotedURL}) || ` +
    `(http2.headers.method == "GET" && http2.request.full_uri == ${quotedURL}) || ` +
    `(http3.headers.method == "GET" && http3.request.full_uri == ${quotedURL}))`;
  const decode = ['-n', '-2', '-r', raw, '-o', `tls.keylog_file:${allKeys}`];
  const hits = run(tshark, [...decode, '-Y', match, '-T', 'fields', '-E', 'occurrence=f',
    '-e', 'frame.number', '-e', 'tcp.stream', '-e', 'udp.stream', '-e', 'quic.connection.number']).trim().split('\n').filter(Boolean);
  if (hits.length !== 1) throw new Error(`Expected exactly one decoded GET to this URL; found ${hits.length}. Raw capture retained in ${scratch}`);
  const [frame, tcp, udp, quic] = hits[0].split('\t');
  const connection = tcp ? `tcp.stream == ${Number(tcp)}` : quic ? `quic.connection.number == ${Number(quic)}` : `udp.stream == ${Number(udp)}`;
  meta.originalFrame = Number(frame);
  meta.originalConnectionFilter = connection;
  // Keep the whole connection, including SYN / ClientHello / H2 settings and
  // HPACK or QPACK state. A GET-only packet file would not be self-contained.
  run(tshark, [...decode, '-Y', connection, '-F', 'pcapng', '-w', selected]);
  const randoms = new Set(run(tshark, [...decode, '-Y', `(${connection}) && tls.handshake.type == 1`,
    '-T', 'fields', '-e', 'tls.handshake.random']).trim().split(/[\s,]+/).filter(Boolean).map(v => v.replaceAll(':', '').toLowerCase()));
  const keys = readFileSync(allKeys, 'utf8').split('\n').filter(line => randoms.has(line.trim().split(/\s+/)[1]?.toLowerCase()));
  if (!keys.length) throw new Error('Cannot associate TLS keys with the captured ClientHello; raw capture retained.');
  const keyFile = path.join(out, 'tls.keys');
  writeFileSync(keyFile, keys.join('\n') + '\n');
  const final = path.join(out, 'first-get.pcapng');
  run(editcap, ['--inject-secrets', `tls,${keyFile}`, selected, final]);
  const finalDecode = ['-n', '-2', '-r', final]; // Verify embedded keys, without the external key log.
  const verified = run(tshark, [...finalDecode, '-Y', match, '-T', 'fields', '-e', 'frame.number']).trim().split('\n').filter(Boolean);
  if (verified.length !== 1) throw new Error('The final pcapng does not decrypt to exactly one matching GET.');
  const requests = run(tshark, [...finalDecode, '-Y', 'http.request || http2.headers.method || http3.headers.method',
    '-T', 'fields', '-e', 'frame.number', '-e', 'http.request.method', '-e', 'http2.headers.method', '-e', 'http3.headers.method']).trim().split('\n').filter(Boolean);
  if (requests.length !== 1 || requests[0].split('\t').filter(Boolean).join(' ') !== `${verified[0]} GET`) {
    throw new Error('Additional HTTP requests were decoded on the selected connection; raw capture retained.');
  }
  for (const [name, args] of [['first-get.txt', ['-V', '-x']], ['request.txt', ['-Y', match, '-V']]]) {
    const fd = openSync(path.join(out, name), 'w', 0o600);
    try { run(tshark, [...finalDecode, ...args], { stdio: ['ignore', fd, 'pipe'] }); }
    finally { closeSync(fd); }
  }
  meta.finished = new Date().toISOString();
  meta.decodedGETs = verified.length;
  meta.files = {};
  for (const name of ['first-get.pcapng', 'first-get.txt', 'request.txt', 'tls.keys']) {
    meta.files[name] = { sha256: createHash('sha256').update(readFileSync(path.join(out, name))).digest('hex') };
  }
  saveMeta();
  rmSync(scratch, { recursive: true }); // Background packets, keys and the temporary profile stay out of the result.
  console.log(`Done: ${final}\nReadable GET: ${path.join(out, 'request.txt')}\nFull packet details: ${path.join(out, 'first-get.txt')}`);
  if (!meta.responseComplete) console.log('The GET was verified; response body is incomplete or was a redirect (see metadata.json).');
} catch (error) {
  meta.error = error.message;
  saveMeta();
  console.error(`ERROR: ${error.message}\nDiagnostics: ${out}`);
  process.exitCode = 1;
} finally {
  await closeBrowser().catch(error => console.error(error.message));
  await stopCapture().catch(error => console.error(error.message));
}
