// tls-forge — an HTTP client for Node whose TLS fingerprint is a real browser's.
//
// Node cannot do this on its own. Its TLS comes from OpenSSL, which exposes no
// control over extension order, GREASE values or the extension set — and those
// are precisely what JA3 and JA4 hash. Chrome uses BoringSSL. So the socket
// moves out of Node into a small Go process and Node keeps the orchestration,
// which is the part it is good at.
//
// One Client is one long-lived process, and that is deliberate: it means one
// TLS fingerprint, one cookie jar and one exit IP for the whole session.
// Reconnecting per request is itself a signal — no browser does it.

import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { resolveBinary } from './binary.js';

/** @typedef {{status:number,url:string,body:string,content:Buffer,headers:Record<string,string[]>,cookies:string[]}} Response */

const DEFAULT_TIMEOUT_MS = 45_000;

function normaliseResponse(response) {
  if (response.error != null && typeof response.error !== 'string') {
    throw new TypeError('field "error" must be a string');
  }

  const status = response.status ?? 0;
  const url = response.url ?? '';
  let body = response.body ?? '';
  const bodyEncoding = response.bodyEncoding ?? '';
  const rawHeaders = response.headers ?? {};
  const cookies = response.cookies ?? [];

  if (!Number.isInteger(status)) throw new TypeError('field "status" must be an integer');
  if (typeof url !== 'string') throw new TypeError('field "url" must be a string');
  if (typeof body !== 'string') throw new TypeError('field "body" must be a string');
  if (typeof bodyEncoding !== 'string') {
    throw new TypeError('field "bodyEncoding" must be a string');
  }

  // A JSON string cannot hold arbitrary bytes, so a body that is not valid
  // UTF-8 arrives as base64 and is decoded here. `content` is always the bytes
  // exactly as they came back; `body` is the text view, lossy by definition for
  // a body that is not text.
  let content;
  if (bodyEncoding === '' || bodyEncoding === 'utf8') {
    content = Buffer.from(body, 'utf8');
  } else if (bodyEncoding === 'base64') {
    content = Buffer.from(body, 'base64');
    if (content.toString('base64').replace(/=+$/, '') !== body.replace(/=+$/, '')) {
      throw new TypeError('field "body" is not valid base64');
    }
    body = content.toString('utf8');
  } else {
    throw new TypeError(`unknown bodyEncoding "${bodyEncoding}"`);
  }
  if (rawHeaders === null || typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) {
    throw new TypeError('field "headers" must be an object');
  }
  if (!Array.isArray(cookies) || cookies.some((cookie) => typeof cookie !== 'string')) {
    throw new TypeError('field "cookies" must be an array of strings');
  }

  const headers = {};
  for (const [name, values] of Object.entries(rawHeaders)) {
    // Accept one release of the old scalar protocol during upgrades while
    // exposing the lossless array shape to callers consistently.
    if (typeof values === 'string') headers[name] = [values];
    else if (Array.isArray(values) && values.every((value) => typeof value === 'string')) {
      headers[name] = [...values];
    } else {
      throw new TypeError(`header "${name}" must be a string or an array of strings`);
    }
  }

  return { ...response, status, url, body, content, headers, cookies: [...cookies] };
}

export class Client {
  #binary;
  #args;
  #timeout;
  #onStderr;

  #process = null;
  #reader = null;
  #queue = [];
  #inFlight = null;

  // Never reset, not even across a restart. An id must never name two different
  // requests on one client, or a late answer from the process we killed can
  // match the request that replaced it — the exact crossing the id exists to
  // prevent.
  #sequence = 0;

  // close() is final. A client is one identity; once it has been given up there
  // is no identity left to make requests with, so a later request is a caller
  // bug and should say so rather than quietly minting a new process with a new
  // fingerprint and an empty jar.
  #closed = false;

  /**
   * @param {object}  [options]
   * @param {string}  [options.profile]  profile to impersonate, e.g. "chrome"
   * @param {string}  [options.proxy]    http:// or socks5:// proxy URL
   * @param {number}  [options.timeout]  per-request deadline in ms
   * @param {string}  [options.binary]   path to the tlsforge binary
   * @param {boolean} [options.insecure] skip certificate verification
   * @param {(line:string)=>void} [options.onStderr] receives the process's stderr
   */
  constructor(options = {}) {
    const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeout) || timeout <= 0) {
      throw new RangeError('tlsforge: timeout must be a positive finite number');
    }
    if (options.onStderr !== undefined && typeof options.onStderr !== 'function') {
      throw new TypeError('tlsforge: onStderr must be a function');
    }
    this.#binary = resolveBinary(options.binary);
    this.#timeout = timeout;
    this.#onStderr = options.onStderr ?? (() => {});

    const args = ['daemon'];
    if (options.profile) args.push('--profile', options.profile);
    if (options.proxy) args.push('--proxy', options.proxy);
    if (options.insecure) args.push('--insecure');
    // The Go side gets a longer deadline than Node's on purpose. If they were
    // equal, a request timing out would race: both sides would decide it failed,
    // and the process would be killed while writing the answer.
    args.push('--timeout', `${Math.ceil((this.#timeout + 15_000) / 1000)}s`);
    this.#args = args;
  }

  /**
   * GET a URL.
   * @param {string} url
   * @param {object} [options]
   * @param {Record<string,string>} [options.headers] layered over the profile's
   * @param {string[]} [options.order] header order; defaults to the profile's
   * @param {string[]} [options.cookies] "name=value" pairs to seed the jar
   * @returns {Promise<Response>}
   */
  get(url, options = {}) {
    return this.request({ ...options, url, method: 'GET' });
  }

  /**
   * POST a body. A Buffer or Uint8Array is sent as base64, so a body that is
   * not text arrives intact.
   * @param {string} url
   * @param {string|Buffer|Uint8Array} body
   * @param {object} [options]
   * @returns {Promise<Response>}
   */
  post(url, body, options = {}) {
    return this.request({ ...options, url, body, method: 'POST' });
  }

  /**
   * Make a request.
   * @param {{url:string,method?:string,headers?:Record<string,string>,order?:string[],body?:string|Buffer|Uint8Array,cookies?:string[]}} request
   * @returns {Promise<Response>}
   */
  request(request) {
    if (!request?.url) return Promise.reject(new Error('tlsforge: request needs a url'));
    if (this.#closed) {
      return Promise.reject(
        new Error('tlsforge: this client was closed and will not respawn; construct a new one'),
      );
    }
    const { cookies, ...rest } = request;
    const id = ++this.#sequence;
    const payload = { ...rest, setCookie: cookies, id };
    // Bytes travel as base64: JSON.stringify would otherwise turn a Buffer into
    // an object of numbered keys, and the transport replaces every byte that is
    // not valid UTF-8 with U+FFFD rather than reporting a problem.
    if (payload.body != null && typeof payload.body !== 'string') {
      if (!ArrayBuffer.isView(payload.body)) {
        return Promise.reject(
          new TypeError('tlsforge: request body must be a string, Buffer or Uint8Array'),
        );
      }
      payload.body = Buffer.from(
        payload.body.buffer,
        payload.body.byteOffset,
        payload.body.byteLength,
      ).toString('base64');
      payload.bodyEncoding = 'base64';
    }
    let line;
    try {
      line = JSON.stringify(payload) + '\n';
    } catch (err) {
      // A circular object or BigInt is a caller error. Serialise before the job
      // enters the queue so a failed JSON.stringify cannot leave #inFlight set
      // until its timeout and hold every request behind it.
      return Promise.reject(
        new TypeError(`tlsforge: request cannot be encoded as JSON: ${err.message}`),
      );
    }
    return new Promise((resolve, reject) => {
      this.#queue.push({
        line,
        id,
        resolve,
        reject,
      });
      this.#pump();
    });
  }

  /** Shut the process down and settle everything outstanding. */
  close() {
    this.#closed = true;
    this.#kill();
    this.#failAll(new Error('tlsforge: client closed'));
  }

  // --- internals ---------------------------------------------------------

  #start() {
    // Defensive: this is the ONLY reference to the previous process's stdout,
    // and overwriting it without closing is how a reader outlives its process —
    // which then keeps delivering that process's buffered lines, and one
    // request's page resolves another request's promise.
    this.#closeReader();

    const process = spawn(this.#binary, this.#args, { stdio: ['pipe', 'pipe', 'pipe'] });
    this.#process = process;
    this.#reader = readline.createInterface({ input: process.stdout });
    this.#reader.on('line', (line) => this.#onLine(line));
    process.stderr.on('data', (chunk) => this.#reportStderr(String(chunk).trimEnd()));

    // A process that could not be spawned reports through 'error', not 'exit',
    // and an 'error' with no listener is an uncaught exception that takes the
    // whole program down rather than the one request. The reachable causes are
    // ordinary: a binary without its exec bit, a Linux binary in a macOS
    // checkout, a directory mounted noexec.
    process.on('error', (err) => {
      // Node documents that exit may still follow error. Detach it before a
      // caller can start a replacement process, or the old exit could clear
      // the new process reference.
      process.removeAllListeners('exit');
      this.#process = null;
      this.#closeReader();
      this.#failAll(new Error(`tlsforge: transport failed to start (${this.#binary}): ${err.message}`));
    });

    // Writing to a pipe whose reader is gone raises EPIPE, and an EPIPE on a
    // stream with no 'error' listener is another uncaught exception. The
    // rejection is NOT done here — the write callback in #pump knows which
    // request was being written, and this handler does not.
    process.stdin.on('error', this.#reportStderr.bind(this));

    process.on('exit', (code) => {
      this.#process = null;
      this.#closeReader();
      this.#failAll(new Error(`tlsforge: transport exited (code ${code})`));
    });
  }

  #closeReader() {
    if (!this.#reader) return;
    // close() alone is documented to stop 'line'. The listener is removed
    // explicitly as well, because this guard exists precisely because a reader
    // was once believed detached when it was not.
    this.#reader.removeAllListeners('line');
    this.#reader.close();
    this.#reader = null;
  }

  #kill() {
    if (!this.#process) return;
    const process = this.#process;
    this.#process = null;
    process.removeAllListeners('exit');
    process.removeAllListeners('error');
    process.stderr.removeAllListeners('data');
    this.#closeReader();
    // Descendants can inherit the pipe handles and outlive the daemon. Destroy
    // our ends explicitly so those descendants cannot keep Node alive until
    // they happen to exit.
    process.stdin.destroy();
    process.stdout.destroy();
    process.stderr.destroy();
    process.kill();
  }

  #restart() {
    this.#kill();
    this.#pump();
  }

  #failAll(error) {
    const job = this.#inFlight;
    this.#inFlight = null;
    if (job) {
      // The deadline timer has to go with the job: an armed timer is a live
      // handle, and a live handle keeps Node's event loop open, so a program
      // that has finished its work sits idle until the deadline expires.
      clearTimeout(job.timer);
      job.reject(error);
    }
    while (this.#queue.length) this.#queue.shift().reject(error);
  }

  #onLine(line) {
    let response;
    try {
      response = JSON.parse(line);
      // `null`, `7` and `[]` are all valid JSON and none can carry an id, so
      // they are garbage in the same sense an unparseable line is. Reading .id
      // off a bare null throws, and a throw out of a readline handler is an
      // uncaught exception — the one failure this file exists to avoid.
      if (response === null || typeof response !== 'object' || Array.isArray(response)) {
        throw new Error(`expected an object, got ${line.slice(0, 40)}`);
      }
    } catch (err) {
      // A line that is not a response cannot be attributed to anything: the id
      // lives inside the thing that failed to parse. The in-flight request pays
      // for it, because a stream producing garbage is desynchronised, and
      // waiting for it to right itself is how a client goes quiet forever.
      const job = this.#inFlight;
      if (!job) return;
      this.#inFlight = null;
      clearTimeout(job.timer);
      job.reject(new Error(`tlsforge: bad response: ${err.message}`));
      this.#pump();
      return;
    }

    const job = this.#inFlight;
    if (!job || response.id !== job.id) {
      // Not an error: this is the abandoned answer arriving, the normal
      // aftermath of a timeout.
      this.#reportStderr(
        `dropping answer for request ${response.id ?? '(none)'}, ` +
          (job ? `waiting on ${job.id}` : 'nothing is outstanding'),
      );
      return;
    }

    try {
      response = normaliseResponse(response);
    } catch (err) {
      this.#inFlight = null;
      clearTimeout(job.timer);
      job.reject(new Error(`tlsforge: bad response: ${err.message}`));
      this.#pump();
      return;
    }

    this.#inFlight = null;
    clearTimeout(job.timer);
    if (response.error) job.reject(new Error(response.error));
    else job.resolve(response);
    this.#pump();
  }

  #reportStderr(line) {
    try {
      this.#onStderr(String(line));
    } catch {
      // Diagnostics supplied by the caller must not crash transport handling.
    }
  }

  #pump() {
    // No check for #closed here, deliberately. request() rejects while closed
    // so nothing new is ever queued, and close() empties the queue, so the two
    // conditions this would test for cannot hold at once. The three callers are
    // request(), settle() and restart(); the last two run from callbacks that
    // return early once close() has cleared the job they were waiting on.
    if (this.#inFlight || !this.#queue.length) return;
    if (!this.#process) {
      try {
        this.#start();
      } catch (err) {
        // spawn throws synchronously for a malformed argv rather than emitting
        // 'error'. Unhandled, the throw escapes request(), which returns a
        // promise everywhere else — so the caller's catch would miss it.
        this.#failAll(new Error(`tlsforge: transport failed to start (${this.#binary}): ${err.message}`));
        return;
      }
    }

    const job = this.#queue.shift();
    this.#inFlight = job;
    job.timer = setTimeout(() => {
      this.#inFlight = null;
      job.reject(new Error('tlsforge: request timed out'));
      // The process is still working on this request — its own deadline is
      // longer — so an answer is not merely possible, it is expected.
      // Restarting stops it at the source, dropping the reader stops one
      // already written, and the id means that even if both of those failed the
      // stale line is discarded instead of handed to whoever asks next.
      this.#restart();
    }, this.#timeout);

    this.#process.stdin.write(job.line, (err) => {
      if (!err || this.#inFlight !== job) return;
      // The process can die between the liveness check above and the write
      // reaching the pipe.
      this.#inFlight = null;
      clearTimeout(job.timer);
      job.reject(new Error(`tlsforge: write failed: ${err.message}`));
      this.#restart();
    });
  }
}

export { resolveBinary } from './binary.js';
export default Client;
