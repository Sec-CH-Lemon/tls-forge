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
import { readFileSync } from 'node:fs';
export const ENGINE_MAJOR = Number(JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version.split('.')[0]);
import { resolveBinary } from './binary.js';
import { RequestFailed, SessionReset, Timeout, TransportError, Unsupported } from './errors.js';

/** @typedef {{status:number,url:string,body:string,content:Buffer,headers:Record<string,string[]>,cookies:string[]}} Response */

const DEFAULT_TIMEOUT_MS = 45_000;

// The most a request can be as the transport reads it: one line of JSON, its
// newline included, in UTF-8. A longer one would end the transport, and the
// session in it, so it is refused before it is queued.
export const MAX_REQUEST_BYTES = 16 * 1024 * 1024;

// What a transport is, as its answer to hello says. One older than control
// lines answers it as a request with no url: protocol 1, nothing it can do.
function helloOf(response) {
  if (response.error != null) return { protocol: 1, capabilities: [] };
  const { protocol, capabilities = [] } = response;
  if (
    !Number.isInteger(protocol) ||
    protocol < 2 ||
    !Array.isArray(capabilities) ||
    !capabilities.every((name) => typeof name === 'string')
  ) {
    throw new TypeError(
      `hello must give a protocol from 2 and a list of capabilities, not ${JSON.stringify({ protocol, capabilities })}`,
    );
  }
  const { engine_major, version } = response;
  return { protocol, capabilities: [...capabilities], engine_major, version };
}
function checkEngine(hello) {
 const {protocol, engine_major, version}=hello;
 if (protocol < 3 || !Number.isSafeInteger(engine_major) || engine_major < 0 || engine_major !== ENGINE_MAJOR ||
     typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version) || Number(version.split('.')[0]) !== engine_major) {
  throw new Unsupported(`tlsforge: daemon engine_major ${JSON.stringify(engine_major) ?? 'missing'} (version ${version ?? 'missing'}, protocol ${protocol}) is incompatible with SDK engine major ${ENGINE_MAJOR}; request was not sent`);
 }
}


// The keys of a browser context, as the protocol names them.
const CONTEXT_KEYS = ['kind', 'initiator', 'referrerPolicy', 'mode', 'credentials'];

// contextProblem is why a browser context cannot be sent, or undefined: one
// that is no object, or has a key the protocol does not, is a mistake in the
// call, said before anything is asked.
function contextProblem(context) {
  if (typeof context !== 'object' || Array.isArray(context)) {
    return 'tlsforge: browserContext must be an object';
  }
  const unknown = Object.keys(context).find((key) => !CONTEXT_KEYS.includes(key));
  if (unknown !== undefined) {
    return `tlsforge: browserContext has no key "${unknown}"; it takes ${CONTEXT_KEYS.join(', ')}`;
  }
  return undefined;
}

// refusedArguments is why a transport that exited at once with a usage error
// failed. With a proxy, that is a tls-forge older than this package, which
// does not know --proxy-stdin; it never got as far as making a request.
function refusedArguments(binary, proxied) {
  const said = `tlsforge: the transport at ${binary} refused its arguments (code 2)`;
  if (!proxied) return said;
  return (
    `${said}: a tls-forge older than this package does not know --proxy-stdin, which keeps ` +
    'the proxy\'s password off its command line and out of its environment; use the tls-forge this ' +
    'package came with'
  );
}

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

  // The fields it documents, and no other: what else the line carries, its id
  // and how its body was encoded among them, and what a newer transport adds,
  // is the protocol's, not the caller's.
  return { status, url, body, content, headers, cookies: [...cookies] };
}

export class Client {
  #binary;
  #args;
  #proxy;
  #timeout;
  #onStderr;

  #process = null;
  #reader = null;
  #stderrReader = null;
  #queue = [];
  #inFlight = null;

  // Never reset, not even across a restart. An id must never name two different
  // requests on one client, or a late answer from the process we killed can
  // match the request that replaced it — the exact crossing the id exists to
  // prevent.
  #sequence = 0;

  // Why the transport the session was in went, until a request has been told
  // with SessionReset; null when nothing is to be told.
  #lost = null;

  // close() is final. A client is one identity; once it has been given up there
  // is no identity left to make requests with, so a later request is a caller
  // bug and should say so rather than quietly minting a new process with a new
  // fingerprint and an empty jar.
  #closed = false;

  // The transport's answer to hello, asked once: what a binary is does not
  // change between its processes.
  #hello = null;

  /**
   * @param {object}  [options]
   * @param {string}  [options.profile]  profile to impersonate, e.g. "chrome"
   * @param {string}  [options.proxy]    http:// or socks5:// proxy URL
   * @param {number}  [options.timeout]  per-request deadline in ms
   * @param {string}  [options.binary]   path to the tlsforge binary
   * @param {boolean} [options.insecure] skip certificate verification
   * @param {string}  [options.cookieFile] warmed cookie file (`--cookies`)
   * @param {string}  [options.cookieSet] set in that file; random when omitted
   * @param {(line:string)=>void} [options.onStderr] receives stderr one line at a time
   */
  constructor(options = {}) {
    const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(timeout) || timeout <= 0) {
      throw new RangeError('tlsforge: timeout must be a positive finite number');
    }
    if (options.onStderr !== undefined && typeof options.onStderr !== 'function') {
      throw new TypeError('tlsforge: onStderr must be a function');
    }
    if (options.cookieSet && !options.cookieFile) {
      throw new TypeError('tlsforge: cookieSet requires cookieFile');
    }
    this.#binary = resolveBinary(options.binary);
    this.#timeout = timeout;
    this.#onStderr = options.onStderr ?? (() => {});

    const args = ['daemon'];
    if (options.profile) args.push('--profile', options.profile);
    // The proxy goes on the transport's input, in the first line it reads:
    // `ps` shows a command line, password and all, to every user of the
    // machine, and the environment is the process's owner's to read.
    if (options.proxy) args.push('--proxy-stdin');
    this.#proxy = options.proxy || undefined;
    if (options.insecure) args.push('--insecure');
    if (options.cookieFile) args.push('--cookies', options.cookieFile);
    if (options.cookieSet) args.push('--cookie-set', options.cookieSet);
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
   * What the transport is: the protocol it speaks and what it can do, asked
   * without a connection and once. One older than the question speaks
   * protocol 1, and can do nothing a client has to ask about.
   * @returns {Promise<{protocol:number,capabilities:string[]}>}
   */
  hello() {
    if (this.#closed) {
      return Promise.reject(
        new TransportError('tlsforge: this client was closed and will not respawn; construct a new one'),
      );
    }
    this.#hello ??= this.#enqueue({ control: 'hello' }, true)
      .then((response) => {
        try {
          return helloOf(response);
        } catch (err) {
          throw new TransportError(`tlsforge: bad response: ${err.message}`, { cause: err });
        }
      })
      .catch((err) => {
        // Asked again next time: a transport that failed to answer has not
        // said what it is.
        this.#hello = null;
        throw err;
      });
    return this.#hello.then((identity) => ({ ...identity, capabilities: [...identity.capabilities] }));
  }

  /**
   * Make a request.
   *
   * A request with a browserContext is sent only to a transport that says,
   * when asked with hello(), that it applies one, and to no other: it is
   * refused with Unsupported rather than sent as though it had none. The
   * first such request waits for that answer, and a request made after it
   * may go first.
   * @param {{url:string,method?:string,headers?:Record<string,string>,order?:string[],body?:string|Buffer|Uint8Array,cookies?:string[],browserContext?:object}} request
   * @returns {Promise<Response>}
   */
  request(request) {
    if (!request?.url) return Promise.reject(new TypeError('tlsforge: request needs a url'));
    if (this.#closed) {
      return Promise.reject(
        new TransportError('tlsforge: this client was closed and will not respawn; construct a new one'),
      );
    }
    const { browserContext, ...asked } = request;
    // null is none, as it is to the daemon.
    const refused = browserContext == null ? undefined : contextProblem(browserContext);
    if (refused) return Promise.reject(new TypeError(refused));
    return this.hello().then((identity) => {
      checkEngine(identity);
      const { protocol, capabilities } = identity;
      if (browserContext != null && !capabilities.includes('browser_context')) {
        throw new Unsupported(
          `tlsforge: the tls-forge at ${this.#binary} speaks protocol ${protocol} and does not apply ` +
            'browser contexts; the request was not sent',
        );
      }
      return this.#send(browserContext == null ? asked : { ...asked, browser: browserContext });
    });
  }

  // send queues a request, its wire fields named as the protocol names them.
  #send(request) {
    const { cookies, ...rest } = request;
    return this.#enqueue({ ...rest, setCookie: cookies, engine_major: ENGINE_MAJOR }, false);
  }

  // enqueue writes fields as one line, with an id of its own, once the lines
  // before it are answered; control is a question for the transport, whose
  // answer is handed back as it came rather than read as a page.
  #enqueue(fields, control) {
    const id = ++this.#sequence;
    const payload = { ...fields, id };
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
    // Measured as it is written: base64 and the newline included. The
    // transport cannot read a longer line, and stops at one.
    const size = Buffer.byteLength(line);
    if (size > MAX_REQUEST_BYTES) {
      return Promise.reject(
        new RangeError(
          `tlsforge: this request is ${size} bytes as the transport reads it, ` +
            `more than the ${MAX_REQUEST_BYTES} it can: send a smaller body`,
        ),
      );
    }
    return new Promise((resolve, reject) => {
      this.#queue.push({
        line,
        id,
        control,
        resolve,
        reject,
        // The call's deadline, from now: the time a request waits for the one
        // before it is part of it.
        deadline: performance.now() + this.#timeout,
      });
      this.#pump();
    });
  }

  /** Shut the process down and settle everything outstanding. */
  close() {
    this.#closed = true;
    this.#kill();
    this.#failAll(new TransportError('tlsforge: client closed'));
  }

  // --- internals ---------------------------------------------------------

  #start() {
    // Defensive: this is the ONLY reference to the previous process's stdout,
    // and overwriting it without closing is how a reader outlives its process —
    // which then keeps delivering that process's buffered lines, and one
    // request's page resolves another request's promise.
    this.#closeReaders();

    const child = spawn(this.#binary, this.#args, { stdio: ['pipe', 'pipe', 'pipe'] });
    this.#process = child;
    this.#reader = readline.createInterface({ input: child.stdout });
    this.#reader.on('line', (line) => this.#onLine(line));
    this.#stderrReader = readline.createInterface({ input: child.stderr });
    this.#stderrReader.on('line', (line) => this.#reportStderr(line));

    // The request timer is the reference that keeps Node alive while work is
    // outstanding. The idle daemon and its pipes must not force every script to
    // call close() merely to let the event loop finish.
    child.unref();
    child.stdin.unref();
    child.stdout.unref();
    child.stderr.unref();

    // A process that could not be spawned reports through 'error', not 'exit',
    // and an 'error' with no listener is an uncaught exception that takes the
    // whole program down rather than the one request. The reachable causes are
    // ordinary: a binary without its exec bit, a Linux binary in a macOS
    // checkout, a directory mounted noexec.
    child.on('error', (err) => {
      // Node documents that exit may still follow error. Detach it before a
      // caller can start a replacement process, or the old exit could clear
      // the new process reference.
      child.removeAllListeners('exit');
      this.#process = null;
      this.#closeReaders();
      this.#failAll(
        new TransportError(`tlsforge: transport failed to start (${this.#binary}): ${err.message}`, { cause: err }),
      );
    });

    // Writing to a pipe whose reader is gone raises EPIPE, and an EPIPE on a
    // stream with no 'error' listener is another uncaught exception. The
    // rejection is NOT done here — the write callback in #pump knows which
    // request was being written, and this handler does not.
    child.stdin.on('error', this.#reportStderr.bind(this));

    child.on('exit', (code) => {
      this.#process = null;
      this.#closeReaders();
      if (code === 2) {
        // A usage error: the transport would not take the arguments it was
        // started with, and every replacement would refuse them the same way.
        // No request reached it, so none of them is indeterminate.
        this.#failAll(new TransportError(refusedArguments(this.#binary, this.#proxy !== undefined)));
        return;
      }
      // Only the request written to the dead transport is indeterminate. The
      // jobs still in the queue were never written, and are told the session
      // they were made in has gone.
      this.#lost = `it exited (code ${code})`;
      this.#hello = null;
      this.#failInFlight(new TransportError(`tlsforge: transport exited (code ${code})`));
      this.#pump();
    });
  }

  // initJob is the line a transport started with a proxy is told it in,
  // first. Until it is answered without an error there is no session: an
  // error, the deadline, a garbled line, a failed write or an exit stops the
  // transport, loses no session, and fails every request waiting with why.
  #initJob() {
    const id = ++this.#sequence;
    const unstarted = (err) => {
      this.#kill();
      // No session started, so none was lost.
      this.#lost = null;
      this.#failAll(err);
    };
    return {
      id,
      init: true,
      control: true,
      line: JSON.stringify({ id, control: 'init', proxy: this.#proxy, engine_major: ENGINE_MAJOR }) + '\n',
      deadline: performance.now() + this.#timeout,
      resolve: (response) => {
        if (response.error == null) return;
        unstarted(new TransportError(`tlsforge: the transport did not take its proxy: ${response.error}`));
      },
      reject: unstarted,
    };
  }

  #closeReaders() {
    // close() alone is documented to stop 'line'. The listener is removed
    // explicitly as well, because this guard exists precisely because a reader
    // was once believed detached when it was not.
    for (const name of ['#reader', '#stderrReader']) {
      const reader = name === '#reader' ? this.#reader : this.#stderrReader;
      if (!reader) continue;
      reader.removeAllListeners('line');
      reader.close();
    }
    this.#reader = null;
    this.#stderrReader = null;
  }

  #kill() {
    if (!this.#process) return;
    const process = this.#process;
    this.#process = null;
    process.removeAllListeners('exit');
    process.removeAllListeners('error');
    this.#closeReaders();
    // Descendants can inherit the pipe handles and outlive the daemon. Destroy
    // our ends explicitly so those descendants cannot keep Node alive until
    // they happen to exit.
    process.stdin.destroy();
    process.stdout.destroy();
    process.stderr.destroy();
    process.kill();
  }

  // restart stops a transport that has a session in it, which is lost.
  #restart(why) {
    this.#kill();
    this.#lost = why;
    this.#hello = null;
    this.#pump();
  }

  #failAll(error) {
    this.#failInFlight(error);
    while (this.#queue.length) this.#queue.shift().reject(error);
  }

  #failInFlight(error) {
    const job = this.#inFlight;
    this.#inFlight = null;
    if (!job) return;
    // The deadline timer has to go with the job: an armed timer is a live
    // handle, and a live handle keeps Node's event loop open.
    clearTimeout(job.timer);
    job.reject(error);
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
      job.reject(new TransportError(`tlsforge: bad response: ${err.message}`, { cause: err }));
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

    if (job.control) {
      this.#inFlight = null;
      clearTimeout(job.timer);
      job.resolve(response);
      this.#pump();
      return;
    }

    let page;
    try {
      page = normaliseResponse(response);
    } catch (err) {
      this.#inFlight = null;
      clearTimeout(job.timer);
      job.reject(new TransportError(`tlsforge: bad response: ${err.message}`, { cause: err }));
      this.#pump();
      return;
    }

    this.#inFlight = null;
    clearTimeout(job.timer);
    if (response.error) job.reject(new RequestFailed(response.error));
    else job.resolve(page);
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
    if (this.#lost !== null && this.#queue.some((job) => !job.control)) {
      // Told, all of them, and not sent: each was made in a session that has
      // gone, and none of them would be what the caller asked for in a new one.
      // A question for the transport was made in no session, and goes on.
      const reset = new SessionReset(
        `tlsforge: the transport this client's session was in has gone (${this.#lost}), ` +
          'and with it its cookies, TLS sessions and connections; this request was not sent, ' +
          'and the next one starts a new session',
      );
      this.#lost = null;
      const told = this.#queue.filter((job) => !job.control);
      this.#queue = this.#queue.filter((job) => job.control);
      for (const job of told) job.reject(reset);
      if (!this.#queue.length) return;
    }
    if (!this.#process) {
      try {
        this.#start();
        if (this.#proxy !== undefined) this.#queue.unshift(this.#initJob());
      } catch (err) {
        // spawn throws synchronously for a malformed argv rather than emitting
        // 'error'. Unhandled, the throw escapes request(), which returns a
        // promise everywhere else — so the caller's catch would miss it.
        this.#failAll(
          new TransportError(`tlsforge: transport failed to start (${this.#binary}): ${err.message}`, { cause: err }),
        );
        return;
      }
    }

    const job = this.#queue.shift();
    this.#inFlight = job;
    // What is left of its deadline, which a request in front of it can only
    // have used part of: that one's deadline came first, and ended it.
    job.timer = setTimeout(() => {
      this.#inFlight = null;
      job.reject(new Timeout('tlsforge: request timed out'));
      // The process is still working on this request — its own deadline is
      // longer — so an answer is not merely possible, it is expected.
      // Restarting stops it at the source, dropping the reader stops one
      // already written, and the id means that even if both of those failed the
      // stale line is discarded instead of handed to whoever asks next. An
      // init line that timed out stopped a transport that had no session.
      if (!job.init) this.#restart('a request timed out, and it was stopped');
    }, job.deadline - performance.now());

    this.#process.stdin.write(job.line, (err) => {
      if (!err || this.#inFlight !== job) return;
      // The process can die between the liveness check above and the write
      // reaching the pipe.
      this.#inFlight = null;
      clearTimeout(job.timer);
      job.reject(new TransportError(`tlsforge: write failed: ${err.message}`, { cause: err }));
      if (!job.init) this.#restart(`a request could not be written to it: ${err.message}`);
    });
  }
}

export { resolveBinary } from './binary.js';
export {
  BinaryNotFound,
  RequestFailed,
  SessionReset,
  TLSForgeError,
  Timeout,
  TransportError,
  Unsupported,
} from './errors.js';
export default Client;
