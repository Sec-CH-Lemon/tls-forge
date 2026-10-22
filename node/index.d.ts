// Types for the tls-forge package: what index.js, binary.js and errors.js do
// at run time, and no more. node/test/types.test.js holds the names here to
// what the package exports, and example/typescript type-checks a program
// against them.

/// <reference types="node" />

/** The most a request can be, in bytes, as the transport reads it: one line of
 * JSON, its newline included, in UTF-8. A longer one is refused with a
 * RangeError before it is queued. */
export const MAX_REQUEST_BYTES: number;

/** How a client is made. Each option is passed to `tls-forge daemon`. */
export interface ClientOptions {
  /** The profile to impersonate, by name or as a JSON profile path. */
  profile?: string;
  /** An HTTP, HTTPS or SOCKS proxy URL, optionally with credentials. It
   * reaches the transport on its input, never on its command line. */
  proxy?: string;
  /** The deadline of each request, in milliseconds, counted from the call.
   * Positive and finite, else a RangeError; 45000 when omitted. */
  timeout?: number;
  /** The path of the transport binary, used as given. */
  binary?: string;
  /** Skip upstream certificate verification. */
  insecure?: boolean;
  /** A warmed cookie file, as `--cookies` reads one. */
  cookieFile?: string;
  /** A set in that file; one at random when omitted. Needs `cookieFile`. */
  cookieSet?: string;
  /** Receives the transport's standard error, a line at a time. */
  onStderr?: (line: string) => void;
}

/** What in a browser a request stands for: it goes out as Chrome sends that
 * kind, CORS and all. See GO.md, «Browser contexts». */
export interface BrowserContext {
  /** What sends the request. */
  kind: 'navigation' | 'form' | 'fetch' | 'xhr';
  /** The URL of the page that sends it. A form, fetch() and an XHR need one;
   * a navigation without one is typed into the address bar. */
  initiator?: string;
  /** That page's referrer policy; strict-origin-when-cross-origin when
   * omitted. */
  referrerPolicy?:
    | 'no-referrer'
    | 'no-referrer-when-downgrade'
    | 'origin'
    | 'origin-when-cross-origin'
    | 'same-origin'
    | 'strict-origin'
    | 'strict-origin-when-cross-origin'
    | 'unsafe-url';
  /** fetch()'s request mode; cors when omitted. Only for fetch(). */
  mode?: 'cors' | 'no-cors' | 'same-origin';
  /** fetch()'s credentials mode; same-origin when omitted. An XHR takes
   * same-origin or include, which is withCredentials. */
  credentials?: 'same-origin' | 'include' | 'omit';
}

/** What `get` and `post` take besides the URL and the body. */
export interface RequestOptions {
  /** Headers layered over the profile's. */
  headers?: Record<string, string>;
  /** The order of the headers given; the profile's own when omitted. */
  order?: string[];
  /** `name=value` pairs put in the jar before the request. */
  cookies?: string[];
  /** The browser context the request is made in. A transport that does not
   * say it applies one rejects the request with Unsupported, unsent. */
  browserContext?: BrowserContext;
}

/** A request, as `request` takes it. */
export interface Request extends RequestOptions {
  url: string;
  /** GET when omitted. */
  method?: string;
  /** Text, or bytes, which travel as base64 and arrive intact. */
  body?: string | Buffer | Uint8Array;
}

/** What came back: exactly these fields, in this order. */
export interface Response {
  /** The HTTP status code. A non-2xx answer still resolves. */
  status: number;
  /** The final URL, after redirects. */
  url: string;
  /** The body as text; bytes that are not valid UTF-8 appear as U+FFFD. */
  body: string;
  /** The body as bytes, exactly as they arrived. */
  content: Buffer;
  /** Lower-cased names, each with its values in wire order. */
  headers: Record<string, string[]>;
  /** The `name=value` pairs the jar holds for the final URL. */
  cookies: string[];
}

/** What a transport is, as it answers `hello`. */
export const ENGINE_MAJOR: number;
export interface Hello {
  engine_major?: number;
  version?: string;
  /** The protocol it speaks: 1 for one older than the question. */
  protocol: number;
  /** What it can do that a client has to ask about, such as
   * `browser_context`. */
  capabilities: string[];
}

/** One browser identity: one transport process, one fingerprint, one cookie
 * jar, one request at a time. */
export class Client {
  /** @throws {BinaryNotFound} no transport binary was found
   * @throws {RangeError} a timeout that is not positive and finite
   * @throws {TypeError} an onStderr that is not a function, or a cookieSet
   * without a cookieFile */
  constructor(options?: ClientOptions);
  /** GET a URL. */
  get(url: string, options?: RequestOptions): Promise<Response>;
  /** POST a body. */
  post(url: string, body: string | Buffer | Uint8Array, options?: RequestOptions): Promise<Response>;
  /** Make a request. */
  request(request: Request): Promise<Response>;
  /** What the transport is, asked without a connection and once. */
  hello(): Promise<Hello>;
  /** Stop the transport, and reject what waits. Final. */
  close(): void;
}

/** The transport binary: the one given, TLSFORGE_BIN, the platform package,
 * a local build, or the one on PATH, in that order.
 * @throws {BinaryNotFound} */
export function resolveBinary(explicit?: string): string;

/** The base of every error this package throws or rejects with. */
export class TLSForgeError extends Error {
  constructor(message?: string, options?: { cause?: unknown });
}

/** No transport binary was found, or the one named is not there. */
export class BinaryNotFound extends TLSForgeError {}

/** The transport failed: it would not start, would not take its arguments or
 * its proxy, died, could not be written to, was closed, or answered with
 * something that is not an answer. */
export class TransportError extends TLSForgeError {}

/** The request was not sent: the session it was made in has gone. */
export class SessionReset extends TransportError {}

/** The transport made the request, and the request failed. */
export class RequestFailed extends TLSForgeError {}

/** The transport cannot make the request as asked; it was not sent. */
export class Unsupported extends TLSForgeError {}

/** The deadline passed with no answer. */
export class Timeout extends TLSForgeError {}

export default Client;
