// What can go wrong, as classes a caller can act on: the ones the Python
// package raises, by the same names. Five, because there are five things to do
// about them: fix the install (BinaryNotFound), try again (TransportError,
// Timeout), give up on the request (RequestFailed), or ask less of the
// transport (Unsupported); and SessionReset, a TransportError, for a request
// that was not sent because the session it was made in has gone. A mistake in
// the call itself is a TypeError or a RangeError, as JavaScript has them, and
// none of these.

/** The base of every error this package throws or rejects with. */
export class TLSForgeError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * No transport binary was found, or the one named is not there: an install
 * problem, which no retry mends.
 */
export class BinaryNotFound extends TLSForgeError {}

/**
 * The transport failed: it would not start, would not take its arguments or
 * its proxy, died, could not be written to, was closed, or answered with
 * something that is not an answer. The request did not happen, or happened and
 * its answer was lost. The client stays usable: the next request starts a
 * fresh transport.
 */
export class TransportError extends TLSForgeError {}

/**
 * A request that was not sent because the transport the client's session was
 * in has gone: its cookies, TLS sessions and connections went with it. Every
 * request waiting when that happens is rejected with this, and the next one
 * made is when none was waiting; requests after that start a new session in a
 * new transport. The client never promises the identity it had before.
 */
export class SessionReset extends TransportError {}

/**
 * The transport made the request, and the request failed: a refused
 * connection, a DNS failure, a TLS error, a proxy that would not tunnel, or a
 * request the transport would not make as it was asked. Nothing is wrong
 * locally, and trying again can make sense.
 */
export class RequestFailed extends TLSForgeError {}

/**
 * A request this client's transport cannot make as asked: it does not do what
 * the request needs, as it says when asked with hello(), or it is older than
 * the question. The request was not sent.
 */
export class Unsupported extends TLSForgeError {}

/** The deadline passed with no answer. */
export class Timeout extends TLSForgeError {}
