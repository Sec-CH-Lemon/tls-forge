"""What can go wrong, as types a caller can act on.

Four, because there are four different things to do about them: fix the install,
retry, give up on the request, or fix the call. Anything finer would be a
taxonomy nobody branches on, but for the one that says the session is not the
one the caller made: SessionReset, a TransportError.
"""

from __future__ import annotations


class TLSForgeError(Exception):
    """Base for everything this package raises."""


class BinaryNotFound(TLSForgeError):
    """The transport binary could not be found or does not exist.

    An install problem rather than a request problem: no retry will help, and
    the message says which of the four places were looked in.
    """


class TransportError(TLSForgeError):
    """The transport process failed: it would not start, died, or spoke nonsense.

    The request did not happen, or happened and the answer was lost. The client
    stays usable — the next request starts a fresh process.
    """


class SessionReset(TransportError):
    """The request was not sent: the transport the client's session was in has
    gone, and its cookies, TLS sessions and connections went with it.

    Raised for every request waiting when that happens, or for the next one made
    when none was waiting. Requests after that start a new session in a new
    transport: the client never promises the identity it had before. A
    TransportError, so that code catching those catches this too.
    """


class RequestFailed(TLSForgeError):
    """The transport ran the request and the request itself failed.

    A refused connection, a DNS failure, a TLS error: the far end's doing, not
    the transport's. Distinct from TransportError because retrying this one can
    make sense and there is nothing wrong locally.
    """


class Timeout(TLSForgeError, TimeoutError):
    """The deadline passed with no answer.

    Also a builtin TimeoutError, so code that already catches those catches this
    without knowing about this package.
    """
