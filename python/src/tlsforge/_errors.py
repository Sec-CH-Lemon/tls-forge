"""What can go wrong, as types a caller can act on.

Four, because there are four different things to do about them: fix the install,
retry, give up on the request, or fix the call. Anything finer would be a
taxonomy nobody branches on.
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
