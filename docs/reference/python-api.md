# Python API

Generated from the public `tlsforge` exports and their runtime signatures. See the [Python integration guide](../integrations/python.md) for examples.

## `Client`

One browser identity: one fingerprint, one cookie jar, one exit IP.

A client serialises: the protocol underneath is one request at a time, so
calls from several threads queue rather than overlap. That is not a
limitation to work around — it is what one session is. Scrape in parallel
with a pool of clients, one per proxy, which is also how the identities stay
separate.

Close it when done, or use it as a context manager. Closing is final: a
client is one identity, and once it has been given up there is no identity
left to make requests with.

```python
Client(*, profile: 'str | None' = None, proxy: 'str | None' = None, timeout: 'float' = DEFAULT_TIMEOUT, binary: 'str | os.PathLike[str] | None' = None, insecure: 'bool' = False, cookie_file: 'str | os.PathLike[str] | None' = None, cookie_set: 'str | None' = None, on_stderr: 'Callable[[str], None] | None' = None) -> 'None'
```

### `Client.__init__(self, *, profile: 'str | None' = None, proxy: 'str | None' = None, timeout: 'float' = DEFAULT_TIMEOUT, binary: 'str | os.PathLike[str] | None' = None, insecure: 'bool' = False, cookie_file: 'str | os.PathLike[str] | None' = None, cookie_set: 'str | None' = None, on_stderr: 'Callable[[str], None] | None' = None) -> 'None'`

:param profile: which browser to impersonate, e.g. ``"chrome"``.
:param proxy: an ``http://`` or ``socks5://`` URL.
:param timeout: per-request deadline, in seconds.
:param binary: path to the tls-forge binary, ahead of every other source.
:param insecure: skip certificate verification.
:param cookie_file: a file of warmed cookies to start from (``--cookies``).
:param cookie_set: which set in that file; one at random when not named.
:param on_stderr: receives the transport's stderr, a line at a time.
:raises BinaryNotFound: when there is no binary to run.

### `Client.get(self, url: 'str', *, headers: 'Mapping[str, str] | None' = None, order: 'Sequence[str] | None' = None, cookies: 'Iterable[str] | None' = None, browser_context: 'BrowserContext | None' = None, network_context: 'NetworkContext | None' = None) -> 'Response'`

GET a URL.

### `Client.post(self, url: 'str', body: 'str | bytes' = '', *, headers: 'Mapping[str, str] | None' = None, order: 'Sequence[str] | None' = None, cookies: 'Iterable[str] | None' = None, browser_context: 'BrowserContext | None' = None, network_context: 'NetworkContext | None' = None) -> 'Response'`

POST a body, in the browser context of the form or script that
posts it: a request without one is a navigation typed into the address
bar, which posts nothing, and is refused.

### `Client.hello(self) -> 'Hello'`

What the transport is: the protocol it speaks and what it can do,
asked without a connection, and once. One older than the question speaks
protocol 1, and can do nothing a client has to ask about.

:raises TransportError: the transport would not start, died, or spoke
    nonsense; asked again next time.
:raises Timeout: the deadline passed with no answer; asked again next
    time.

### `Client.request(self, url: 'str', *, method: 'str' = 'GET', headers: 'Mapping[str, str] | None' = None, order: 'Sequence[str] | None' = None, body: 'str | bytes | None' = None, cookies: 'Iterable[str] | None' = None, browser_context: 'BrowserContext | None' = None, network_context: 'NetworkContext | None' = None) -> 'Response'`

Make a request.

:param headers: the request's own fields. Without a browser context,
    each goes where Chrome writes that field, in place of Chrome's own,
    and one Chrome has no place for after ``user-agent``, by the bytes
    of its name; in one, what the page's script gives fetch() or an XHR.
:param order: the order of the headers *you* send, for a profile that
    lays them out as given. Without it they go sorted.
:param cookies: ``name=value`` pairs added to the jar before the request.
:param browser_context: the browser context the request is made in, by
    this package's names (:class:`BrowserContext`), sent only to a
    transport that says, when asked with :meth:`hello`, that it applies
    one.
:raises RequestFailed: the request ran and failed — refused, DNS, TLS.
:raises TransportError: the transport would not start, died, or spoke
    nonsense. The client stays usable.
:raises Timeout: the deadline passed with no answer.
:raises Unsupported: a browser context, to a transport that does not
    apply one; the request was not sent.
:raises TypeError: a browser context that is no mapping, or has a key
    there is none of; nothing was asked.

### `Client.close(self) -> 'None'`

Stop the transport. Idempotent, and final.

At once: a request in flight, or one waiting for it, is not waited for,
and raises TransportError. A write stuck on a pipe the transport has
stopped reading is ended by stopping the transport first.

## `BrowserContext`

What in a browser a request stands for: it goes out as Chrome sends that
kind, CORS and all. See GO.md, «Browser contexts».

The keys are this package's names for the daemon's fields, which the client
sends as the daemon names them: ``referrer_policy`` is its
``referrerPolicy``. A key there is none of is a TypeError.

| Field | Type |
| --- | --- |
| `kind` | `ForwardRef("Literal['navigation', 'form', 'fetch', 'xhr']", module='tlsforge._client')` |
| `initiator` | `ForwardRef('str', module='tlsforge._client')` |
| `referrer_policy` | `ForwardRef("Literal['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url']", module='tlsforge._client')` |
| `mode` | `ForwardRef("Literal['cors', 'no-cors', 'same-origin']", module='tlsforge._client')` |
| `credentials` | `ForwardRef("Literal['same-origin', 'include', 'omit']", module='tlsforge._client')` |

## `NetworkContext`

Actual network metadata, with no precomputed RTT or downlink values.

| Field | Type |
| --- | --- |
| `type` | `ForwardRef("Literal['unknown', 'ethernet', 'wifi', '2g', '3g', '4g', '5g', 'none', 'bluetooth']", module='tlsforge._client')` |
| `id` | `ForwardRef('str', module='tlsforge._client')` |
| `generation` | `ForwardRef('int', module='tlsforge._client')` |
| `signal` | `ForwardRef('Optional[int]', module='tlsforge._client')` |

## `Hello`

What a transport is, as it says when asked: the protocol it speaks, and
what it can do that a client has to ask about before relying on it. One
older than the question speaks protocol 1 and can do nothing it is asked
about.

```python
Hello(protocol: 'int', capabilities: 'tuple[str, ...]', engine_major: 'int | None' = None, version: 'str | None' = None) -> None
```

| Field | Type |
| --- | --- |
| `protocol` | `int` |
| `capabilities` | `tuple[str, ...]` |
| `engine_major` | `int | None` |
| `version` | `str | None` |

### `Hello.__init__(self, protocol: 'int', capabilities: 'tuple[str, ...]', engine_major: 'int | None' = None, version: 'str | None' = None) -> None`

Initialize self.  See help(type(self)) for accurate signature.

## `Response`

What came back.

```python
Response(status: 'int', url: 'str', body: 'str', content: 'bytes' = b'', headers: 'Mapping[str, tuple[str, ...]]' = <factory>, cookies: 'tuple[str, ...]' = ()) -> None
```

| Field | Type |
| --- | --- |
| `status` | `int` |
| `url` | `str` |
| `body` | `str` |
| `content` | `bytes` |
| `headers` | `Mapping[str, tuple[str, ...]]` |
| `cookies` | `tuple[str, ...]` |

### `Response.ok`

Did the server answer with a 2xx?

### `Response.json(self, **kwargs: 'Any') -> 'Any'`

The body parsed as JSON. Raises `json.JSONDecodeError` if it is not.

### `Response.__init__(self, status: 'int', url: 'str', body: 'str', content: 'bytes' = b'', headers: 'Mapping[str, tuple[str, ...]]' = <factory>, cookies: 'tuple[str, ...]' = ()) -> None`

Initialize self.  See help(type(self)) for accurate signature.

## `DEFAULT_TIMEOUT`

`45.0`

## `MAX_REQUEST_BYTES`

`16777216`

## `TLSForgeError`

Base for everything this package raises.

## `BinaryNotFound`

The transport binary could not be found or does not exist.

An install problem rather than a request problem: no retry will help, and
the message says which of the four places were looked in.

## `TransportError`

The transport process failed: it would not start, died, or spoke nonsense.

The request did not happen, or happened and the answer was lost. The client
stays usable — the next request starts a fresh process.

## `SessionReset`

The request was not sent: the transport the client's session was in has
gone, and its cookies, TLS sessions and connections went with it.

Raised for every request waiting when that happens, or for the next one made
when none was waiting. Requests after that start a new session in a new
transport: the client never promises the identity it had before. A
TransportError, so that code catching those catches this too.

## `RequestFailed`

The transport ran the request and the request itself failed.

A refused connection, a DNS failure, a TLS error: the far end's doing, not
the transport's. Distinct from TransportError because retrying this one can
make sense and there is nothing wrong locally.

## `Timeout`

The deadline passed with no answer.

Also a builtin TimeoutError, so code that already catches those catches this
without knowing about this package.

## `Unsupported`

The transport cannot make the request as asked, and it was not sent.

It does not do what the request needs, as it says when asked with
Client.hello(), or it is older than the question. A newer tls-forge, or a
request that does not need it, is the fix.

## `resolve_binary`

```python
resolve_binary(explicit: 'str | os.PathLike[str] | None' = None) -> 'str'
```

Find the transport binary.

:param explicit: a path to use as given, ahead of everything else.
:raises BinaryNotFound: when nothing was found, or when a path that was
    named does not exist.

## `bundled_binary`

```python
bundled_binary(platform: 'str' = sys.platform) -> 'Path'
```

The binary shipped inside this package, whether or not it is there.

## `exe_name`

```python
exe_name(platform: 'str' = sys.platform) -> 'str'
```

The executable's name, which is the command's name, not the package's.

## `ENV_VAR`

`'TLSFORGE_BIN'`
