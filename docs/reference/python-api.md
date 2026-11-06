# Python API

Generated from the public `tlsforge` exports and their runtime signatures. See the [Python integration guide](../integrations/python.md) for examples.

## Client { .tf-symbol }

```python linenums="0"
Client(
    *,
    profile: str | None = None,
    proxy: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    binary: str | os.PathLike[str] | None = None,
    insecure: bool = False,
    cookie_file: str | os.PathLike[str] | None = None,
    cookie_set: str | None = None,
    on_stderr: Callable[[str], None] | None = None,
)
```

One browser identity: one fingerprint, one cookie jar, one exit IP.

A client serialises: the protocol underneath is one request at a time, so calls from several threads queue rather than overlap. That is not a limitation to work around — it is what one session is. Scrape in parallel with a pool of clients, one per proxy, which is also how the identities stay separate.

Close it when done, or use it as a context manager. Closing is final: a client is one identity, and once it has been given up there is no identity left to make requests with.

<div class="tf-params">
<p class="tf-params__title">Parameters</p>
<div class="tf-param" id="client-profile"><div class="tf-param__head"><code class="tf-param__name">profile</code><span class="tf-param__type">str | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">which browser to impersonate, e.g. <code>&quot;chrome&quot;</code>.</div></div>
<div class="tf-param" id="client-proxy"><div class="tf-param__head"><code class="tf-param__name">proxy</code><span class="tf-param__type">str | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">an <code>http://</code> or <code>socks5://</code> URL.</div></div>
<div class="tf-param" id="client-timeout"><div class="tf-param__head"><code class="tf-param__name">timeout</code><span class="tf-param__type">float</span><span class="tf-param__label">default <code>DEFAULT_TIMEOUT</code></span></div><div class="tf-param__text">per-request deadline, in seconds.</div></div>
<div class="tf-param" id="client-binary"><div class="tf-param__head"><code class="tf-param__name">binary</code><span class="tf-param__type">str | os.PathLike[str] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">path to the tls-forge binary, ahead of every other source.</div></div>
<div class="tf-param" id="client-insecure"><div class="tf-param__head"><code class="tf-param__name">insecure</code><span class="tf-param__type">bool</span><span class="tf-param__label">default <code>False</code></span></div><div class="tf-param__text">skip certificate verification.</div></div>
<div class="tf-param" id="client-cookie-file"><div class="tf-param__head"><code class="tf-param__name">cookie_file</code><span class="tf-param__type">str | os.PathLike[str] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">a file of warmed cookies to start from (<code>--cookies</code>).</div></div>
<div class="tf-param" id="client-cookie-set"><div class="tf-param__head"><code class="tf-param__name">cookie_set</code><span class="tf-param__type">str | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">which set in that file; one at random when not named.</div></div>
<div class="tf-param" id="client-on-stderr"><div class="tf-param__head"><code class="tf-param__name">on_stderr</code><span class="tf-param__type">Callable[[str], None] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">receives the transport&#x27;s stderr, a line at a time.</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Raises</p>
<div class="tf-param"><div class="tf-param__head"><a href="#binarynotfound"><code class="tf-param__name">BinaryNotFound</code></a></div><div class="tf-param__text">when there is no binary to run.</div></div>
</div>

### Client.get() { .tf-member }

```python linenums="0"
Client.get(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    order: Sequence[str] | None = None,
    cookies: Iterable[str] | None = None,
    browser_context: BrowserContext | None = None,
    network_context: NetworkContext | None = None,
) -> Response
```

GET a URL.

### Client.post() { .tf-member }

```python linenums="0"
Client.post(
    url: str,
    body: str | bytes = '',
    *,
    headers: Mapping[str, str] | None = None,
    order: Sequence[str] | None = None,
    cookies: Iterable[str] | None = None,
    browser_context: BrowserContext | None = None,
    network_context: NetworkContext | None = None,
) -> Response
```

POST a body, in the browser context of the form or script that posts it: a request without one is a navigation typed into the address bar, which posts nothing, and is refused.

### Client.hello() { .tf-member }

```python linenums="0"
Client.hello() -> Hello
```

What the transport is: the protocol it speaks and what it can do, asked without a connection, and once. One older than the question speaks protocol 1, and can do nothing a client has to ask about.

<div class="tf-params">
<p class="tf-params__title">Raises</p>
<div class="tf-param"><div class="tf-param__head"><a href="#transporterror"><code class="tf-param__name">TransportError</code></a></div><div class="tf-param__text">the transport would not start, died, or spoke nonsense; asked again next time.</div></div>
<div class="tf-param"><div class="tf-param__head"><a href="#timeout"><code class="tf-param__name">Timeout</code></a></div><div class="tf-param__text">the deadline passed with no answer; asked again next time.</div></div>
</div>

### Client.request() { .tf-member }

```python linenums="0"
Client.request(
    url: str,
    *,
    method: str = 'GET',
    headers: Mapping[str, str] | None = None,
    order: Sequence[str] | None = None,
    body: str | bytes | None = None,
    cookies: Iterable[str] | None = None,
    browser_context: BrowserContext | None = None,
    network_context: NetworkContext | None = None,
) -> Response
```

Make a request.

<div class="tf-params">
<p class="tf-params__title">Parameters</p>
<div class="tf-param" id="client-request-url"><div class="tf-param__head"><code class="tf-param__name">url</code><span class="tf-param__type">str</span></div></div>
<div class="tf-param" id="client-request-method"><div class="tf-param__head"><code class="tf-param__name">method</code><span class="tf-param__type">str</span><span class="tf-param__label">default <code>&#x27;GET&#x27;</code></span></div></div>
<div class="tf-param" id="client-request-headers"><div class="tf-param__head"><code class="tf-param__name">headers</code><span class="tf-param__type">Mapping[str, str] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">the request&#x27;s own fields. Without a browser context, each goes where Chrome writes that field, in place of Chrome&#x27;s own, and one Chrome has no place for after <code>user-agent</code>, by the bytes of its name; in one, what the page&#x27;s script gives fetch() or an XHR.</div></div>
<div class="tf-param" id="client-request-order"><div class="tf-param__head"><code class="tf-param__name">order</code><span class="tf-param__type">Sequence[str] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">the order of the headers <em>you</em> send, for a profile that lays them out as given. Without it they go sorted.</div></div>
<div class="tf-param" id="client-request-body"><div class="tf-param__head"><code class="tf-param__name">body</code><span class="tf-param__type">str | bytes | None</span><span class="tf-param__label">default <code>None</code></span></div></div>
<div class="tf-param" id="client-request-cookies"><div class="tf-param__head"><code class="tf-param__name">cookies</code><span class="tf-param__type">Iterable[str] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text"><code>name=value</code> pairs added to the jar before the request.</div></div>
<div class="tf-param" id="client-request-browser-context"><div class="tf-param__head"><code class="tf-param__name">browser_context</code><span class="tf-param__type">BrowserContext | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">the browser context the request is made in, by this package&#x27;s names (<code>BrowserContext</code>), sent only to a transport that says, when asked with <code>hello</code>, that it applies one.</div></div>
<div class="tf-param" id="client-request-network-context"><div class="tf-param__head"><code class="tf-param__name">network_context</code><span class="tf-param__type">NetworkContext | None</span><span class="tf-param__label">default <code>None</code></span></div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Raises</p>
<div class="tf-param"><div class="tf-param__head"><a href="#requestfailed"><code class="tf-param__name">RequestFailed</code></a></div><div class="tf-param__text">the request ran and failed — refused, DNS, TLS.</div></div>
<div class="tf-param"><div class="tf-param__head"><a href="#transporterror"><code class="tf-param__name">TransportError</code></a></div><div class="tf-param__text">the transport would not start, died, or spoke nonsense. The client stays usable.</div></div>
<div class="tf-param"><div class="tf-param__head"><a href="#timeout"><code class="tf-param__name">Timeout</code></a></div><div class="tf-param__text">the deadline passed with no answer.</div></div>
<div class="tf-param"><div class="tf-param__head"><a href="#unsupported"><code class="tf-param__name">Unsupported</code></a></div><div class="tf-param__text">a browser context, to a transport that does not apply one; the request was not sent.</div></div>
<div class="tf-param"><div class="tf-param__head"><code class="tf-param__name">TypeError</code></div><div class="tf-param__text">a browser context that is no mapping, or has a key there is none of; nothing was asked.</div></div>
</div>

### Client.close() { .tf-member }

```python linenums="0"
Client.close() -> None
```

Stop the transport. Idempotent, and final.

At once: a request in flight, or one waiting for it, is not waited for, and raises TransportError. A write stuck on a pipe the transport has stopped reading is ended by stopping the transport first.

## BrowserContext { .tf-symbol }

```python linenums="0"
class BrowserContext(TypedDict)
```

What in a browser a request stands for: it goes out as Chrome sends that kind, CORS and all. See GO.md, «Browser contexts».

The keys are this package's names for the daemon's fields, which the client sends as the daemon names them: `referrer_policy` is its `referrerPolicy`. A key there is none of is a TypeError.

<div class="tf-params">
<p class="tf-params__title">Keys</p>
<div class="tf-param" id="browsercontext-kind"><div class="tf-param__head"><code class="tf-param__name">kind</code><span class="tf-param__type">Literal[&#x27;navigation&#x27;, &#x27;form&#x27;, &#x27;fetch&#x27;, &#x27;xhr&#x27;]</span></div></div>
<div class="tf-param" id="browsercontext-initiator"><div class="tf-param__head"><code class="tf-param__name">initiator</code><span class="tf-param__type">str</span><span class="tf-param__label">optional</span></div><div class="tf-param__text">The URL of the page that sends it. A form, fetch() and an XHR need one; a navigation without one is typed into the address bar.</div></div>
<div class="tf-param" id="browsercontext-referrer-policy"><div class="tf-param__head"><code class="tf-param__name">referrer_policy</code><span class="tf-param__type">Literal[&#x27;no-referrer&#x27;, &#x27;no-referrer-when-downgrade&#x27;, &#x27;origin&#x27;, &#x27;origin-when-cross-origin&#x27;, &#x27;same-origin&#x27;, &#x27;strict-origin&#x27;, &#x27;strict-origin-when-cross-origin&#x27;, &#x27;unsafe-url&#x27;]</span><span class="tf-param__label">optional</span></div><div class="tf-param__text">That page&#x27;s referrer policy; strict-origin-when-cross-origin when omitted.</div></div>
<div class="tf-param" id="browsercontext-mode"><div class="tf-param__head"><code class="tf-param__name">mode</code><span class="tf-param__type">Literal[&#x27;cors&#x27;, &#x27;no-cors&#x27;, &#x27;same-origin&#x27;]</span><span class="tf-param__label">optional</span></div><div class="tf-param__text">fetch()&#x27;s request mode; cors when omitted. Only for fetch().</div></div>
<div class="tf-param" id="browsercontext-credentials"><div class="tf-param__head"><code class="tf-param__name">credentials</code><span class="tf-param__type">Literal[&#x27;same-origin&#x27;, &#x27;include&#x27;, &#x27;omit&#x27;]</span><span class="tf-param__label">optional</span></div><div class="tf-param__text">fetch()&#x27;s credentials mode; same-origin when omitted. An XHR takes same-origin or include, which is withCredentials.</div></div>
</div>

## NetworkContext { .tf-symbol }

```python linenums="0"
class NetworkContext(TypedDict)
```

Actual network metadata, with no precomputed RTT or downlink values.

<div class="tf-params">
<p class="tf-params__title">Keys</p>
<div class="tf-param" id="networkcontext-type"><div class="tf-param__head"><code class="tf-param__name">type</code><span class="tf-param__type">Literal[&#x27;unknown&#x27;, &#x27;ethernet&#x27;, &#x27;wifi&#x27;, &#x27;2g&#x27;, &#x27;3g&#x27;, &#x27;4g&#x27;, &#x27;5g&#x27;, &#x27;none&#x27;, &#x27;bluetooth&#x27;]</span></div></div>
<div class="tf-param" id="networkcontext-id"><div class="tf-param__head"><code class="tf-param__name">id</code><span class="tf-param__type">str</span></div></div>
<div class="tf-param" id="networkcontext-generation"><div class="tf-param__head"><code class="tf-param__name">generation</code><span class="tf-param__type">int</span></div></div>
<div class="tf-param" id="networkcontext-signal"><div class="tf-param__head"><code class="tf-param__name">signal</code><span class="tf-param__type">Optional[int]</span></div></div>
</div>

## Hello { .tf-symbol }

```python linenums="0"
Hello(
    protocol: int,
    capabilities: tuple[str, ...],
    engine_major: int | None = None,
    version: str | None = None,
)
```

What a transport is, as it says when asked: the protocol it speaks, and what it can do that a client has to ask about before relying on it. One older than the question speaks protocol 1 and can do nothing it is asked about.

<div class="tf-params">
<p class="tf-params__title">Fields</p>
<div class="tf-param" id="hello-protocol"><div class="tf-param__head"><code class="tf-param__name">protocol</code><span class="tf-param__type">int</span></div></div>
<div class="tf-param" id="hello-capabilities"><div class="tf-param__head"><code class="tf-param__name">capabilities</code><span class="tf-param__type">tuple[str, ...]</span></div></div>
<div class="tf-param" id="hello-engine-major"><div class="tf-param__head"><code class="tf-param__name">engine_major</code><span class="tf-param__type">int | None</span><span class="tf-param__label">default <code>None</code></span></div></div>
<div class="tf-param" id="hello-version"><div class="tf-param__head"><code class="tf-param__name">version</code><span class="tf-param__type">str | None</span><span class="tf-param__label">default <code>None</code></span></div></div>
</div>

## Response { .tf-symbol }

```python linenums="0"
Response(
    status: int,
    url: str,
    body: str,
    content: bytes = b'',
    headers: Mapping[str, tuple[str, ...]] = dict(),
    cookies: tuple[str, ...] = (),
)
```

What came back.

<div class="tf-params">
<p class="tf-params__title">Fields</p>
<div class="tf-param" id="response-status"><div class="tf-param__head"><code class="tf-param__name">status</code><span class="tf-param__type">int</span></div></div>
<div class="tf-param" id="response-url"><div class="tf-param__head"><code class="tf-param__name">url</code><span class="tf-param__type">str</span></div><div class="tf-param__text">The final URL, after redirects.</div></div>
<div class="tf-param" id="response-body"><div class="tf-param__head"><code class="tf-param__name">body</code><span class="tf-param__type">str</span></div><div class="tf-param__text">The response as text. Bytes that are not valid UTF-8 appear as U+FFFD; use <code>content</code> when the response is not text.</div></div>
<div class="tf-param" id="response-content"><div class="tf-param__head"><code class="tf-param__name">content</code><span class="tf-param__type">bytes</span><span class="tf-param__label">default <code>b&#x27;&#x27;</code></span></div><div class="tf-param__text">The response as bytes, exactly as they arrived. This is the one to use for images, archives, or any body that is not text.</div></div>
<div class="tf-param" id="response-headers"><div class="tf-param__head"><code class="tf-param__name">headers</code><span class="tf-param__type">Mapping[str, tuple[str, ...]]</span><span class="tf-param__label">default <code>dict()</code></span></div><div class="tf-param__text">Header values in wire order. Values stay separate because folding <code>set-cookie</code>, among others, changes its meaning.</div></div>
<div class="tf-param" id="response-cookies"><div class="tf-param__head"><code class="tf-param__name">cookies</code><span class="tf-param__type">tuple[str, ...]</span><span class="tf-param__label">default <code>()</code></span></div><div class="tf-param__text">What the jar holds for this URL afterwards.</div></div>
</div>

### Response.ok { .tf-member }

```python linenums="0"
Response.ok: bool
```

Did the server answer with a 2xx?

### Response.json() { .tf-member }

```python linenums="0"
Response.json(**kwargs: Any) -> Any
```

The body parsed as JSON. Raises `json.JSONDecodeError` if it is not.

## DEFAULT\_TIMEOUT { .tf-symbol }

```python linenums="0"
DEFAULT_TIMEOUT = 45.0
```

## MAX\_REQUEST\_BYTES { .tf-symbol }

```python linenums="0"
MAX_REQUEST_BYTES = 16 * 1024 * 1024
```

The most a request can be as the transport reads it: one line of JSON, its newline included, in UTF-8. A longer one would end the transport, and the session in it, so it is refused before it is sent.

## TLSForgeError { .tf-symbol }

```python linenums="0"
class TLSForgeError(Exception)
```

Base for everything this package raises.

## BinaryNotFound { .tf-symbol }

```python linenums="0"
class BinaryNotFound(TLSForgeError)
```

The transport binary could not be found or does not exist.

An install problem rather than a request problem: no retry will help, and the message says which of the four places were looked in.

## TransportError { .tf-symbol }

```python linenums="0"
class TransportError(TLSForgeError)
```

The transport process failed: it would not start, died, or spoke nonsense.

The request did not happen, or happened and the answer was lost. The client stays usable — the next request starts a fresh process.

## SessionReset { .tf-symbol }

```python linenums="0"
class SessionReset(TransportError)
```

The request was not sent: the transport the client's session was in has gone, and its cookies, TLS sessions and connections went with it.

Raised for every request waiting when that happens, or for the next one made when none was waiting. Requests after that start a new session in a new transport: the client never promises the identity it had before. A TransportError, so that code catching those catches this too.

## RequestFailed { .tf-symbol }

```python linenums="0"
class RequestFailed(TLSForgeError)
```

The transport ran the request and the request itself failed.

A refused connection, a DNS failure, a TLS error: the far end's doing, not the transport's. Distinct from TransportError because retrying this one can make sense and there is nothing wrong locally.

## Timeout { .tf-symbol }

```python linenums="0"
class Timeout(TLSForgeError, TimeoutError)
```

The deadline passed with no answer.

Also a builtin TimeoutError, so code that already catches those catches this without knowing about this package.

## Unsupported { .tf-symbol }

```python linenums="0"
class Unsupported(TLSForgeError)
```

The transport cannot make the request as asked, and it was not sent.

It does not do what the request needs, as it says when asked with Client.hello(), or it is older than the question. A newer tls-forge, or a request that does not need it, is the fix.

## resolve\_binary() { .tf-symbol }

```python linenums="0"
resolve_binary(explicit: str | os.PathLike[str] | None = None) -> str
```

Find the transport binary.

<div class="tf-params">
<p class="tf-params__title">Parameters</p>
<div class="tf-param" id="resolve-binary-explicit"><div class="tf-param__head"><code class="tf-param__name">explicit</code><span class="tf-param__type">str | os.PathLike[str] | None</span><span class="tf-param__label">default <code>None</code></span></div><div class="tf-param__text">a path to use as given, ahead of everything else.</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Raises</p>
<div class="tf-param"><div class="tf-param__head"><a href="#binarynotfound"><code class="tf-param__name">BinaryNotFound</code></a></div><div class="tf-param__text">when nothing was found, or when a path that was named does not exist.</div></div>
</div>

## bundled\_binary() { .tf-symbol }

```python linenums="0"
bundled_binary(platform: str = sys.platform) -> Path
```

The binary shipped inside this package, whether or not it is there.

## exe\_name() { .tf-symbol }

```python linenums="0"
exe_name(platform: str = sys.platform) -> str
```

The executable's name, which is the command's name, not the package's.

## ENV\_VAR { .tf-symbol }

```python linenums="0"
ENV_VAR = 'TLSFORGE_BIN'
```

The environment variable that overrides every other source.
