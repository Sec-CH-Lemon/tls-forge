# Daemon protocol

`tls-forge daemon` speaks one JSON object per line on stdin and one per line on stdout. Node.js and Python use it internally; another language can implement the protocol directly. The development source speaks **protocol 3** with compiled **engine major 1**.

## Discover capabilities

An offline `hello` line can omit `engine_major` and has no URL:

```json
{"id":1,"control":"hello"}
```

The answer includes `id`, `protocol`, `capabilities`, `engine_major`, and `version`. Validate the returned engine major before executing a request and again after replacing the process. Every ordinary request line must include the same `engine_major`.

## Request and response

```json
{"id":2,"engine_major":1,"url":"https://example.com/","method":"GET"}
```

```json
{"id":2,"status":200,"url":"https://example.com/","body":"...","headers":{"content-type":["text/html"]},"cookies":[]}
```

The `id` is echoed even for errors; a client must match responses to requests. A request may also have `headers`, `order`, `body`, `bodyEncoding`, `setCookie`, `browser` and `network`. `bodyEncoding: "base64"` carries arbitrary request bytes. Response bodies that are not valid UTF-8 are base64 with the same marker. Response headers map lower-case names to arrays so repeated fields remain separate. Non-2xx responses are normal answers; an `error` field reports a failed request.

The daemon accepts at most **16 MiB per input line**, newline included. Exceeding it ends the process. Requests are handled one at a time. Missing or mismatched major metadata is rejected before request-related network activity.

## Proxy init line

With `--proxy-stdin`, the first nonblank input line must initialize the upstream proxy:

```json
{"id":1,"engine_major":1,"control":"init","proxy":"http://user:password@proxy.example:8080"}
```

Wait for its answer before sending another line. This keeps proxy credentials off the command line and process environment. `--proxy-stdin` cannot be combined with `--proxy` or `--proxy-env`. Consult the generated [daemon Go declarations](../reference/go-api.md) for exact request and response fields.
