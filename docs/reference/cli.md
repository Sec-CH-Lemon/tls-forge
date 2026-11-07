# CLI commands and flags

Generated from the current CLI executable: what `tls-forge --help` and each command's `--help` say.

tls-forge — an HTTP client that sends a real browser's TLS fingerprint.

```bash linenums="0"
tls-forge <command> [flags]
```

<div class="tf-params">
<p class="tf-params__title">Commands</p>
<div class="tf-param" id="command-fetch"><div class="tf-param__head"><a href="#fetch"><code class="tf-param__name">fetch</code></a></div><div class="tf-param__text">make requests with a browser fingerprint: one URL, or a list</div></div>
<div class="tf-param" id="command-capture"><div class="tf-param__head"><a href="#capture"><code class="tf-param__name">capture</code></a></div><div class="tf-param__text">measure the browser installed on this machine</div></div>
<div class="tf-param" id="command-compare"><div class="tf-param__head"><a href="#compare"><code class="tf-param__name">compare</code></a></div><div class="tf-param__text">diff this library&#x27;s handshake against the browser&#x27;s</div></div>
<div class="tf-param" id="command-profiles"><div class="tf-param__head"><a href="#profiles"><code class="tf-param__name">profiles</code></a></div><div class="tf-param__text">list the profiles that can be impersonated</div></div>
<div class="tf-param" id="command-proxy"><div class="tf-param__head"><a href="#proxy"><code class="tf-param__name">proxy</code></a></div><div class="tf-param__text">run a proxy that re-sends every request with the fingerprint</div></div>
<div class="tf-param" id="command-serve"><div class="tf-param__head"><a href="#serve"><code class="tf-param__name">serve</code></a></div><div class="tf-param__text">run the local fingerprint echo server</div></div>
<div class="tf-param" id="command-daemon"><div class="tf-param__head"><a href="#daemon"><code class="tf-param__name">daemon</code></a></div><div class="tf-param__text">speak JSON lines on stdin/stdout</div></div>
<div class="tf-param" id="command-version"><div class="tf-param__head"><a href="#version"><code class="tf-param__name">version</code></a></div><div class="tf-param__text">print the version</div></div>
</div>

Run `tls-forge <command> --help` for a command's flags.

Start with `tls-forge compare`: it opens your browser, measures it, measures this library, and prints the differences. There should not be any.

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## fetch { .tf-symbol }

<div class="tf-ref__docs" markdown>

<div class="tf-params">
<p class="tf-params__title">What to fetch</p>
<div class="tf-param" id="fetch-input"><div class="tf-param__head"><code class="tf-param__name">--input</code><span class="tf-param__type">string</span></div><div class="tf-param__text">file of URLs to fetch; a list piped to standard input is read when no URL is named</div></div>
<div class="tf-param" id="fetch-urls"><div class="tf-param__head"><code class="tf-param__name">--urls</code><code class="tf-param__alias">-u</code><span class="tf-param__type">string</span></div><div class="tf-param__text">URLs as a comma-separated list, instead of a file</div></div>
<div class="tf-param" id="fetch-format"><div class="tf-param__head"><code class="tf-param__name">--format</code><code class="tf-param__alias">-F</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;auto&quot;</code></span></div><div class="tf-param__text">how to read the list: auto, lines, json or csv</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">The request</p>
<div class="tf-param" id="fetch-method"><div class="tf-param__head"><code class="tf-param__name">--method</code><code class="tf-param__alias">-X</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;GET&quot;</code></span></div><div class="tf-param__text">HTTP method</div></div>
<div class="tf-param" id="fetch-header"><div class="tf-param__head"><code class="tf-param__name">--header</code><code class="tf-param__alias">-H</code><span class="tf-param__type">name: value</span></div><div class="tf-param__text">extra header, repeatable: -H &quot;Authorization: Bearer …&quot;</div></div>
<div class="tf-param" id="fetch-data"><div class="tf-param__head"><code class="tf-param__name">--data</code><code class="tf-param__alias">-d</code><span class="tf-param__type">string</span></div><div class="tf-param__text">request body</div></div>
<div class="tf-param" id="fetch-request-kind"><div class="tf-param__head"><code class="tf-param__name">--request-kind</code><span class="tf-param__type">string</span></div><div class="tf-param__text">send each request as Chrome sends this kind: navigation, form, fetch or xhr, from the page --initiator-url names; without it, a GET as a navigation typed into the address bar, with what -H gives, and another method or -d as an XHR of the root of the URL&#x27;s own origin</div></div>
<div class="tf-param" id="fetch-initiator-url"><div class="tf-param__head"><code class="tf-param__name">--initiator-url</code><span class="tf-param__type">string</span></div><div class="tf-param__text">the page a --request-kind request is sent from: a form, fetch and xhr need one, and a navigation without one is typed into the address bar</div></div>
<div class="tf-param" id="fetch-clicked"><div class="tf-param__head"><code class="tf-param__name">--clicked</code></div><div class="tf-param__text">a person&#x27;s click on the --initiator-url page sends the request, a link or a form&#x27;s button, as Sec-Fetch-User says; without it the page&#x27;s script navigates or submits the form</div></div>
<div class="tf-param" id="fetch-form"><div class="tf-param__head"><code class="tf-param__name">--form</code></div><div class="tf-param__text">send the request as the form a person&#x27;s click submits, on the page --initiator-url names or on the root of the URL&#x27;s own origin: a POST of urlencoded, multipart or text/plain fields, or a GET with them in the URL</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Fingerprint and transport</p>
<div class="tf-param" id="fetch-profile"><div class="tf-param__head"><code class="tf-param__name">--profile</code><code class="tf-param__alias">-p</code><span class="tf-param__type">string</span></div><div class="tf-param__text">profile to impersonate; without one, chrome: the newest Chrome, shipped or kept on this machine</div></div>
<div class="tf-param" id="fetch-random-profile"><div class="tf-param__head"><code class="tf-param__name">--random-profile</code></div><div class="tf-param__text">wear, for each request, a profile drawn at random from every browser measured, shipped or kept on this machine, that this tls-forge can wear; a request keeps its profile for all of its tries</div></div>
<div class="tf-param" id="fetch-timeout"><div class="tf-param__head"><code class="tf-param__name">--timeout</code><code class="tf-param__alias">-t</code><span class="tf-param__type">duration</span><span class="tf-param__label">default <code>30s</code></span></div><div class="tf-param__text">request timeout</div></div>
<div class="tf-param" id="fetch-insecure"><div class="tf-param__head"><code class="tf-param__name">--insecure</code><code class="tf-param__alias">-k</code></div><div class="tf-param__text">skip certificate verification</div></div>
<div class="tf-param" id="fetch-dns-server"><div class="tf-param__head"><code class="tf-param__name">--dns-server</code><span class="tf-param__type">string</span></div><div class="tf-param__text">look names up with the DNS server at this IP address (and port, else 53), addresses and HTTPS records alike, instead of the machine&#x27;s; for direct connections, as a proxy looks up its own</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Proxy</p>
<div class="tf-param" id="fetch-proxy"><div class="tf-param__head"><code class="tf-param__name">--proxy</code><code class="tf-param__alias">-x</code><span class="tf-param__type">string</span></div><div class="tf-param__text">proxy URL, e.g. http://user:pass@host:port</div></div>
<div class="tf-param" id="fetch-proxy-env"><div class="tf-param__head"><code class="tf-param__name">--proxy-env</code><span class="tf-param__type">TLSFORGE_PROXY</span></div><div class="tf-param__text">name of an environment variable holding the proxy URL, such as TLSFORGE_PROXY, which keeps its password off the command line; no variable is read unless named</div></div>
<div class="tf-param" id="fetch-exit-headers"><div class="tf-param__head"><code class="tf-param__name">--exit-headers</code><span class="tf-param__type">string</span></div><div class="tf-param__text">a JSON file laid over the exit header fields built in: one of the same key replaces ours, &quot;off&quot; takes ours out, the rest are added</div></div>
<div class="tf-param" id="fetch-exit-lookup"><div class="tf-param__head"><code class="tf-param__name">--exit-lookup</code></div><div class="tf-param__text">ask address services where the run comes out; with reports/output also enable site probes and proxy-name resolution; services verify TLS even with --insecure</div></div>
<div class="tf-param" id="fetch-no-exit-lookup"><div class="tf-param__head"><code class="tf-param__name">--no-exit-lookup</code></div><div class="tf-param__text">explicitly keep the default: no address service, site probe or proxy-name resolution; passive proxy fields are still read</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Session</p>
<div class="tf-param" id="fetch-cookie"><div class="tf-param__head"><code class="tf-param__name">--cookie</code><code class="tf-param__alias">-b</code><span class="tf-param__type">name=value</span></div><div class="tf-param__text">cookie as name=value, repeatable</div></div>
<div class="tf-param" id="fetch-cookies"><div class="tf-param__head"><code class="tf-param__name">--cookies</code><span class="tf-param__type">string</span></div><div class="tf-param__text">file of warmed cookies to start from</div></div>
<div class="tf-param" id="fetch-cookie-set"><div class="tf-param__head"><code class="tf-param__name">--cookie-set</code><span class="tf-param__type">string</span></div><div class="tf-param__text">which set in that file to use; one at random when not named</div></div>
<div class="tf-param" id="fetch-save-cookies"><div class="tf-param__head"><code class="tf-param__name">--save-cookies</code><span class="tf-param__type">string</span></div><div class="tf-param__text">write the session this run ends with here; .txt writes a cookies.txt</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Running</p>
<div class="tf-param" id="fetch-concurrency"><div class="tf-param__head"><code class="tf-param__name">--concurrency</code><code class="tf-param__alias">-c</code><span class="tf-param__type">int</span><span class="tf-param__label">default <code>4</code></span></div><div class="tf-param__text">requests to run at once; one URL is asked for one at a time unless this is given</div></div>
<div class="tf-param" id="fetch-retry"><div class="tf-param__head"><code class="tf-param__name">--retry</code><span class="tf-param__type">int</span></div><div class="tf-param__text">times to ask again when the answer is not a 2xx, or does not come</div></div>
<div class="tf-param" id="fetch-retry-as-browser"><div class="tf-param__head"><code class="tf-param__name">--retry-as-browser</code></div><div class="tf-param__text">ask again as Chrome does when the page is reloaded (Ctrl+R): to the URL the answer is at, on the connection it came on, asking for it afresh, with the cookies and client hints it set; fetch and xhr are sent again as their page&#x27;s script sends them; needs --retry and a client-scope profile</div></div>
<div class="tf-param" id="fetch-repeat"><div class="tf-param__head"><code class="tf-param__name">--repeat</code><span class="tf-param__type">int</span><span class="tf-param__label">default <code>1</code></span></div><div class="tf-param__text">times to make each request</div></div>
<div class="tf-param" id="fetch-reuse-connection"><div class="tf-param__head"><code class="tf-param__name">--reuse-connection</code></div><div class="tf-param__text">keep a private client per input row across repeats and tries; requires a client-scope profile</div></div>
<div class="tf-param" id="fetch-fresh-connection"><div class="tf-param__head"><code class="tf-param__name">--fresh-connection</code></div><div class="tf-param__text">close each worker&#x27;s idle connections after every try in client scope; redundant with request isolation</div></div>
<div class="tf-param" id="fetch-wait-for"><div class="tf-param__head"><code class="tf-param__name">--wait-for</code><span class="tf-param__type">string</span></div><div class="tf-param__text">count an answer as the page when its body has this text in it, whatever its status, or, written as /regexp/ with any of the flags i, m, s and U, text this regular expression matches</div></div>
<div class="tf-param" id="fetch-wait-for-element"><div class="tf-param__head"><code class="tf-param__name">--wait-for-element</code><span class="tf-param__type">string</span></div><div class="tf-param__text">count an answer as the page when its HTML has an element matching this CSS selector, whatever its status; the HTML as it came: no script runs</div></div>
<div class="tf-param" id="fetch-html-decoding"><div class="tf-param__head"><code class="tf-param__name">--html-decoding</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;legacy&quot;</code></span></div><div class="tf-param__text">how --wait-for and --wait-for-element read a body as text: legacy, by its byte order mark or Content-Type, else as UTF-8 when it is UTF-8 throughout, whatever a &lt;meta&gt; says; or browser, as Chrome 155 decodes the document, by those, then what a document of its type names in itself</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Output</p>
<div class="tf-param" id="fetch-output"><div class="tf-param__head"><code class="tf-param__name">--output</code><code class="tf-param__alias">-o</code><span class="tf-param__type">string</span></div><div class="tf-param__text">keep every request in this directory: its page, a log of it and a trace of it, and a log of the run</div></div>
<div class="tf-param" id="fetch-clear-output-dir"><div class="tf-param__head"><code class="tf-param__name">--clear-output-dir</code></div><div class="tf-param__text">empty the --output directory before the run writes into it: every file and directory in it</div></div>
<div class="tf-param" id="fetch-pcap"><div class="tf-param__head"><code class="tf-param__name">--pcap</code></div><div class="tf-param__text">with --output, keep beside each request&#x27;s files the connections it went out on, as NAME.pcapng: every byte each way and the TLS secrets that open them, so that Wireshark reads it as it was sent, and so does anybody else who has it</div></div>
<div class="tf-param" id="fetch-include"><div class="tf-param__head"><code class="tf-param__name">--include</code><code class="tf-param__alias">-i</code></div><div class="tf-param__text">print the status and response headers; with JSON lines, add the headers to each</div></div>
<div class="tf-param" id="fetch-json"><div class="tf-param__head"><code class="tf-param__name">--json</code></div><div class="tf-param__text">write a line of JSON for each request rather than the page, as for a list</div></div>
<div class="tf-param" id="fetch-print-body"><div class="tf-param__head"><code class="tf-param__name">--print-body</code></div><div class="tf-param__text">print the output on stdout even when that is a terminal, or when --output has the page</div></div>
<div class="tf-param" id="fetch-verbose"><div class="tf-param__head"><code class="tf-param__name">--verbose</code><code class="tf-param__alias">-v</code></div><div class="tf-param__text">print a line for every request as it finishes</div></div>
<div class="tf-param" id="fetch-progress"><div class="tf-param__head"><code class="tf-param__name">--progress</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;auto&quot;</code></span></div><div class="tf-param__text">live status on stderr: auto, always or never</div></div>
<div class="tf-param" id="fetch-color"><div class="tf-param__head"><code class="tf-param__name">--color</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;auto&quot;</code></span></div><div class="tf-param__text">colour the status by outcome: auto, always or never</div></div>
</div>

<div class="tf-params">
<p class="tf-params__title">Report, trace and log</p>
<div class="tf-param" id="fetch-report"><div class="tf-param__head"><code class="tf-param__name">--report</code><code class="tf-param__alias">-R</code><span class="tf-param__type">string[=&quot;auto&quot;]</span></div><div class="tf-param__text">write a report of the run into --output, or here, as report-&lt;date-time&gt;; --report=PATH says where</div></div>
<div class="tf-param" id="fetch-report-format"><div class="tf-param__head"><code class="tf-param__name">--report-format</code><span class="tf-param__type">string</span></div><div class="tf-param__text">what to write the report as: html, json, or html,json for both; by default json for a --report=PATH ending in .json, and html otherwise</div></div>
<div class="tf-param" id="fetch-trace"><div class="tf-param__head"><code class="tf-param__name">--trace</code><span class="tf-param__type">string</span></div><div class="tf-param__text">write every step of the run here as Trace Event JSON, for ui.perfetto.dev</div></div>
<div class="tf-param" id="fetch-log"><div class="tf-param__head"><code class="tf-param__name">--log</code><span class="tf-param__type">string</span></div><div class="tf-param__text">write every step of the run here as it happens: each request, the connections it went out on and what came back; - is standard error, and a name ending in .json, .jsonl or .ndjson gets JSON lines. With --output, a run-&lt;time&gt;.log in it unless this names another</div></div>
<div class="tf-param" id="fetch-log-level"><div class="tf-param__head"><code class="tf-param__name">--log-level</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;trace&quot;</code></span></div><div class="tf-param__text">how much the log says: error, warn, info, debug, or trace, which adds every TLS handshake, certificate and HTTP/2 frame</div></div>
<div class="tf-param" id="fetch-keylog"><div class="tf-param__head"><code class="tf-param__name">--keylog</code><span class="tf-param__type">string</span></div><div class="tf-param__text">add the TLS secrets of every connection the run makes, to its sites and its proxy, to this file, as browsers do to the one SSLKEYLOGFILE names: Wireshark given it reads a capture of the run as plainly as it was sent, and so does anybody else who has it</div></div>
</div>

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge fetch [flags] [url...]
```

```bash title="Example"
tls-forge fetch -i https://example.com/
```

```text title="Response" linenums="0"
200 https://example.com/
…
content-type: text/html; charset=utf-8
…

<!doctype html><html lang=en><head><meta charset=utf-8>…
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## capture { .tf-symbol }

<div class="tf-ref__docs" markdown>

<div class="tf-params">
<p class="tf-params__title">Flags</p>
<div class="tf-param" id="capture-browser"><div class="tf-param__head"><code class="tf-param__name">--browser</code><code class="tf-param__alias">-b</code><span class="tf-param__type">string</span></div><div class="tf-param__text">browser to measure: chrome, chromium, edge, brave, or a path</div></div>
<div class="tf-param" id="capture-headless"><div class="tf-param__head"><code class="tf-param__name">--headless</code></div><div class="tf-param__text">run the browser without a window</div></div>
<div class="tf-param" id="capture-save"><div class="tf-param__head"><code class="tf-param__name">--save</code><code class="tf-param__alias">-s</code><span class="tf-param__type">string</span></div><div class="tf-param__text">write a reusable profile here; a directory gets &lt;name&gt;/&lt;platform&gt;.json</div></div>
<div class="tf-param" id="capture-install"><div class="tf-param__head"><code class="tf-param__name">--install</code></div><div class="tf-param__text">keep the profile in this machine&#x27;s own directory, where --profile finds it by name</div></div>
<div class="tf-param" id="capture-name"><div class="tf-param__head"><code class="tf-param__name">--name</code><code class="tf-param__alias">-n</code><span class="tf-param__type">string</span></div><div class="tf-param__text">profile name (default: browser version; manual_ prefix with --manual)</div></div>
<div class="tf-param" id="capture-json"><div class="tf-param__head"><code class="tf-param__name">--json</code><code class="tf-param__alias">-j</code></div><div class="tf-param__text">print the raw capture instead of a summary</div></div>
<div class="tf-param" id="capture-timeout"><div class="tf-param__head"><code class="tf-param__name">--timeout</code><code class="tf-param__alias">-t</code><span class="tf-param__type">duration</span><span class="tf-param__label">default <code>2m0s</code></span></div><div class="tf-param__text">how long to wait for the browser; with --manual, ten minutes unless given</div></div>
<div class="tf-param" id="capture-browser-arg"><div class="tf-param__head"><code class="tf-param__name">--browser-arg</code><span class="tf-param__type">stringArray</span></div><div class="tf-param__text">extra flag for the browser, repeatable; for the machine, not the measurement</div></div>
<div class="tf-param" id="capture-manual"><div class="tf-param__head"><code class="tf-param__name">--manual</code></div><div class="tf-param__text">measure a browser you open the page in yourself, which nothing here can launch: Firefox, Safari, a phone&#x27;s</div></div>
<div class="tf-param" id="capture-addr"><div class="tf-param__head"><code class="tf-param__name">--addr</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;127.0.0.1:0&quot;</code></span></div><div class="tf-param__text">with --manual, where to listen; 0.0.0.0:8443 lets in a phone on this network</div></div>
<div class="tf-param" id="capture-host"><div class="tf-param__head"><code class="tf-param__name">--host</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;localhost&quot;</code></span></div><div class="tf-param__text">with --manual, the name or address the page is opened at, which its certificate is made for</div></div>
<div class="tf-param" id="capture-policy-from"><div class="tf-param__head"><code class="tf-param__name">--policy-from</code><span class="tf-param__type">string</span></div><div class="tf-param__text">full profile or file whose unmeasured policies the capture inherits (default: newest shipped same family/platform)</div></div>
<div class="tf-param" id="capture-provenance-dir"><div class="tf-param__head"><code class="tf-param__name">--provenance-dir</code><span class="tf-param__type">string</span></div><div class="tf-param__text">directory for separate provenance JSON (default: provenance subtree, never a profile file)</div></div>
<div class="tf-param" id="capture-set"><div class="tf-param__head"><code class="tf-param__name">--set</code><span class="tf-param__type">stringArray</span></div><div class="tf-param__text">with --save or --install, a value the profile keeps of this machine, NAME=VALUE as its header carries it; again for more</div></div>
</div>

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge capture [flags]
```

```bash title="Example"
tls-forge capture --headless
```

```text title="Response" linenums="0"
────────────────────────────────────────────────────────────────────────
  user-agent       Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … HeadlessChrome/157.0.0.0 Safari/537.36
  JA4              t13d1517h2_8daaf6152771_cb7bf5808d99
  JA3 hash         27da79ce232c1b9b70150145293bcdd7
  ALPN             h2, http/1.1
  HTTP/2           1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  …
  client hints     21 of the 21 a server asks for, sent when asked
────────────────────────────────────────────────────────────────────────

Re-run with --install to keep this profile, or --save <path> to write it out.
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## compare { .tf-symbol }

<div class="tf-ref__docs" markdown>

<div class="tf-params">
<p class="tf-params__title">Flags</p>
<div class="tf-param" id="compare-profile"><div class="tf-param__head"><code class="tf-param__name">--profile</code><code class="tf-param__alias">-p</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;chrome&quot;</code></span></div><div class="tf-param__text">profile to check</div></div>
<div class="tf-param" id="compare-browser"><div class="tf-param__head"><code class="tf-param__name">--browser</code><code class="tf-param__alias">-b</code><span class="tf-param__type">string</span></div><div class="tf-param__text">browser to compare against</div></div>
<div class="tf-param" id="compare-headless"><div class="tf-param__head"><code class="tf-param__name">--headless</code></div><div class="tf-param__text">run the browser without a window</div></div>
<div class="tf-param" id="compare-json"><div class="tf-param__head"><code class="tf-param__name">--json</code><code class="tf-param__alias">-j</code></div><div class="tf-param__text">print both captures and the diff as JSON</div></div>
<div class="tf-param" id="compare-color"><div class="tf-param__head"><code class="tf-param__name">--color</code><code class="tf-param__alias">-c</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;auto&quot;</code></span></div><div class="tf-param__text">colourise the diff: auto, always or never</div></div>
<div class="tf-param" id="compare-full"><div class="tf-param__head"><code class="tf-param__name">--full</code><code class="tf-param__alias">-f</code></div><div class="tf-param__text">print matching values in full; differing ones always are</div></div>
<div class="tf-param" id="compare-timeout"><div class="tf-param__head"><code class="tf-param__name">--timeout</code><code class="tf-param__alias">-t</code><span class="tf-param__type">duration</span><span class="tf-param__label">default <code>2m0s</code></span></div><div class="tf-param__text">how long to wait for the browser; with --manual, ten minutes unless given</div></div>
<div class="tf-param" id="compare-browser-arg"><div class="tf-param__head"><code class="tf-param__name">--browser-arg</code><span class="tf-param__type">stringArray</span></div><div class="tf-param__text">extra flag for the browser, repeatable; for the machine, not the measurement</div></div>
<div class="tf-param" id="compare-manual"><div class="tf-param__head"><code class="tf-param__name">--manual</code></div><div class="tf-param__text">measure a browser you open the page in yourself, which nothing here can launch: Firefox, Safari, a phone&#x27;s</div></div>
<div class="tf-param" id="compare-addr"><div class="tf-param__head"><code class="tf-param__name">--addr</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;127.0.0.1:0&quot;</code></span></div><div class="tf-param__text">with --manual, where to listen; 0.0.0.0:8443 lets in a phone on this network</div></div>
<div class="tf-param" id="compare-host"><div class="tf-param__head"><code class="tf-param__name">--host</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;localhost&quot;</code></span></div><div class="tf-param__text">with --manual, the name or address the page is opened at, which its certificate is made for</div></div>
</div>

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge compare [flags]
```

```bash title="Example"
tls-forge compare --headless
```

```text title="Response" linenums="0"
--- browser  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … HeadlessChrome/157.0.0.0 Safari/537.36
             Google Chrome 157.0.8103.39, macOS 27.0.1, arm 64, headless
+++ client   profile chrome_157_macos
…
TLS
  ja4                    t13d1517h2_8daaf6152771_cb7bf5808d99
  …
HTTP/2
  http2_akamai           1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  …
- header_values          …, user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … HeadlessChrome/157.0.0.0 Safari/537.36, …
+ header_values          …, user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … Chrome/157.0.0.0 Safari/537.36, …
…
2 field(s) differ. Fix by measuring this browser and using the profile
it produces:
  tls-forge capture --save my-browser.json
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## profiles { .tf-symbol }

<div class="tf-ref__docs" markdown>

This command takes no flags.

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge profiles [flags]
```

```bash title="Example"
tls-forge profiles
```

```text title="Response" linenums="0"
Measured from a real browser.
  * kept on this machine, and used ahead of anything shipped
  < what you get when no profile is named

  chrome_151
  …
  chrome_157
    chrome_157_linux
    chrome_157_macos          <
    chrome_157_windows

From the tls-client catalogue, a handshake but no headers of its own:

…

Measure your own with:  tls-forge capture --install
Kept on this machine in: …/Library/Application Support/tls-forge/profiles
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## proxy { .tf-symbol }

<div class="tf-ref__docs" markdown>

<div class="tf-params">
<p class="tf-params__title">Flags</p>
<div class="tf-param" id="proxy-profile"><div class="tf-param__head"><code class="tf-param__name">--profile</code><code class="tf-param__alias">-p</code><span class="tf-param__type">string</span></div><div class="tf-param__text">profile to impersonate; without one, chrome: the newest Chrome, shipped or kept on this machine</div></div>
<div class="tf-param" id="proxy-proxy"><div class="tf-param__head"><code class="tf-param__name">--proxy</code><code class="tf-param__alias">-x</code><span class="tf-param__type">string</span></div><div class="tf-param__text">proxy URL, e.g. http://user:pass@host:port</div></div>
<div class="tf-param" id="proxy-proxy-env"><div class="tf-param__head"><code class="tf-param__name">--proxy-env</code><span class="tf-param__type">TLSFORGE_PROXY</span></div><div class="tf-param__text">name of an environment variable holding the proxy URL, such as TLSFORGE_PROXY, which keeps its password off the command line; no variable is read unless named</div></div>
<div class="tf-param" id="proxy-timeout"><div class="tf-param__head"><code class="tf-param__name">--timeout</code><code class="tf-param__alias">-t</code><span class="tf-param__type">duration</span><span class="tf-param__label">default <code>30s</code></span></div><div class="tf-param__text">request timeout</div></div>
<div class="tf-param" id="proxy-insecure"><div class="tf-param__head"><code class="tf-param__name">--insecure</code><code class="tf-param__alias">-k</code></div><div class="tf-param__text">skip certificate verification</div></div>
<div class="tf-param" id="proxy-dns-server"><div class="tf-param__head"><code class="tf-param__name">--dns-server</code><span class="tf-param__type">string</span></div><div class="tf-param__text">look names up with the DNS server at this IP address (and port, else 53), addresses and HTTPS records alike, instead of the machine&#x27;s; for direct connections, as a proxy looks up its own</div></div>
<div class="tf-param" id="proxy-addr"><div class="tf-param__head"><code class="tf-param__name">--addr</code><code class="tf-param__alias">-a</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;127.0.0.1:8080&quot;</code></span></div><div class="tf-param__text">listen address</div></div>
<div class="tf-param" id="proxy-ca-cert"><div class="tf-param__head"><code class="tf-param__name">--ca-cert</code><span class="tf-param__type">string</span></div><div class="tf-param__text">certificate authority to sign with (default: alongside the config)</div></div>
<div class="tf-param" id="proxy-ca-key"><div class="tf-param__head"><code class="tf-param__name">--ca-key</code><span class="tf-param__type">string</span></div><div class="tf-param__text">the authority&#x27;s key</div></div>
<div class="tf-param" id="proxy-quiet"><div class="tf-param__head"><code class="tf-param__name">--quiet</code><code class="tf-param__alias">-q</code></div><div class="tf-param__text">do not report per-connection failures</div></div>
<div class="tf-param" id="proxy-max-request-body"><div class="tf-param__head"><code class="tf-param__name">--max-request-body</code><span class="tf-param__type">int</span><span class="tf-param__label">default <code>16777216</code></span></div><div class="tf-param__text">largest request body to buffer, in bytes</div></div>
</div>

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge proxy [flags]
```

```bash title="Example"
tls-forge proxy --addr 127.0.0.1:8080
```

```text title="Response" linenums="0"
proxy listening on 127.0.0.1:8080

  export HTTPS_PROXY=http://127.0.0.1:8080
  curl --proxy http://127.0.0.1:8080 --cacert '…/Library/Application Support/tls-forge/ca.pem' https://tls.browserleaks.com/json

…

Ctrl-C to stop.
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## serve { .tf-symbol }

<div class="tf-ref__docs" markdown>

<div class="tf-params">
<p class="tf-params__title">Flags</p>
<div class="tf-param" id="serve-addr"><div class="tf-param__head"><code class="tf-param__name">--addr</code><code class="tf-param__alias">-a</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;127.0.0.1:0&quot;</code></span></div><div class="tf-param__text">listen address</div></div>
<div class="tf-param" id="serve-host"><div class="tf-param__head"><code class="tf-param__name">--host</code><span class="tf-param__type">string</span><span class="tf-param__label">default <code>&quot;localhost&quot;</code></span></div><div class="tf-param__text">hostname used in the URL and certificate</div></div>
<div class="tf-param" id="serve-session-tickets"><div class="tf-param__head"><code class="tf-param__name">--session-tickets</code></div><div class="tf-param__text">allow TLS session resumption</div></div>
</div>

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge serve [flags]
```

```bash title="Example"
tls-forge serve
```

```text title="Response" linenums="0"
https://localhost:58155
  /          a page that measures the browser that opens it
  /api/all   this connection's fingerprint, as JSON

The certificate is self-signed and generated for this run, so clients
must be told to accept it (curl -k, tlsforge --insecure).
Ctrl-C to stop.
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## daemon { .tf-symbol }

<div class="tf-ref__docs" markdown>

<div class="tf-params">
<p class="tf-params__title">Flags</p>
<div class="tf-param" id="daemon-cookie"><div class="tf-param__head"><code class="tf-param__name">--cookie</code><code class="tf-param__alias">-b</code><span class="tf-param__type">name=value</span></div><div class="tf-param__text">cookie as name=value, repeatable</div></div>
<div class="tf-param" id="daemon-cookies"><div class="tf-param__head"><code class="tf-param__name">--cookies</code><span class="tf-param__type">string</span></div><div class="tf-param__text">file of warmed cookies to start from</div></div>
<div class="tf-param" id="daemon-cookie-set"><div class="tf-param__head"><code class="tf-param__name">--cookie-set</code><span class="tf-param__type">string</span></div><div class="tf-param__text">which set in that file to use; one at random when not named</div></div>
<div class="tf-param" id="daemon-profile"><div class="tf-param__head"><code class="tf-param__name">--profile</code><code class="tf-param__alias">-p</code><span class="tf-param__type">string</span></div><div class="tf-param__text">profile to impersonate; without one, chrome: the newest Chrome, shipped or kept on this machine</div></div>
<div class="tf-param" id="daemon-proxy"><div class="tf-param__head"><code class="tf-param__name">--proxy</code><code class="tf-param__alias">-x</code><span class="tf-param__type">string</span></div><div class="tf-param__text">proxy URL, e.g. http://user:pass@host:port</div></div>
<div class="tf-param" id="daemon-proxy-env"><div class="tf-param__head"><code class="tf-param__name">--proxy-env</code><span class="tf-param__type">TLSFORGE_PROXY</span></div><div class="tf-param__text">name of an environment variable holding the proxy URL, such as TLSFORGE_PROXY, which keeps its password off the command line; no variable is read unless named</div></div>
<div class="tf-param" id="daemon-timeout"><div class="tf-param__head"><code class="tf-param__name">--timeout</code><code class="tf-param__alias">-t</code><span class="tf-param__type">duration</span><span class="tf-param__label">default <code>30s</code></span></div><div class="tf-param__text">request timeout</div></div>
<div class="tf-param" id="daemon-insecure"><div class="tf-param__head"><code class="tf-param__name">--insecure</code><code class="tf-param__alias">-k</code></div><div class="tf-param__text">skip certificate verification</div></div>
<div class="tf-param" id="daemon-dns-server"><div class="tf-param__head"><code class="tf-param__name">--dns-server</code><span class="tf-param__type">string</span></div><div class="tf-param__text">look names up with the DNS server at this IP address (and port, else 53), addresses and HTTPS records alike, instead of the machine&#x27;s; for direct connections, as a proxy looks up its own</div></div>
<div class="tf-param" id="daemon-proxy-stdin"><div class="tf-param__head"><code class="tf-param__name">--proxy-stdin</code></div><div class="tf-param__text">take the proxy URL from the first line of standard input, an init line, which keeps it off the command line and out of the environment</div></div>
</div>

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge daemon [flags]
```

```bash title="Example"
echo '{"id":1,"engine_major":1,"url":"https://example.com/"}' | tls-forge daemon
```

```json title="Response" linenums="0"
{"id":1,"status":200,"url":"https://example.com/","body":"\u003c!doctype html\u003e…","headers":{…,"content-type":["text/html; charset=utf-8"],…},"cookies":[]}
```

</div>

</div>

<div class="tf-ref" markdown>

<div class="tf-ref__text" markdown>

## version { .tf-symbol }

<div class="tf-ref__docs" markdown>

This command takes no flags.

</div>

</div>

<div class="tf-ref__code" markdown>

```bash linenums="0"
tls-forge version [flags]
```

```bash title="Example"
tls-forge version
```

```text title="Response" linenums="0"
tls-forge v1.0.0
```

</div>

</div>
