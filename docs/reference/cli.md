# CLI commands and flags

Generated from the current CLI executable. Every command's `--help` output is included below.

```text
tls-forge — an HTTP client that sends a real browser's TLS fingerprint.

usage: tls-forge <command> [flags]

  fetch      make requests with a browser fingerprint: one URL, or a list
  capture    measure the browser installed on this machine
  compare    diff this library's handshake against the browser's
  profiles   list the profiles that can be impersonated
  proxy      run a proxy that re-sends every request with the fingerprint
  serve      run the local fingerprint echo server
  daemon     speak JSON lines on stdin/stdout
  version    print the version

Run `tls-forge <command> --help` for a command's flags.

Start with `tls-forge compare`: it opens your browser, measures it, measures
this library, and prints the differences. There should not be any.
```

## `fetch`

```text
usage: tls-forge fetch [flags] [url...]

what to fetch:
      --input string               file of URLs to fetch; a list piped to standard input is read when no URL is named
  -u, --urls string                URLs as a comma-separated list, instead of a file
  -F, --format string              how to read the list: auto, lines, json or csv (default "auto")

the request:
  -X, --method string              HTTP method (default "GET")
  -H, --header name: value         extra header, repeatable: -H "Authorization: Bearer …"
  -d, --data string                request body
      --request-kind string        send each request as Chrome sends this kind: navigation, form, fetch or xhr, from the page --initiator-url names; without it, a GET as a navigation typed into the address bar, with what -H gives, and another method or -d as an XHR of the root of the URL's own origin
      --initiator-url string       the page a --request-kind request is sent from: a form, fetch and xhr need one, and a navigation without one is typed into the address bar
      --clicked                    a person's click on the --initiator-url page sends the request, a link or a form's button, as Sec-Fetch-User says; without it the page's script navigates or submits the form
      --form                       send the request as the form a person's click submits, on the page --initiator-url names or on the root of the URL's own origin: a POST of urlencoded, multipart or text/plain fields, or a GET with them in the URL

fingerprint and transport:
  -p, --profile string             profile to impersonate; without one, the browser measured on this machine when there is one, else chrome, the newest Chrome shipped
  -t, --timeout duration           request timeout (default 30s)
  -k, --insecure                   skip certificate verification
      --dns-server string          look names up with the DNS server at this IP address (and port, else 53), addresses and HTTPS records alike, instead of the machine's; for direct connections, as a proxy looks up its own

proxy:
  -x, --proxy string               proxy URL, e.g. http://user:pass@host:port
      --proxy-env TLSFORGE_PROXY   name of an environment variable holding the proxy URL, such as TLSFORGE_PROXY, which keeps its password off the command line; no variable is read unless named
      --exit-headers string        a JSON file laid over the exit header fields built in: one of the same key replaces ours, "off" takes ours out, the rest are added
      --exit-lookup                ask address services where the run comes out; with reports/output also enable site probes and proxy-name resolution; services verify TLS even with --insecure
      --no-exit-lookup             explicitly keep the default: no address service, site probe or proxy-name resolution; passive proxy fields are still read

session:
  -b, --cookie name=value          cookie as name=value, repeatable
      --cookies string             file of warmed cookies to start from
      --cookie-set string          which set in that file to use; one at random when not named
      --save-cookies string        write the session this run ends with here; .txt writes a cookies.txt

running:
  -c, --concurrency int            requests to run at once; one URL is asked for one at a time unless this is given (default 4)
      --retry int                  times to ask again when the answer is not a 2xx, or does not come
      --retry-as-browser           ask again as Chrome does when the page is reloaded (Ctrl+R): to the URL the answer is at, on the connection it came on, asking for it afresh, with the cookies and client hints it set; fetch and xhr are sent again as their page's script sends them; needs --retry and a client-scope profile
      --repeat int                 times to make each request (default 1)
      --reuse-connection           keep a private client per input row across repeats and tries; requires a client-scope profile
      --fresh-connection           close each worker's idle connections after every try in client scope; redundant with request isolation
      --wait-for string            count an answer as the page when its body has this text in it, whatever its status, or, written as /regexp/ with any of the flags i, m, s and U, text this regular expression matches
      --wait-for-element string    count an answer as the page when its HTML has an element matching this CSS selector, whatever its status; the HTML as it came: no script runs
      --html-decoding string       how --wait-for and --wait-for-element read a body as text: legacy, by its byte order mark or Content-Type, else as UTF-8 when it is UTF-8 throughout, whatever a <meta> says; or browser, as Chrome 155 decodes the document, by those, then what a document of its type names in itself (default "legacy")

output:
  -o, --output string              keep every request in this directory: its page, a log of it and a trace of it, and a log of the run
      --clear-output-dir           empty the --output directory before the run writes into it: every file and directory in it
      --pcap                       with --output, keep beside each request's files the connections it went out on, as NAME.pcapng: every byte each way and the TLS secrets that open them, so that Wireshark reads it as it was sent, and so does anybody else who has it
  -i, --include                    print the status and response headers; with JSON lines, add the headers to each
      --json                       write a line of JSON for each request rather than the page, as for a list
      --print-body                 print the output on stdout even when that is a terminal, or when --output has the page
  -v, --verbose                    print a line for every request as it finishes
      --progress string            live status on stderr: auto, always or never (default "auto")
      --color string               colour the status by outcome: auto, always or never (default "auto")

report, trace and log:
  -R, --report string[="auto"]     write a report of the run into --output, or here, as report-<date-time>; --report=PATH says where
      --report-format string       what to write the report as: html, json, or html,json for both; by default json for a --report=PATH ending in .json, and html otherwise
      --trace string               write every step of the run here as Trace Event JSON, for ui.perfetto.dev
      --log string                 write every step of the run here as it happens: each request, the connections it went out on and what came back; - is standard error, and a name ending in .json, .jsonl or .ndjson gets JSON lines. With --output, a run-<time>.log in it unless this names another
      --log-level string           how much the log says: error, warn, info, debug, or trace, which adds every TLS handshake, certificate and HTTP/2 frame (default "trace")
      --keylog string              add the TLS secrets of every connection the run makes, to its sites and its proxy, to this file, as browsers do to the one SSLKEYLOGFILE names: Wireshark given it reads a capture of the run as plainly as it was sent, and so does anybody else who has it
```

## `capture`

```text
usage: tls-forge capture [flags]

flags:
  -b, --browser string            browser to measure: chrome, chromium, edge, brave, or a path
      --headless                  run the browser without a window
  -s, --save string               write a reusable profile here; a directory gets <name>/<platform>.json
      --install                   keep the profile in this machine's own directory, where --profile finds it by name
  -n, --name string               profile name (default: browser version; manual_ prefix with --manual)
  -j, --json                      print the raw capture instead of a summary
  -t, --timeout duration          how long to wait for the browser; with --manual, ten minutes unless given (default 2m0s)
      --browser-arg stringArray   extra flag for the browser, repeatable; for the machine, not the measurement
      --manual                    measure a browser you open the page in yourself, which nothing here can launch: Firefox, Safari, a phone's
      --addr string               with --manual, where to listen; 0.0.0.0:8443 lets in a phone on this network (default "127.0.0.1:0")
      --host string               with --manual, the name or address the page is opened at, which its certificate is made for (default "localhost")
      --policy-from string        full profile or file whose unmeasured policies the capture inherits (default: newest shipped same family/platform)
      --provenance-dir string     directory for separate provenance JSON (default: provenance subtree, never a profile file)
      --set stringArray           with --save or --install, a value the profile keeps of this machine, NAME=VALUE as its header carries it; again for more
```

## `compare`

```text
usage: tls-forge compare [flags]

flags:
  -p, --profile string            profile to check (default "chrome")
  -b, --browser string            browser to compare against
      --headless                  run the browser without a window
  -j, --json                      print both captures and the diff as JSON
  -c, --color string              colourise the diff: auto, always or never (default "auto")
  -f, --full                      print matching values in full; differing ones always are
  -t, --timeout duration          how long to wait for the browser; with --manual, ten minutes unless given (default 2m0s)
      --browser-arg stringArray   extra flag for the browser, repeatable; for the machine, not the measurement
      --manual                    measure a browser you open the page in yourself, which nothing here can launch: Firefox, Safari, a phone's
      --addr string               with --manual, where to listen; 0.0.0.0:8443 lets in a phone on this network (default "127.0.0.1:0")
      --host string               with --manual, the name or address the page is opened at, which its certificate is made for (default "localhost")
```

## `profiles`

```text
usage: tls-forge profiles [flags]

This command takes no flags.
```

## `proxy`

```text
usage: tls-forge proxy [flags]

flags:
  -p, --profile string             profile to impersonate; without one, the browser measured on this machine when there is one, else chrome, the newest Chrome shipped
  -x, --proxy string               proxy URL, e.g. http://user:pass@host:port
      --proxy-env TLSFORGE_PROXY   name of an environment variable holding the proxy URL, such as TLSFORGE_PROXY, which keeps its password off the command line; no variable is read unless named
  -t, --timeout duration           request timeout (default 30s)
  -k, --insecure                   skip certificate verification
      --dns-server string          look names up with the DNS server at this IP address (and port, else 53), addresses and HTTPS records alike, instead of the machine's; for direct connections, as a proxy looks up its own
  -a, --addr string                listen address (default "127.0.0.1:8080")
      --ca-cert string             certificate authority to sign with (default: alongside the config)
      --ca-key string              the authority's key
  -q, --quiet                      do not report per-connection failures
      --max-request-body int       largest request body to buffer, in bytes (default 16777216)
```

## `serve`

```text
usage: tls-forge serve [flags]

flags:
  -a, --addr string       listen address (default "127.0.0.1:0")
      --host string       hostname used in the URL and certificate (default "localhost")
      --session-tickets   allow TLS session resumption
```

## `daemon`

```text
usage: tls-forge daemon [flags]

flags:
  -b, --cookie name=value          cookie as name=value, repeatable
      --cookies string             file of warmed cookies to start from
      --cookie-set string          which set in that file to use; one at random when not named
  -p, --profile string             profile to impersonate; without one, the browser measured on this machine when there is one, else chrome, the newest Chrome shipped
  -x, --proxy string               proxy URL, e.g. http://user:pass@host:port
      --proxy-env TLSFORGE_PROXY   name of an environment variable holding the proxy URL, such as TLSFORGE_PROXY, which keeps its password off the command line; no variable is read unless named
  -t, --timeout duration           request timeout (default 30s)
  -k, --insecure                   skip certificate verification
      --dns-server string          look names up with the DNS server at this IP address (and port, else 53), addresses and HTTPS records alike, instead of the machine's; for direct connections, as a proxy looks up its own
      --proxy-stdin                take the proxy URL from the first line of standard input, an init line, which keeps it off the command line and out of the environment
```

## `version`

```text
usage: tls-forge version [flags]

This command takes no flags.
```
