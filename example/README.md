# Examples

This directory contains runnable consumer projects for all three libraries and
every input-file format understood by the CLI. The examples make real requests;
the commands and sample output below were checked against the committed files.

The URLs are `example.com`, `example.org` and `example.net`, so the runnable
examples work from anywhere without an account or a proxy.

| path | what it is |
|---|---|
| [`go/`](go/) | standalone Go module using the Go library |
| [`node/`](node/) | standalone npm project using the Node.js package |
| [`python/`](python/) | standalone Python project using the Python package |
| [`urls.txt`](urls.txt) | a list, one URL per line |
| [`urls.csv`](urls.csv) | a list as CSV |
| [`urls.json`](urls.json) | a list as JSON |
| [`urls-with-proxies.csv`](urls-with-proxies.csv) | the same, a proxy per URL |
| [`urls-with-proxies.json`](urls-with-proxies.json) | the same, as JSON |
| [`cookies.json`](cookies.json) | two warmed sessions |
| [`cookies.txt`](cookies.txt) | the Netscape cookie file, which curl and wget read |
| [`cookies-browser-export.json`](cookies-browser-export.json) | what a browser extension writes as JSON |

## Library examples

Each example accepts an optional URL as its first argument and otherwise calls
`https://tls.browserleaks.com/json`, where the returned JA3, JA4 and HTTP/2
fingerprint can be inspected directly.

### Go

The example is a separate module with a `replace` directive pointing to this
checkout, so it exercises the package as a consumer without downloading a
published version. It uses the Go transport directly and needs no CLI binary.

```bash
cd example/go
go run .
go run . https://example.com/       # optional URL override
```

### Node.js

The local npm dependency contains the JavaScript SDK but, unlike a published
package, no platform binary. Build the repository binary once, install the local
package without its release-only optional dependencies, and run the script:

```bash
cd example/node
go build -o ../../bin/tls-forge ../../cmd/tls-forge
npm install --omit=optional
npm start
npm start -- https://example.com/   # optional URL override
```

On Windows, name the output `../../bin/tls-forge.exe`. The script also honours
`TLSFORGE_BIN`, so an already installed or custom transport can be selected
without building into `bin/`.

### Python

The editable install likewise contains the Python SDK but not the binary that a
release wheel embeds:

```bash
cd example/python
go build -o ../../bin/tls-forge ../../cmd/tls-forge
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
.venv/bin/python main.py https://example.com/   # optional URL override
```

On Windows, build `../../bin/tls-forge.exe` and replace `.venv/bin/python` with
`.venv\Scripts\python.exe`. This script honours `TLSFORGE_BIN` as well.

## CLI examples

The commands below run from this directory. Build the CLI first:

```bash
cd example
make -C .. build
../bin/tls-forge version
```

On Windows without Make, use
`go build -o ..\bin\tls-forge.exe ..\cmd\tls-forge` and invoke
`..\bin\tls-forge.exe` in place of `../bin/tls-forge`.

## Scrape a list

```bash
../bin/tls-forge fetch --input urls.csv
```

`fetch` is given one URL or many. One is answered with its page. A list is
answered with one JSON object per URL on standard output, when that is a pipe
or a file, and with what the run came to on standard error:

```
  ████████████████████████████████████████  3/3  100%
  0s elapsed · 1.7 kB

  ✓ 200 OK   3  100%

  Requests      3
  Retries       0
  Success rate  100.0%
  Avg time      71ms
```

`Avg time` is what one URL took from when it was asked for to its last answer.
It is not the run divided by the URLs: several are out at once, so three pages
of 71 ms each fit in a run of 84.

The format is read from the extension: `.json` is JSON, `.csv` is CSV, anything
else is one URL per line. Name it yourself with `-F` when the file is called
something else.

```bash
../bin/tls-forge fetch --input urls.txt        # lines
../bin/tls-forge fetch --input urls.json       # JSON
../bin/tls-forge fetch -u "https://example.com/,https://example.org/"
../bin/tls-forge fetch https://example.com/ https://example.org/
cat urls.txt | ../bin/tls-forge fetch          # or standard input
```

It is how the command was asked that decides the shape, not how many URLs
turned up, so a list of one is still answered with a line. `--json` asks for
the line when the one URL is named on the command line:

```bash
../bin/tls-forge fetch --json https://example.com/ | jq '{status, bytes, ms}'
```

## Keep the results

```bash
../bin/tls-forge fetch --input urls.csv -o out/ -R reports/ > results.jsonl
```

The JSON lines go where standard output goes, here a file. `-o` keeps every
request in a directory, and `-R` writes an HTML report; given a directory, the
report names itself after the run. Both are named at the end:

```
  Saved to      out/
  Report        reports/report-2026-08-16-091854-584.html
```

One line of a run without `-o`, with the body cut short here:

```json
{
  "url": "https://example.com/",
  "status": 200,
  "final_url": "https://example.com/",
  "bytes": 559,
  "body": "<!doctype html><html lang=\"en\"><head><ti…",
  "started": "2026-08-16T09:18:54.499687+02:00",
  "ended": "2026-08-16T09:18:54.556431+02:00",
  "ms": 56,
  "attempts": 1
}
```

Bodies inline into the line. With `-o`, the page is in a file instead and the
line names it, which is what to do when the pages are large; `-i` adds the
response headers to every line, as `headers`. For every request `-o` keeps
three files, under the host, the moment and the number of the request:

```
out/example.com-2026-08-16-091854-584-1.html
out/example.com-2026-08-16-091854-584-1.log
out/trace-example.com-2026-08-16-091854-584-1.json
```

The page is whatever came back, a refusal included. The log is the request
written out to be read: how it ended, every try with what it waited on, the
header fields that went out and the ones that came back. The trace is the same
request for [ui.perfetto.dev](https://ui.perfetto.dev/). A request that got no
answer has a log and a trace, and no page. A log reads like this:

```
GET https://example.com/

  request  1 of 3
  profile  chrome_155_macos
  proxy    direct
  exit-ip  203.0.113.7 · PL
  started  16 Aug 2026 09:18:54.584
  ended    16 Aug 2026 09:18:55.087
  took     503ms
  outcome  200 OK · 559 B
  tries    1
  page     out/example.com-2026-08-16-091854-584-1.html

try 1 of 1: 200 OK · 559 B, 503ms
  began       16 Aug 2026 09:18:54.584
  connection  new connection to 104.20.23.154:443 · TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2

  dns         1.9ms  example.com → 104.20.23.154, 172.66.147.243
  connect     6.4ms  104.20.23.154:443
  tls          12ms  TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2
  send         65µs
  wait        482ms
  receive     164µs

  request headers, as written
    :method: GET
    :authority: example.com
    …

  response headers
    content-type: text/html
    …
```

## Watch it happen

```bash
../bin/tls-forge fetch --input urls.csv -v
```

```
  200      559 B     52ms       https://example.com/
  200      559 B     59ms       https://example.org/
  200      559 B     84ms       https://example.net/
```

Under that, a count redraws while the run goes: a bar, how long it has been and
how many requests are out, and a row for each status the answers have had:

```
  ████████████████████████████████████████  3/3  100%
  0s elapsed · 1.7 kB

  ✓ 200 OK   3  100%
```

Both go to standard error, so the JSON lines on standard output stay readable by
whatever is consuming them.

## A proxy per URL

[`urls-with-proxies.csv`](urls-with-proxies.csv) puts one in the second column:

```csv
url,proxy
https://example.com/,http://user:pass@eu-1.proxy.example:8080
https://example.org/,socks5://us-3.proxy.example:1080
https://example.net/,
```

An empty cell means direct. The proxies named there are not real, so running
that file as it stands reports two URLs that got no response and one that came
back; put your own in to see it work.

One client is opened per distinct proxy and shared between the workers, because
the proxy is the identity: two pages through one exit sharing a cookie jar is
what a browser does, and a jar spread across two exits is what none does.

`--proxy` sets the one to use for entries that name none, so the flag and the
column compose rather than override. What a run through proxies comes to says
which of them carried nothing:

```
  Proxies       2 used, 0 alive, some direct
  dead proxy    http://user@eu-1.proxy.example:8080  (1 requests, none came back)
  dead proxy    socks5://us-3.proxy.example:1080  (1 requests, none came back)
```

## Warmed cookies

[`cookies.json`](cookies.json) holds two sessions. Name one:

```bash
../bin/tls-forge fetch --cookies cookies.json --cookie-set warm-eu https://example.com/
```

```
warmed from cookies.json, set warm-eu, 2 cookies
```

Name none and one is drawn at random, which is what a file of warmed sessions is
for. Eight runs of the command below chose `warm-eu` three times and `warm-us`
five:

```bash
../bin/tls-forge fetch --cookies cookies.json https://example.com/
```

A cookie by hand, without a file, for the times one value is all that is needed:

```bash
../bin/tls-forge fetch -b "session=abc" -b "consent=accepted" https://example.com/
```

[`cookies-browser-export.json`](cookies-browser-export.json) is the flat array an
extension writes, `httpOnly` and `expirationDate` and all. It is read as one set,
and gets the id `1` because the export gave it none:

```bash
../bin/tls-forge fetch --cookies cookies-browser-export.json https://example.com/
```

```
warmed from cookies-browser-export.json, set 1, 2 cookies
```

The cookies in both files name `example.com`, so they are sent there and nowhere
else. That is worth knowing when a session looks like it is being ignored: a
cookie goes to the domain it names, and one that named the wrong domain is
quietly not sent.

### The format everything agrees on

[`cookies.txt`](cookies.txt) is the **Netscape cookie file**. curl writes it with
`-c` and reads it with `-b`, wget and yt-dlp use it, and every "export cookies"
browser extension offers it. If a session has to travel between tools, this is
the shape to travel in.

```bash
../bin/tls-forge fetch --cookies cookies.txt https://example.com/
```

```
warmed from cookies.txt, set 1, 3 cookies
```

Seven tab-separated fields per line:

```
domain  includeSubdomains  path  secure  expires  name  value
```

Two conventions in it are not obvious. An expiry of `0` means a session cookie,
not one that expired in 1970. And a domain prefixed `#HttpOnly_` marks the
cookie HttpOnly: it reads like a comment and is not one, so a reader that skips
every line starting with `#` drops exactly the cookies that matter most.

It works in both directions, and was checked against curl itself:

```bash
curl -c jar.txt https://example.com/            # curl warms it
../bin/tls-forge fetch --cookies jar.txt …       # this reads it

../bin/tls-forge fetch --save-cookies jar.txt …  # this warms it
curl -b jar.txt https://example.com/            # curl reads it
```

### Writing a session down

```bash
../bin/tls-forge fetch --save-cookies session.json https://example.com/
../bin/tls-forge fetch --input urls.csv --save-cookies session.json
```

The file's name says which format. A `.txt` is written as a cookies.txt and
**replaced**, because that is what a jar written down means to everything else
that reads one. Anything else is this project's JSON, which holds sets, so a run
is **added** to what the file already had and one file builds up over time. A
run is one set per proxy, each noting which exit warmed it.

Written `0600` either way: a warmed session is a credential.

## How a run went

```bash
../bin/tls-forge fetch https://example.com/
```

On a terminal that prints how the request went rather than the page: how it
ended, how much came back and how long it took.

```
  ✓ 200 OK · 577 B · 54ms
```

Green and `✓` for a 2xx, yellow and `→` for a 3xx, red and `✗` for anything
else, a request that got no answer included. The page itself is the output, so
it goes wherever standard output is pointed, and to the screen when asked:

```bash
../bin/tls-forge fetch https://example.com/ > page.html      # a file gets it
../bin/tls-forge fetch https://example.com/ | head -3        # so does a pipe
../bin/tls-forge fetch --body https://example.com/           # and so does the screen
```

A list does the same with its JSON lines: a terminal gets the count and what
the run came to, a pipe or `-o` gets the lines, and `--body` prints them on the
screen as well.

Several requests are counted rather than listed. A bar shows how far the run
has got and, by its three shades, how the answers are going; under it there is
a row for every status that came back, with how many answers had it and what
share of them that is. Forty requests to a server that is not having a good
day:

```
  █████████████████████████████▓▓▓▒▒▒▒▒▒▒▒  40/40  100%
  5s elapsed · 731 B

  ✓ 200 OK                    29   73%
  → 304 Not Modified           3    8%
  ✗ 403 Forbidden              5   13%
  ✗ 503 Service Unavailable    3    8%

  Requests      40
  Retries       0
  Success rate  72.5%
  Avg time      126ms
```

The four figures under the rows are what the run came to: the requests it made,
the further tries `--retry` spent on them, the share that ended with a 2xx, and
how long one request took on average, its retries and the waits between them
included.

## Ask again, and ask several times

```bash
../bin/tls-forge fetch --retry 3 https://example.com/
```

`--retry` asks again when the answer is not a 2xx, or when none comes. What is
reported is how the request ended, so a page that arrived on the third try is a
200, and how many further tries it took to get there:

```
  ✓ 200 OK · 577 B · 1.1s · 2 retries
```

`-v` says each try that was made again, and why:

```
  try 1 of 4: HTTP 503, trying again in 250ms
  try 2 of 4: HTTP 503, trying again in 500ms
```

`fetch` makes no further tries unless told to, for a list as for one URL.

```bash
../bin/tls-forge fetch --repeat 3 -o out/ https://example.com/
```

`--repeat` is the other thing: the same request, made several times on purpose.
Each run is kept under its own number, and the count is of all of them:

```
  ████████████████████████████████████████  3/3  100%
  0s elapsed · 1.7 kB

  ✓ 200 OK   3  100%

  Requests      3
  Retries       0
  Success rate  100.0%
  Avg time      16ms
  Saved to      out/
```

With `-v` there is a line for each run as well:

```
  1/3  200      577 B     29ms       out/example.com-2026-08-16-091854-584-1.html
  2/3  200      577 B     11ms       out/example.com-2026-08-16-091854-614-2.html
  3/3  200      577 B     10ms       out/example.com-2026-08-16-091854-626-3.html
```

The first run paid for a lookup, a dial and a handshake; the two after it found
the connection open. One URL is asked for one run at a time, the way a page is
reloaded; `-c 10` makes ten of them at once instead. For a list, `--repeat`
goes through the whole of it that many times, and every line of the output
says which pass it was:

```bash
../bin/tls-forge fetch -u https://example.com/ --repeat 2 -o out/ \
  | jq -c '{url, status, file, run, attempts}'
```

```json
{"url":"https://example.com/","status":200,"file":"out/example.com-2026-08-16-091854-584-1.html","run":1,"attempts":1}
{"url":"https://example.com/","status":200,"file":"out/example.com-2026-08-16-091855-103-2.html","run":2,"attempts":1}
```

## A report of every request

```bash
../bin/tls-forge fetch --repeat 3 -R reports/ https://example.com/
```

`-R` writes the run as an HTML page, for one URL made several times as for a
list. The count says how the run went; the page has a row for every request,
with when it was made, how long it took, how it ended and where it came out. Its name is
the last thing the run says:

```
  Requests      3
  Retries       0
  Success rate  100.0%
  Avg time      16ms
  Report        reports/report-2026-08-16-091854-584.html
```

It is one file with nothing to fetch from anywhere else, so it opens offline
and can be sent on as it is. A request that got no answer is reported like any
other, which is usually the one the page is opened for.

Every row opens, and inside it is everything that request took: each try, the
connection it went out on, and what it waited on. A page that was refused once
and then arrived reads like this:

```
Try 1 of 2   ! 503   84ms   19 B    new connection to 104.20.23.154:443 · TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2
  dns        1.9ms   example.com → 104.20.23.154, 172.66.147.243
  connect    6.4ms   104.20.23.154:443
  tls         12ms   TLS 1.3 · TLS_AES_128_GCM_SHA256 · h2
  send        65µs
  wait        63ms
  receive    164µs
Then 250ms of waiting before the next try.

Try 2 of 2   ✓ 200   11ms   577 B   began 334ms into the request   connection already open to 104.20.23.154:443
  send        66µs   on the connection already open to 104.20.23.154:443
  wait        10ms
  receive    162µs
```

Above each list the try is drawn as a bar on the length of the whole request,
so the two tries and the wait between them are one picture. The second try
looked nothing up and dialled nothing: the connection was still open.

Two more things open inside a try. `send` holds the request as it was written,
field by field in the order they went out:

```
:method: GET
:authority: example.com
:scheme: https
:path: /
sec-ch-ua: "Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"
…
```

And under the steps is what the answer came with: its header fields, and for
an answer that was not the page the start of its body, already open, because
that is where a server usually says why:

```
cf-mitigated: challenge
server: cloudflare

<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>…
```

Cookie values and credentials are written as `***`, as they are in a trace.

The same report can be had as JSON, for a program rather than a person. A name
ending in `.json` is enough, and `--report-format html,json` writes both from
the one run:

```bash
../bin/tls-forge fetch --repeat 20 --retry 2 -R run.json https://example.com/
../bin/tls-forge fetch --repeat 20 --retry 2 -R reports/ --report-format html,json https://example.com/
```

Everything the page shows is in it under a name, so a question about a run is
one line of `jq`. How it went:

```bash
jq '.summary' run.json
```

```json
{
  "requests": 20,
  "scraped": 18,
  "not_2xx": 2,
  "no_response": 0,
  "success_rate": 90,
  "bytes": 10386,
  "retries": 4,
  "elapsed_ms": 4021,
  "avg_ms": 199
}
```

Which runs had to be asked for again, and what each try got:

```bash
jq -c '.requests[] | select(.attempts > 1) | {run, ms, tries: [.tries[].status]}' run.json
```

```json
{"run":7,"ms":345,"tries":[503,200]}
{"run":14,"ms":1012,"tries":[503,503,200]}
```

And the longest any try waited for its first byte, in milliseconds:

```bash
jq '[.requests[].tries[].steps[] | select(.name == "wait") | .ms] | max' run.json
```

## See what a run did

```bash
../bin/tls-forge fetch --repeat 3 --trace run.json https://example.com/
```

`--trace` writes down every step, in the Trace Event JSON format. Drop the file
onto [ui.perfetto.dev](https://ui.perfetto.dev/) and the run is a timeline: a
bar per request, and inside it a bar for the lookup, the dial, the handshake,
the request, the wait and the answer. Several requests at once get a row per
worker.

It is one event to a line, so it also answers without a viewer. Where the time
of each run went, in microseconds:

```bash
jq -r '.[] | select(.ph == "X") | "\(.name)\t\(.dur)"' run.json
```

```
exit-ip	42618
dns	14506
connect	7468
tls	15689
send	97
wait	18257
receive	212
send	93
wait	13932
receive	177
```

Which connection each run went out on:

```bash
jq -r '.[] | select(.name == "send") | .args | "\(.reused) \(.alpn) \(.tls) \(.remote)"' run.json
```

```
false h2 TLS 1.3 104.20.23.154:443
true h2 TLS 1.3 104.20.23.154:443
true h2 TLS 1.3 104.20.23.154:443
```

And whatever went wrong, which is what the file is usually opened for:

```bash
grep -E '"error"|"name":"retry"' run.json
```

A trace keeps the names of cookies and leaves out their values, and does the
same for proxy passwords and `Authorization` headers, so it can be attached to
a bug report as it is.

## Everything at once

```bash
../bin/tls-forge fetch \
  --input urls.csv \
  --cookies cookies.json --cookie-set warm-eu \
  --save-cookies session.json \
  -c 8 --retry 3 -v \
  --trace run.json \
  -o out/ -R reports/ --report-format html,json > results.jsonl
```

A list, a warmed session to start from, the session written back when it is
done, eight pages at a time, three further tries for anything that does not
come back as a page, a line per request, a trace of every step, every request
kept in `out/` with its page, its log and its trace, the results as JSON lines,
and a report to look at with the same report as JSON beside it.

## Where to read more

The [project README](../README.md) documents every command and flag, the file
formats in full, and how the impersonation is verified.
