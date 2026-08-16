# Examples

Every file `tls-forge` reads, one of each, with the commands that use them. The
files here are real: every command below was run against them, and the output is
what came back.

The URLs are `example.com`, `example.org` and `example.net`, so the runnable
examples work from anywhere without an account or a proxy.

| file | what it is |
|---|---|
| [`urls.txt`](urls.txt) | a list, one URL per line |
| [`urls.csv`](urls.csv) | a list as CSV |
| [`urls.json`](urls.json) | a list as JSON |
| [`urls-with-proxies.csv`](urls-with-proxies.csv) | the same, a proxy per URL |
| [`urls-with-proxies.json`](urls-with-proxies.json) | the same, as JSON |
| [`cookies.json`](cookies.json) | two warmed sessions |
| [`cookies.txt`](cookies.txt) | the Netscape cookie file, which curl and wget read |
| [`cookies-browser-export.json`](cookies-browser-export.json) | what a browser extension writes as JSON |

Run these from the repository root, after `make build`.

## Scrape a list

```bash
tls-forge batch -i example/urls.csv
```

One JSON object per URL on standard output, and a summary on standard error:

```
  Ran          3 URLs in 84ms
  Scraped      3  (100.0%)
  Not 2xx      0  (0.0%)
  No response  0  (0.0%)
  Data         1.7 kB
  Retries      0
```

The format is read from the extension: `.json` is JSON, `.csv` is CSV, anything
else is one URL per line. Name it yourself with `-F` when the file is called
something else.

```bash
tls-forge batch -i example/urls.txt        # lines
tls-forge batch -i example/urls.json       # JSON
tls-forge batch -u "https://example.com/,https://example.org/"
cat example/urls.txt | tls-forge batch     # or standard input
```

## Keep the results

```bash
tls-forge batch -i example/urls.csv -o results.jsonl -R reports/
```

`-o` sends the JSON lines to a file, `-R` writes an HTML report. Given a
directory, the report names itself after the run:

```
report written to reports/report-2026-08-16-09:18:54:584.html
```

One line of `results.jsonl`, with the body cut short here:

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

Bodies inline into that file. `-d bodies/` writes them out as files instead and
leaves a path in their place, which is what to do when the pages are large.

## Watch it happen

```bash
tls-forge batch -i example/urls.csv -v
```

```
  200      559 B     52ms       https://example.com/
  200      559 B     59ms       https://example.org/
  200      559 B     84ms       https://example.net/
```

Under that, a status line redraws while the run goes:

```
3/3  0 running  1.7 kB  1s elapsed
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
column compose rather than override.

## Warmed cookies

[`cookies.json`](cookies.json) holds two sessions. Name one:

```bash
tls-forge fetch --cookies example/cookies.json --cookie-set warm-eu https://example.com/
```

```
warmed from example/cookies.json, set warm-eu, 2 cookies
```

Name none and one is drawn at random, which is what a file of warmed sessions is
for. Eight runs of the command below chose `warm-eu` three times and `warm-us`
five:

```bash
tls-forge fetch --cookies example/cookies.json https://example.com/
```

A cookie by hand, without a file, for the times one value is all that is needed:

```bash
tls-forge fetch -b "session=abc" -b "consent=accepted" https://example.com/
```

[`cookies-browser-export.json`](cookies-browser-export.json) is the flat array an
extension writes, `httpOnly` and `expirationDate` and all. It is read as one set,
and gets the id `1` because the export gave it none:

```bash
tls-forge fetch --cookies example/cookies-browser-export.json https://example.com/
```

```
warmed from example/cookies-browser-export.json, set 1, 2 cookies
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
tls-forge fetch --cookies example/cookies.txt https://example.com/
```

```
warmed from example/cookies.txt, set 1, 3 cookies
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
tls-forge fetch --cookies jar.txt …       # this reads it

tls-forge fetch --save-cookies jar.txt …  # this warms it
curl -b jar.txt https://example.com/            # curl reads it
```

### Writing a session down

```bash
tls-forge fetch --save-cookies session.json https://example.com/
tls-forge batch -i example/urls.csv --save-cookies session.json
```

The file's name says which format. A `.txt` is written as a cookies.txt and
**replaced**, because that is what a jar written down means to everything else
that reads one. Anything else is this project's JSON, which holds sets, so a run
is **added** to what the file already had and one file builds up over time. In
`batch` that is one set per proxy, each noting which exit warmed it.

Written `0600` either way: a warmed session is a credential.

## Everything at once

```bash
tls-forge batch \
  -i example/urls.csv \
  --cookies example/cookies.json --cookie-set warm-eu \
  --save-cookies session.json \
  -c 8 --repeat 3 -v \
  -o results.jsonl -R reports/
```

A list, a warmed session to start from, the session written back when it is
done, eight pages at a time, three further tries for anything that does not
load, a line per request, the results as JSON lines and a report to look at.

## Where to read more

The [project README](../README.md) documents every command and flag, the file
formats in full, and how the impersonation is verified.
