# Lists and concurrency

The CLI accepts URLs as arguments, comma-separated text, a file, or standard input. Supply **one** input source per invocation.

```bash
tls-forge fetch https://example.com/ https://example.org/
tls-forge fetch --urls 'https://example.com/,https://example.org/' --json
tls-forge fetch --input urls.csv --format csv --concurrency 8 --json
cat urls.txt | tls-forge fetch --output pages/ --json
```

`--format` is `auto`, `lines`, `json`, or `csv`. The input is validated before fetching. `--concurrency` is the number of simultaneous workers; `--repeat` repeats each input row. With shipped profiles, each request has a fresh browser network instance. Concurrency does not imply a shared browser session.

## SDK equivalents

Go's `Client` is safe for concurrent use. Node.js and Python SDK clients serialize requests through one daemon process; create a pool of clients for parallel work, usually one per desired proxy or identity. Keep each client within its own lifetime and close it when done. If a workflow needs cookies, cache or a connection to carry across calls, use an explicitly client-scoped JSON profile and test the state sequence; see [cookies and sessions](cookies.md).

The CLI's CSV/JSON/line parser, progress display, per-row reports and files are CLI features. SDK callers own their own input parsing, scheduling and report storage.
