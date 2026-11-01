# Output and diagnostics

The CLI has several output modes. Choose the least data needed for your run.

| Need | CLI option | Result |
| --- | --- | --- |
| Body on terminal | `--print-body` | Response body on stdout |
| Status and headers | `--include` | Response head with body, or headers in JSON Lines |
| Machine-readable rows | `--json` | One JSON object per request |
| Every request's files | `--output DIR` | Response, per-request log and trace, plus run log |
| Summary report | `--report`, `--report-format` | HTML, JSON, or both |
| Timeline | `--trace FILE` | Trace Event JSON for Perfetto |
| Detailed log | `--log FILE`, `--log-level` | Text or JSON Lines |
| Wire inspection | `--pcap` with `--output`, `--keylog FILE` | PCAPNG and/or TLS secrets |

```bash
tls-forge fetch --output pages --report=pages/run.html --json \
  https://example.com/
tls-forge fetch --trace trace.json --log run.jsonl --log-level debug \
  https://example.com/
```

`--clear-output-dir` empties the named output directory before the run and refuses protected locations and files the run reads. Use a dedicated directory. A response extension follows the response Content-Type when it identifies a known type; otherwise the tool sniffs the bytes. JSON served as `text/plain` is saved as `.txt`.

PCAPNG, TLS key logs, logs, and reports can contain full response bodies, credentials, cookies or decrypted traffic. Store them only where intended. The CLI masks selected sensitive diagnostic fields, but exported application data remains application data. Node.js and Python SDKs return response data and expose stderr callbacks; they do not produce the CLI's reports or packet captures. Go exposes request traces and key-log output options.
