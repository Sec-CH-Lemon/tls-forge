# CLI

The CLI combines request execution with list input, concurrency, progress, reports, traces, capture and comparison. `tls-forge --help` shows its commands; `tls-forge <command> --help` shows every flag. The [generated CLI reference](../reference/cli.md) contains those exact outputs from the source executable.

| Command | Purpose | Guide |
| --- | --- | --- |
| `fetch` | Collect one or many HTTP responses | [Requests](../guides/requests.md), [lists](../guides/batch.md) |
| `capture` | Measure an installed or manually opened browser | [Capture and compare](../guides/capture-compare.md) |
| `compare` | Compare browser and client in a local fixture | [Capture and compare](../guides/capture-compare.md) |
| `profiles` | List selectable profiles | [Profiles](../guides/profiles.md) |
| `proxy` | Run a local intercepting proxy | [Local proxy](proxy.md) |
| `serve` | Run the local fingerprint echo server | [Capture and compare](../guides/capture-compare.md) |
| `daemon` | Speak JSON Lines to another program | [Daemon protocol](daemon.md) |
| `version` | Print the compiled version | [Verify](../getting-started/verify.md) |

CLI exit codes distinguish success (**0**), execution error (**1**), usage error (**2**), and completed comparison with differences (**3**). See [errors and exit codes](../reference/errors.md).
