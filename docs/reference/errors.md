# Errors and exit codes

## CLI process status

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed; a `compare` found no difference in its measured scope. |
| `1` | Execution failed, such as I/O, DNS, TLS, proxy, or browser launch. |
| `2` | Usage error, invalid flags/input, or `--help` for a command. |
| `3` | `compare` completed and found a difference. |

Read the command's stderr for detail. A non-2xx HTTP answer is data, not automatically a process failure; `fetch` can retry or apply a body check according to its flags.

## SDK errors

Node.js exports `TLSForgeError`, `BinaryNotFound`, `TransportError`, `SessionReset`, `RequestFailed`, `Unsupported`, and `Timeout`; invalid inputs can also throw built-in `TypeError` or `RangeError`. Python exports similarly named exceptions and can raise `TypeError` or `ValueError` for invalid arguments. Go returns `error` values; callers can inspect wrapped request errors with `errors.As`.

An engine-major mismatch is an execution rejection. It does not fall back to another profile or daemon. See [profiles and compatibility](../guides/profiles.md) and the generated [Node.js](node-api.md) and [Python](python-api.md) references.
