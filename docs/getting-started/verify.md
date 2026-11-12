# Verify an installation

## Check the executable and profiles

```bash title="Terminal"
tls-forge version
tls-forge profiles
```

Release 1.1.0 reports `v1.1.0`. `profiles` lists identities available to this executable. The `chrome` alias resolves to the newest bundled Chrome profile for the host platform; pin an exact profile name when a reproducible identity matters.

## Make one request

```bash title="Terminal"
tls-forge fetch --profile chrome --print-body https://example.com/
```

The response body says that a request completed. It does not prove a browser fingerprint match.

## Compare against a real browser

With an installed Chromium-based browser:

```bash title="Terminal"
tls-forge compare --profile chrome
```

The command measures the browser and client against a local echo server and exits **3** when they differ. A match covers the fields and scenario compared by this command. Separate connection states, browser contexts, QUIC paths, and platforms need their own evidence. Read [capture and compare](../guides/capture-compare.md) and [scope and limits](../support/limits.md).
