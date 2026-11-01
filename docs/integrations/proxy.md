# Local intercepting proxy

`tls-forge proxy` accepts HTTP(S) requests from another program, terminates incoming HTTPS, and opens a **new outbound connection** with the selected profile. It does not create a browser process, browser context or page behaviour for the caller.

```bash title="Terminal"
tls-forge proxy --profile chrome --addr 127.0.0.1:8080
```

The proxy prints the generated CA certificate location. An HTTPS client must trust that CA or it will reject the proxy's certificate. Store the CA private key securely. The default listener is loopback and has no authentication; binding beyond loopback requires your own network access controls.

To use an upstream proxy as the outbound route, add `--proxy` or `--proxy-env`. `--ca-cert` and `--ca-key` select persistent CA files. `--max-request-body` bounds buffering. The [CLI reference](../reference/cli.md#proxy) lists all flags.

For Go embedding, use the `proxy` package's `Start` and `Options` types, documented in the [generated Go API](../reference/go-api.md). Node.js and Python clients use the daemon for their own requests; they do not start this listener.
