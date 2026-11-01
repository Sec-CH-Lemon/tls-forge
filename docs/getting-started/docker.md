# Docker

The release image is published for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/sec-ch-lemon/tls-forge
docker run --rm ghcr.io/sec-ch-lemon/tls-forge \
  fetch --print-body https://example.com/
```

To build the current checkout instead:

```bash
docker build -t tls-forge:dev .
docker run --rm tls-forge:dev version
```

The image's entry point is the CLI, so `fetch`, `proxy`, `profiles`, `serve`, `daemon`, and `version` use the same command names. The small release image excludes a browser and intentionally does not support browser capture or comparison.

## Read and write local files

Mount one working directory and refer to paths inside the container:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/sec-ch-lemon/tls-forge \
  fetch --input /work/urls.csv --output /work/out --json
```

The image runs as `tlsforge` in `/work`. The mounted directory must be writable by that user for `--output`, cookie saves, reports, logs, or traces. On Linux you can use `--user "$(id -u):$(id -g)"` when the host permissions require it.

## Use the local proxy from the host

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/proxy-state:/work" ghcr.io/sec-ch-lemon/tls-forge \
  proxy --addr 0.0.0.0:8080 --ca-cert /work/ca.pem --ca-key /work/ca.key
```

The proxy prints its CA certificate path. An HTTPS client using it must trust that CA; keep its private key private. Bind the published host port to loopback unless you deliberately secure a wider listener. Read the [proxy guide](../integrations/proxy.md) before using it with an application.
