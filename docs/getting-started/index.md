# Install TLS Forge

<p class="tf-lede">Choose one installation path, then run a request using a browser network profile.</p>

<div class="tf-card-grid">
  <a class="tf-card" href="install-cli/#release-binary"><strong>Download a release binary</strong><span>Use a prebuilt archive for macOS, Linux, or Windows. Check available release verification artifacts.</span></a>
  <a class="tf-card" href="install-cli/#homebrew"><strong>Install with Homebrew</strong><span>Use the published third-party tap on macOS or Linux.</span></a>
  <a class="tf-card" href="install-cli/#go-install"><strong>Install the CLI with Go</strong><span>Build the latest published module version with your Go toolchain.</span></a>
  <a class="tf-card" href="install-cli/#build-from-source"><strong>Build from source</strong><span>Compile the unreleased development engine or a custom checkout.</span></a>
  <a class="tf-card" href="docker/"><strong>Run with Docker</strong><span>Use the published Linux image or build an image from this checkout.</span></a>
  <a class="tf-card" href="go/"><strong>Add the Go library</strong><span>Create a native client inside a Go application.</span></a>
  <a class="tf-card" href="node/"><strong>Add the Node.js SDK</strong><span>Use the ESM package and its matching transport executable.</span></a>
  <a class="tf-card" href="python/"><strong>Add the Python SDK</strong><span>Install a wheel and use a context-managed client.</span></a>
</div>

## Make a first request

After installing the CLI, confirm its compiled version and available profiles:

```bash
tls-forge version
tls-forge profiles
tls-forge fetch --profile chrome --print-body https://example.com/
```

A browser is required for `capture` and `compare`; requests, SDKs, and the local proxy do not need one. Read [verification](verify.md) and [request guidance](../guides/requests.md) next.

A profile-shaped request is still an HTTP request. Server authorization, rate limits, challenges, and application logic remain separate concerns.
