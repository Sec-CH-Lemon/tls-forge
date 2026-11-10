# Get started

<p class="tf-lede">Install TLS Forge and make your first request with a selected browser network profile.</p>

<div class="tf-actions">
  <a class="tf-action" href="getting-started/install-cli/">Install the CLI <span aria-hidden="true">→</span></a>
  <a class="tf-action tf-action--secondary" href="integrations/">Choose an interface <span aria-hidden="true">→</span></a>
</div>

<div class="tf-feature">
  <div>
    <h2>Collect a response in one command</h2>
    <p><code>fetch</code> makes an HTTP request using the selected profile. It collects HTML, JSON, or another response for your application; it does not render a page or execute JavaScript.</p>
    <a href="guides/requests/">Make requests <span aria-hidden="true">→</span></a>
  </div>
  <div class="tf-feature-code">
    <div class="tf-feature-code__head">Terminal</div>
    <pre><code>tls-forge fetch \
  --profile chrome \
  --print-body \
  https://example.com/</code></pre>
  </div>
</div>

<div class="tf-version-note">
  <strong>Engine 1.1.0 · not yet released</strong>
  <span>Latest published release: 1.0.1, engine 1 as well. Keep the binary, SDK, and profile on the same engine major. <a href="support/release-status/">Release status →</a></span>
</div>

## Start building

<p class="tf-section-intro">Choose the installation path that fits your project. Each guide includes the next step after installation.</p>

<div class="tf-card-grid">
  <a class="tf-card" href="getting-started/install-cli/"><strong>Install the CLI</strong><span>Download a release binary, use Homebrew, install with Go, or build from source.</span></a>
  <a class="tf-card" href="getting-started/docker/"><strong>Use Docker</strong><span>Run the CLI in a container or build an image from the current checkout.</span></a>
  <a class="tf-card" href="getting-started/go/"><strong>Go library</strong><span>Create a native client, choose a profile, and make your first request.</span></a>
  <a class="tf-card" href="getting-started/node/"><strong>Node.js SDK</strong><span>Use the ESM package and its engine-matched transport binary.</span></a>
  <a class="tf-card" href="getting-started/python/"><strong>Python SDK</strong><span>Install a wheel and use the client as a context manager.</span></a>
  <a class="tf-card" href="getting-started/verify/"><strong>Verify an installation</strong><span>Inspect the version and profiles, then compare a bounded scenario.</span></a>
</div>

## Common use cases

<p class="tf-section-intro">Follow a task guide and switch between CLI, Go, Node.js, and Python examples where the interface supports the same result.</p>

<div class="tf-card-grid">
  <a class="tf-card" href="guides/requests/"><strong>Collect a response</strong><span>Make GET and POST requests, read response bodies, and handle failures.</span></a>
  <a class="tf-card" href="guides/browser-context/"><strong>Describe browser context</strong><span>Choose navigation, form, <code>fetch()</code>, or XHR semantics.</span></a>
  <a class="tf-card" href="guides/proxies/"><strong>Route through a proxy</strong><span>Configure an upstream HTTP, HTTPS, or SOCKS proxy.</span></a>
  <a class="tf-card" href="guides/cookies/"><strong>Handle cookies and sessions</strong><span>Seed or save cookies and understand request versus client scope.</span></a>
  <a class="tf-card" href="guides/capture-compare/"><strong>Capture and compare</strong><span>Measure a real browser and inspect differences in a local fixture.</span></a>
  <a class="tf-card" href="guides/profiles/"><strong>Configure a profile</strong><span>Understand JSON behavior choices and the strict engine-major gate.</span></a>
</div>

## Explore the reference

<div class="tf-card-grid">
  <a class="tf-card" href="reference/cli/"><strong>CLI commands and flags</strong><span>Generated from the current executable's help output.</span></a>
  <a class="tf-card" href="reference/go-api/"><strong>Go API</strong><span>Generated from exported declarations and organized by package.</span></a>
  <a class="tf-card" href="reference/node-api/"><strong>Node.js API</strong><span>Generated from the public TypeScript declarations.</span></a>
  <a class="tf-card" href="reference/python-api/"><strong>Python API</strong><span>Generated from public exports and runtime signatures.</span></a>
</div>

## Scope

TLS Forge models selected browser **network** behavior. It cannot run JavaScript, reproduce a DOM, solve a challenge, or control the host TCP stack. The local [proxy](integrations/proxy.md) terminates incoming HTTPS and opens a new outbound profile-shaped connection; HTTPS callers must trust its printed CA. Read [scope and limits](support/limits.md) before treating a fingerprint match as a browser match.
