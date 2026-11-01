# API Reference

<div class="tf-api-intro">
  <div>
    <p class="tf-lede">Find the commands, options, types, and profile fields available in the current development source.</p>
    <p>The CLI, Go library, Node.js SDK, and Python SDK use the same engine-major gate. Their public surfaces differ: the CLI owns capture, comparison, reports, and batch input; SDK callers own some of that orchestration.</p>
    <p>References are regenerated from source during the documentation build. Start with an <a href="../integrations/">integration guide</a> for a working request.</p>
  </div>
  <div class="tf-api-panel">
    <span class="tf-api-panel__label">CURRENT SOURCE</span>
    <code>1.0.0 · engine 1 · schema 4</code>
    <p>Unreleased on <code>development</code>. Use a matching binary, SDK, and executable profile.</p>
  </div>
</div>

## Interfaces

<div class="tf-card-grid">
  <a class="tf-card" href="cli/"><strong>CLI commands and flags</strong><span>Exact help output from the current executable.</span></a>
  <a class="tf-card" href="go-api/"><strong>Go API</strong><span>Exported declarations and Go doc comments, organized by package.</span></a>
  <a class="tf-card" href="node-api/"><strong>Node.js API</strong><span>Public TypeScript declarations and request options.</span></a>
  <a class="tf-card" href="python-api/"><strong>Python API</strong><span>Public exports, signatures, methods, and response types.</span></a>
</div>

## Profiles and execution

<div class="tf-card-grid">
  <a class="tf-card" href="profile-behavior/"><strong>Profile behavior</strong><span>JSON sections, policy groups, and safe editing workflow.</span></a>
  <a class="tf-card" href="profile-fields/"><strong>Shipped profile fields</strong><span>Generated inventory of the fields present in bundled JSON files.</span></a>
  <a class="tf-card" href="errors/"><strong>Errors and exit codes</strong><span>Distinguish usage errors, request failures, and comparison differences.</span></a>
</div>
