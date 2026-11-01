# Troubleshooting

## The executable or SDK has a different engine major

Run `tls-forge version` and inspect the selected profile's top-level `engine_major`. A development engine 1 binary executes only engine 1 profiles. Node.js and Python also check their daemon binary before requests. Update the binary, SDK and profile together, or explicitly migrate and revalidate a profile. Renaming it or changing the marker alone does not establish compatibility.

## `capture` or `compare` cannot start a browser

Request execution does not need a browser; measurement does. Install a Chromium-based browser or pass `--browser /absolute/path/to/browser`. For an unsupported or remote browser, use `--manual` and open the printed local page yourself. A `compare` execution failure is exit 1; measured differences are exit 3.

## HTTPS through the local proxy fails certificate validation

The local intercepting proxy presents certificates signed by its printed CA. Configure the caller to trust that CA and keep the CA key private. An upstream proxy and the local listener have separate certificate and authentication concerns.

## A POST is rejected by a language SDK

The shipped Chrome profiles require a browser context for a non-GET. Supply the real `form`, `fetch`, or `xhr` kind and initiator page. The CLI can infer an XHR of the target origin's root when `--request-kind` is omitted; the SDKs do not apply that CLI convenience.

## Responses do not share cookies or connections

Bundled profiles use request scope: each call starts with a fresh browser network instance. Seed cookies explicitly or use a separately validated client-scoped profile for a stateful sequence. Reusing the same Node.js or Python `Client` object alone does not change the shipped profile's scope.

## A page check never finds a script-created element

`--wait-for-element` examines returned HTML bytes. It does not execute scripts. Use a browser automation tool when the element exists only after JavaScript runs; TLS Forge may still be useful for separate HTTP requests made by that workflow.

## The Docker container cannot write `--output`

The image runs as `tlsforge`. Make the mounted directory writable by that user or run the container with a suitable `--user`. Use a dedicated output directory, especially with `--clear-output-dir`.

For a reproducible bug report, include the CLI version, exact profile name and major, platform, command with secrets removed, observed error, and the relevant request or wire scenario. Avoid attaching key logs, captures, credentials or cookies to a public issue.
