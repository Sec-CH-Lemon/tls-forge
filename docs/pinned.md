# The pinned reference

A release of tls-forge is held to one build of Google Chrome, the reference:
the profile it ships is compared with that browser, and the release goes ahead
only if they match. `go run ./internal/pinned` is the check. It is not part of
what ships.

The browser on a CI runner is no reference: it is whatever an action installs
that week, often Chrome for Testing, which turns on experiments real users do
not have. The `browser` job in `ci.yml` compares with it to show drift, and
fails nothing. The pinned check fails a release.

## What the reference is

Google publishes no archive of past builds of Google Chrome, only the current
one, so whoever releases keeps the installers of the builds the profiles were
measured on, for as long as those profiles are supported. Google's terms do not
allow handing them on, so the archive is private, and is never a release asset.
The manifest that says what is in it is committed:

```json
{
  "schema": 1,
  "version": "155.0.8059.80",
  "profile": "chrome_155",
  "launch": {"headless": false, "args": ["--no-sandbox"]},
  "builds": [
    {
      "platform": "linux",
      "arch": "amd64",
      "installer": "google-chrome-stable_155.0.8059.80-1_amd64.deb",
      "installer_sha256": "…",
      "binary": "opt/google/chrome/chrome",
      "binary_sha256": "…"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `version` | Google Chrome's full version, as `--version` says it |
| `profile` | the profile held to it |
| `launch` | how it is started to be measured: with a window or headless, and its arguments. Headless Chrome says `HeadlessChrome` in its user agent, so a headed profile is held to a headed browser |
| `builds` | one for each platform (`linux`, `macos`, `windows`) and machine (`amd64`, `arm64`) |
| `installer`, `installer_sha256` | the installer's file name in the archive, and its SHA-256 in lower-case hex |
| `binary`, `binary_sha256` | the browser's executable once installed, relative to where it is installed, with forward slashes, and its SHA-256 |

The manifest is read strictly: a field the format does not have, another
schema, a version that is not a full one, a hash that is not 64 lower-case hex
digits, an installer that is not a bare file name, a binary path that is not
clean and relative, or one platform and machine twice is an error.

## What the check does

```bash
go run ./internal/pinned --manifest reference/chrome.json \
  --archive /path/to/archive --installed /path/to/installed \
  [--out result.json] [--commit SHA] [--set DIGEST] \
  [--requests FILE] [--decoding FILE] [--scenario-timeout 45m]
```

In order, and stopping at the first that fails:

1. It reads the manifest and takes the build for the machine it runs on, and
   reads the fixtures of what a page does, `--requests` and `--decoding`,
   `testdata/chrome155-requests.json` and `testdata/chrome155-decoding.json`
   unless said.
2. It hashes the installer in `--archive` and holds it to `installer_sha256`.
3. It hashes the browser installed in `--installed` and holds it to
   `binary_sha256`.
4. It reads the executable's header, ELF, Mach-O (universal ones too) or PE,
   and holds its platform and machine to the build's.
5. It asks the browser `--version`, and holds the answer to `Google Chrome`
   and the version exactly: Chrome for Testing, Chromium or another version
   is refused, by name. On Windows, where `chrome.exe --version` starts the
   browser instead, it reads the product name and version the executable
   holds, with PowerShell.
6. It compares the profile with the browser, launched as `launch` says,
   exactly as `tls-forge compare` does, and writes the result and what it
   held to what to `--out`, with what the result is for: the commit a
   release is built from (`--commit`, else `GITHUB_SHA`) and the identity
   of the release's set (`--set`, the SHA-256 of its `manifest.json`). A
   release takes a result only for its own commit and its own set.
7. It measures the browser on the bench in `internal/harness`, headless as
   the fixtures were measured, with `launch`'s arguments, which are for the
   machine (`--no-sandbox` on a hosted runner), every scenario of a page over HTTP/2 and over
   HTTP/1.1 and every page whose decoding is asked about, within
   `--scenario-timeout`, and holds it to the fixtures tls-forge is tested
   against: every request in order, its method, URL, body, HTTP/2 priority,
   the names of its headers in order and spelling and their values, and what
   it made of each page. A value the machine decides (the user agent, the
   window, the memory, the network, the system's version and processor) is
   compared by its presence; one the build decides (`sec-ch-ua`, its
   platform, its full version and form factor) is held to the profile's, and
   each of either has to be one the profile has, or tls-forge would not send
   it. What differs goes to `--out` as `scenarios`, and the result does not
   pass.

It exits 0 only when every field compared matches, nothing is left
unchecked and the browser is what the fixtures say; 1 when anything does not
hold, saying what; 2 when it is not told
where the manifest, the archive and the installed browser are, or is given a
commit that is not 40 lower-case hex digits or a set that is not 64, before it
measures anything. A reference it cannot find or check is a failure, never a
reason to measure another browser.

## In a release

The release workflow runs the check on every build `reference/chrome.json`
names, each on a runner of its platform and machine, after the release's set
is stored and before anything is published ([RELEASING.md](../RELEASING.md)):

1. `scripts/release-set.mjs gates` reads the reference and names a gate for
   each build. No reference, or one that names no build, stops the release.
2. `scripts/pinned-restore.mjs` fetches the build's installer from the
   private archive, at `PINNED_ARCHIVE_URL/<installer>`, with
   `PINNED_ARCHIVE_TOKEN` as a bearer token when it is set. It holds the
   installer to `installer_sha256` before anything opens it, and unpacks it
   without installing it for the machine: a `.deb` by `dpkg-deb`, a `.dmg`
   mounted and copied, an `.msi` by an administrative install, or an archive
   of an installed browser by `tar`.
3. The check runs with `--commit` and `--set`, under `xvfb-run` on Linux,
   and its result is kept in the tag's draft as
   `pinned-<platform>-<arch>.json`.
4. Each publishing job verifies the set with every gate result: each passed,
   for this commit and this set. A result for another commit or another set
   counts for nothing.

A result kept in the draft is not measured again when the release is run
again; a gate that failed is.

## What is left

The check, the manifest format, the restore and the release workflow that
runs them exist. The archive does not: its installers have to be kept, by
whoever releases, from the day a profile is measured, with the manifest
committed beside the profiles as `reference/chrome.json` and the archive's
address and token as the repository's secrets. Until then every release
stops at the gate, and the drift check in `ci.yml` and `drift.yml` stays what
it is: a measurement of the browser of the day.

Run today against Google Chrome 155.0.8059.80 on macOS, headless, the
comparison finds the user agent alone, `HeadlessChrome`, which a headed
reference does not send: `:path` goes into HPACK as Chrome writes it, through
tls-forge's fork of fhttp ([support](support.md)). On the bench, the same
Chrome is what both fixtures say, every scenario and every page.

The fixtures were measured on macOS. Every profile of `chrome_155` has the
values of the client hints a server asks for, as Chrome sent them on its
platform (Linux's and Windows's on GitHub's runners), so a build for Linux or
Windows is held to its own platform's values in the scenarios that ask for
them.
