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
  [--out result.json] [--commit SHA] [--set DIGEST]
```

In order, and stopping at the first that fails:

1. It reads the manifest and takes the build for the machine it runs on.
2. It hashes the installer in `--archive` and holds it to `installer_sha256`.
3. It hashes the browser installed in `--installed` and holds it to
   `binary_sha256`.
4. It reads the executable's header, ELF, Mach-O (universal ones too) or PE,
   and holds its platform and machine to the build's.
5. It asks the browser `--version`, and holds the answer to `Google Chrome`
   and the version exactly: Chrome for Testing, Chromium or another version
   is refused, by name.
6. It compares the profile with the browser, launched as `launch` says,
   exactly as `tls-forge compare` does, and writes the result and what it
   held to what to `--out`, with what the result is for: the commit a
   release is built from (`--commit`, else `GITHUB_SHA`) and the identity
   of the release's set (`--set`, the SHA-256 of its `manifest.json`). A
   release takes a result only for its own commit and its own set.

It exits 0 only when every field compared matches and nothing is left
unchecked; 1 when anything does not hold, saying what; 2 when it is not told
where the manifest, the archive and the installed browser are, or is given a
commit that is not 40 lower-case hex digits or a set that is not 64, before it
measures anything. A reference it cannot find or check is a failure, never a
reason to measure another browser.

## What is left

The check, the manifest format and their tests exist. The archive does not:
its installers have to be kept, by whoever releases, from the day a profile is
measured, with the manifest committed beside the profiles as
`reference/chrome.json`. A release workflow that restores the archive and
installs the build, runs the check on every platform a profile ships for, and
makes every publish job depend on it, binding the result to the commit and the
artifacts being published, comes with the rest of the release work. Until
then nothing publishes on this check, and the drift check in `ci.yml` and
`drift.yml` stays what it is: a measurement of the browser of the day.

Run today against Google Chrome 155.0.8059.80 on macOS, the comparison finds
one difference: tls-forge's transport writes `:path` in HPACK with indexing,
where Chrome writes it without ([support](support.md)). The check fails until
that is fixed.
