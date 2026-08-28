# Releasing

A release is a tag. Push `v0.1.0` and everything else happens on its own:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The version has exactly one source. Nothing reads it from a committed file —
the tag is it, and every package is stamped from it. There is no version to
bump, no file to edit, and therefore no way for two of them to disagree.

What that one tag produces:

| | where it lands |
|---|---|
| binaries and tarballs | the GitHub Release, five platforms |
| npm packages | `tls-forge` plus one binary package per platform |
| Python wheels | `tls-forge` on PyPI, one wheel per platform, plus an sdist |
| Docker image | `ghcr.io/sec-ch-lemon/tls-forge`, linux/amd64 and arm64 |
| Homebrew formula | `Sec-CH-Lemon/homebrew-tap` |

Before any of it publishes, the tag runs the same gates a push does — `go vet`,
the race suite, 100% Go coverage, `govulncheck`, golangci-lint, Go tests on
Linux/macOS/Windows, the Node and Python suites, and a real-daemon wrapper smoke
test — and checks that `THIRD-PARTY-NOTICES.txt` is current. A release is the
worst moment to find out a test was failing. Third-party Actions in the release
and drift paths use stable major tags such as `@v7` and `@v8`, so patch and
security fixes arrive without silently crossing a breaking major version.

## What to set up first, once

There are five pieces of external state. The workflow cannot create or inspect
them for you, so check these before pushing the first tag.

### 1. GitHub — the release environment and permissions

Create an environment named **`release`** under Settings → Environments. The npm
and PyPI publishing jobs both use it, and both trusted-publisher configurations
below must name it exactly. Required reviewers are optional; adding one turns a
tag into an approval-gated release without changing the workflow.

The workflow declares least-privilege permissions per job: the build is
read-only, npm and PyPI get OIDC, the GitHub Release gets `contents: write`, and
the image gets `packages: write`. The repository's default workflow permission
may remain read-only, but an organisation policy must not forbid those explicit
write grants. Protect tags matching `v*` if not every repository writer should
be able to publish a release.

### 2. npm — bootstrap once, then use trusted publishing

The packages publish under the `@sec-ch-lemon` scope, so that scope has to
exist and your account has to own it. npm has no pending-publisher mechanism:
a package must exist before a trusted publisher can be attached. The first
release therefore needs a short-lived bootstrap token.

1. Create the organisation `sec-ch-lemon` at
   [npmjs.com/org/create](https://www.npmjs.com/org/create). The free plan is
   enough for public packages.
2. Create a **granular access token** under Access Tokens → Generate New Token:
   - enable **Bypass two-factor authentication**;
   - grant **Packages and scopes → Read and write → All packages**, because the
     six package names do not exist yet and cannot be selected individually;
   - use the shortest expiration that comfortably covers the first release.
3. Put it in the repository as `NPM_TOKEN` (Settings → Secrets and variables →
   Actions → New repository secret).

The current npm instructions for these settings are in
[Creating and viewing access tokens](https://docs.npmjs.com/creating-and-viewing-access-tokens/).

After the first successful release, open Settings → Trusted publishing on each
of these six npm packages:

- `tls-forge`
- `@sec-ch-lemon/tls-forge-darwin-arm64`
- `@sec-ch-lemon/tls-forge-darwin-x64`
- `@sec-ch-lemon/tls-forge-linux-arm64`
- `@sec-ch-lemon/tls-forge-linux-x64`
- `@sec-ch-lemon/tls-forge-win32-x64`

Use the same values for every package:

| field | value |
|---|---|
| Organization or user | `Sec-CH-Lemon` |
| Repository | `tls-forge` |
| Workflow filename | `release.yml` |
| Environment name | `release` |
| Allowed action | `npm publish` |

Then delete the `NPM_TOKEN` repository secret and revoke the token. npm CLI
prefers the short-lived OIDC credential when a trusted publisher exists and
falls back to `NPM_TOKEN` only for the bootstrap release. Provenance is
generated in either path.
See npm's [Trusted publishing guide](https://docs.npmjs.com/trusted-publishers/)
for the package-side configuration.

### 3. PyPI — a pending trusted publisher, and no token

PyPI can verify that an upload came from this workflow, in this repository, by
checking the OIDC token GitHub signs for it. Nothing to store, nothing to
rotate, nothing that can leak.

The project does not exist yet, so create a **pending** publisher — one that
brings the project into being on its first upload:

1. Sign in at [pypi.org](https://pypi.org) and go to
   [Your projects → Publishing](https://pypi.org/manage/account/publishing/).
2. Under "Add a new pending publisher", fill in exactly:

   | field | value |
   |---|---|
   | PyPI Project Name | `tls-forge` |
   | Owner | `Sec-CH-Lemon` |
   | Repository name | `tls-forge` |
   | Workflow name | `release.yml` |
   | Environment name | `release` |

3. Save. That is all — there is no `PYPI_TOKEN` to create.

This is PyPI's documented
[pending publisher flow](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

`tls-forge` is free on PyPI as of this writing. The name is claimed by the
first successful upload, so if you want to hold it earlier, do the dry run
below.

### 4. Homebrew — a repository and a cross-repo token

The workflow writes the formula into a separate tap repository, which its own
`GITHUB_TOKEN` cannot reach.

1. Create a public repository called **`homebrew-tap`** under `Sec-CH-Lemon`.
   The `homebrew-` prefix is what makes `brew tap Sec-CH-Lemon/tap` work; the
   repository can otherwise be empty.
2. Make a fine-grained personal access token
   ([Settings → Developer settings → Fine-grained tokens](https://github.com/settings/personal-access-tokens/new)):
   - Resource owner: `Sec-CH-Lemon`
   - Repository access: only `homebrew-tap`
   - Permissions: **Contents → Read and write**
3. Put it in the `tls-forge` repository as `HOMEBREW_TAP_TOKEN`.

Skipping this is safe: without the secret, the release says so, leaves the
formula at `dist/tls-forge.rb`, and carries on. Everything else still
publishes.

### 5. GHCR — nothing to create, one thing to click afterwards

The image pushes with the workflow's own token, so there is no secret. But a
package created this way is **private by default**, and `docker pull` will ask
strangers to log in.

After the first release: repository → Packages → `tls-forge` → Package settings
→ Change visibility → **Public**. Once only; later releases keep it.

## Do a dry run first

Publishing across registries is not transactional. npm and PyPI publish in
independent jobs, so one can succeed while the other fails. Make the first tag
one that does not matter:

```bash
git tag -a v0.0.1-rc1 -m "release plumbing"
git push origin v0.0.1-rc1
```

A pre-release tag stays off every stable channel: npm publishes it under
`next` without moving `latest`, PyPI reads `0.0.1rc1` as a pre-release that a
plain `pip install tls-forge` will not select, GitHub marks the release as a
pre-release, Docker leaves `latest` where it is, and Homebrew is not updated.
Use `alpha`, `beta`, `rc` or `dev`, optionally followed by a number (with or
without a dot); arbitrary SemVer suffixes are rejected because npm and PyPI do
not always classify them as the same kind of release.

Then check what came out:

```bash
npm view tls-forge dist-tags versions
pip index versions tls-forge
docker pull ghcr.io/sec-ch-lemon/tls-forge:0.0.1-rc1
```

To undo a tag that failed before it published anything:

```bash
git push --delete origin v0.0.1-rc1
git tag -d v0.0.1-rc1
```

A version that **did** publish cannot be undone anywhere: npm unpublish is
limited to 72 hours, PyPI does not allow re-uploading a version even after
deleting it, and a deleted git tag does not remove either. Burn version
numbers freely on release candidates and treat every published number as spent.

## If a release fails halfway

The workflow stops where it failed and every registry write that already
succeeded remains. If no publish job started, retrying the failed workflow is
safe. Once any package was accepted by npm or PyPI, do not retry the same
release: registries reject duplicate versions and npm may already contain only
some of the six packages.

The way back is a new patch version. Fix the cause, tag `v0.1.1`, and let the
whole thing run again — a registry that already has `0.1.0` simply gains
`0.1.1`, and one that never got it gets `0.1.1` first. Do not try to publish
`0.1.0` by hand into the registry that missed it; a version that means
different things in two places is worse than a gap.

## What the pipeline actually does

`release.yml`, in order:

1. **Gates.** Go vet, race tests, 100% Go coverage, vulnerability and lint
   checks, Go on all supported OSes, Node/Python unit suites and their smoke
   tests against the real daemon, notices current.
2. **Cross-compile** five binaries with `CGO_ENABLED=0`, stamped with the tag,
   and run the linux one to prove it starts.
3. **Package** release archives, six npm tarballs, five Python wheels and an
   sdist, all with the required licence notices.
4. **Prove the distributions** by installing the exact npm tarballs and wheels
   on Linux, macOS and Windows and running their bundled binaries.
5. **Freeze the artifacts** in one short-lived GitHub Actions artifact. The
   following jobs publish these exact tested bytes and run no project build
   code with publishing credentials.
6. **Publish npm and PyPI** in separate least-privilege jobs. npm publishes all
   platform tarballs before the main package; PyPI uploads all wheels and the
   sdist together through Trusted Publishing.
7. **Create the GitHub Release** only after both registries succeeded.
8. **Update Homebrew** only for a stable release, after the GitHub assets exist.
9. **Build the image** for linux/amd64 and arm64, push it to GHCR, then pull it
   back and run it on both platforms.

None of the packaging is exercised only at release time. CI runs the same
cross-compile and both packaging scripts on every push, packs and installs the
npm distributions, and installs the built wheel. Authentication itself cannot
be dry-run in CI, which is why the first tag should be a release candidate.

## Adding a platform

Four lists, and they have to agree:

| file | what to add |
|---|---|
| `.github/workflows/release.yml` | the `goos/goarch` pair, in both loops |
| `.github/workflows/ci.yml` | the same pair in the `packaging` job |
| `scripts/npm-release.mjs` | `TARGETS`: npm's platform and arch names beside Go's |
| `scripts/pypi-release.py` | `TARGETS`: the wheel platform tag beside Go's |

Both scripts fail loudly when a binary they expect is missing, so a pair added
in one place and forgotten in another stops the release rather than shipping a
package that quietly has no binary in it.
