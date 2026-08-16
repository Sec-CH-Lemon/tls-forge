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
the race suite, 100% Go coverage, the Node suite, the Python suite at 100% of
lines and branches — and checks that `THIRD-PARTY-NOTICES.txt` is current. A
release is the worst moment to find out a test was failing.

## What to set up first, once

Five things, and only three of them need anything from you.

### 1. npm — a token

The packages publish under the `@sec-ch-lemon` scope, so that scope has to
exist and your account has to own it.

1. Create the organisation `sec-ch-lemon` at
   [npmjs.com/org/create](https://www.npmjs.com/org/create). The free plan is
   enough for public packages.
2. Make an **Automation** token (Access Tokens → Generate New Token →
   Classic → Automation). Automation rather than Publish: it bypasses 2FA,
   which a workflow cannot answer.
3. Put it in the repository as `NPM_TOKEN` (Settings → Secrets and variables →
   Actions → New repository secret).

`tls-forge` is free on npm as of this writing, and so are the five scoped
packages, which are yours by virtue of owning the scope.

### 2. PyPI — a trusted publisher, and no token

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
   | Environment name | *leave empty* |

3. Save. That is all — there is no `PYPI_TOKEN` to create.

`tls-forge` is free on PyPI as of this writing. The name is claimed by the
first successful upload, so if you want to hold it earlier, do the dry run
below.

### 3. Homebrew — a repository and a cross-repo token

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

### 4. GHCR — nothing to create, one thing to click afterwards

The image pushes with the workflow's own token, so there is no secret. But a
package created this way is **private by default**, and `docker pull` will ask
strangers to log in.

After the first release: repository → Packages → `tls-forge` → Package settings
→ Change visibility → **Public**. Once only; later releases keep it.

### 5. The repository itself

Nothing to change. `release.yml` already asks for the permissions it needs
(`contents: write` for the release, `id-token: write` for npm provenance and
PyPI, `packages: write` for the image). Confirm that Settings → Actions →
General → Workflow permissions is not set to "read repository contents", which
would override them.

## Do a dry run first

Publishing is not transactional. The registries are written one after another,
and a failure at PyPI leaves npm already published with a version that cannot
be taken back. So make the first tag one that does not matter:

```bash
git tag -a v0.0.1-rc1 -m "release plumbing"
git push origin v0.0.1-rc1
```

A pre-release tag is handled as one throughout: npm gets it as a normal
version, PyPI reads `0.0.1rc1` as a pre-release that `pip install tls-forge`
will not pick up, and the Docker `latest` tag stays where it is rather than
moving to a release candidate.

Then check what came out:

```bash
npm view tls-forge versions
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

The workflow stops where it failed and everything before it stands. Nothing
retries by itself, and re-pushing the same tag will not re-run it.

The way back is a new patch version. Fix the cause, tag `v0.1.1`, and let the
whole thing run again — a registry that already has `0.1.0` simply gains
`0.1.1`, and one that never got it gets `0.1.1` first. Do not try to publish
`0.1.0` by hand into the registry that missed it; a version that means
different things in two places is worse than a gap.

## What the pipeline actually does

`release.yml`, in order:

1. **Gates.** Go vet, race tests, 100% Go coverage, Node suite, Python suite at
   100% lines and branches, notices current.
2. **Cross-compile** five binaries with `CGO_ENABLED=0`, stamped with the tag,
   and run the linux one to prove it starts.
3. **Package** tarballs with the licence notices inside them, npm packages, and
   Python wheels.
4. **Prove the wheel** by installing it into a fresh virtualenv and running the
   binary out of it — the whole chain, including the exec bit, which is lost
   silently and only shows up at someone else's first request.
5. **Publish** npm (platform packages first, since the main one pins them by
   exact version), then PyPI.
6. **GitHub Release** with the tarballs and the notices attached.
7. **Homebrew tap**, last, because the formula carries the release's download
   URL and checksum and would point at nothing if it went first.
8. **The image**, in a second job: built for both platforms, pushed to GHCR,
   then pulled back and run on each — pushing an image that cannot start is
   worse than not pushing one, because it looks like a release.

None of this is exercised only at release time. CI runs the same cross-compile
and both packaging scripts on every push, and installs the built wheel, so the
first tag is not the first time any of it has run.

## Adding a platform

Three lists, and they have to agree:

| file | what to add |
|---|---|
| `.github/workflows/release.yml` | the `goos/goarch` pair, in both loops |
| `.github/workflows/ci.yml` | the same pair in the `packaging` job |
| `scripts/npm-release.mjs` | `TARGETS`: npm's platform and arch names beside Go's |
| `scripts/pypi-release.py` | `TARGETS`: the wheel platform tag beside Go's |

Both scripts fail loudly when a binary they expect is missing, so a pair added
in one place and forgotten in another stops the release rather than shipping a
package that quietly has no binary in it.
