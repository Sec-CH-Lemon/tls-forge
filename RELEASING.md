# Releasing

A release is a tag. Pushing `vX.Y.Z` starts
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds
everything once, holds it to the same gates as a push to `main`, and publishes
it to npm, PyPI, GitHub Releases, the Homebrew tap and the GitHub Container
Registry. Nothing reads the version from a committed file: the tag is the
version, and every package is stamped from it.

## Before the tag

1. `main` is green, and `make check` passes on the commit to be tagged.
2. `[Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) becomes
   `[X.Y.Z] - YYYY-MM-DD`, dated the day of the tag, with an empty
   `[Unreleased]` above it.
3. `THIRD-PARTY-NOTICES.txt` is current: `make notices` changes nothing. The
   release checks this and stops when it is stale.

## The tag

```bash
git tag -a vX.Y.Z -m vX.Y.Z
git push origin vX.Y.Z
```

A pre-release is `vX.Y.Z-rc.N`, or `-alpha`, `-beta`, `-pre`, `-preview` or
`-dev` with an optional number: spellings npm and PyPI classify the same way.
A tag of any other shape stops the release before it builds anything.

## What the workflow does

1. **build**: runs the gates (vet, race tests, the coverage gate, govulncheck,
   golangci-lint, the Node.js and Python suites, the real-daemon smoke test,
   the release-script tests and the examples) and checks the notices. It
   cross-compiles five binaries, packs each with `LICENSE`, `NOTICE`,
   `THIRD-PARTY-NOTICES.txt` and `README.md` into a `.tar.gz`, and assembles
   the npm packages, the Python wheels and the Homebrew formula. It installs
   and runs the Linux npm package and wheel, and saves everything as one
   artifact, `release-artifacts`, kept for two days.
2. **go-platforms** builds, vets and tests the module on Linux, macOS and
   Windows. **package-smoke** installs and runs the saved npm packages and
   wheels on each of them.
3. **publish-npm**, in the `release` environment, publishes the platform
   packages first and the main package last, since it pins them by exact
   version. A package already published at this version with the same
   integrity is skipped; one with different contents stops the release.
   Packages carry provenance. A pre-release goes under the `next` tag, a
   release under `latest`.
4. **publish-pypi**, in the `release` environment, publishes the wheels
   through trusted publishing: PyPI checks the job's OIDC token against the
   publisher configured on the project, and attestations are published with
   the files.
5. **github-release** creates the GitHub release for the tag, with generated
   notes, the archives and the licence files, marked as a pre-release for a
   pre-release tag.
6. **homebrew**, for a release and never a pre-release, pushes
   `Formula/tls-forge.rb` to `Sec-CH-Lemon/homebrew-tap`. A formula that has
   not changed is left as it is.
7. **image** builds `linux/amd64` and `linux/arm64` and pushes them to
   `ghcr.io` under the version and `X.Y`; `latest` moves for a release only.
   It pulls both back and runs them.

## What it needs

- The `release` environment, which the two publishing jobs run in.
- `NPM_TOKEN`, to create packages that do not exist yet. Once npm's trusted
  publishing is configured for each package, npm prefers OIDC and the secret
  can be deleted.
- A trusted publisher on the PyPI project for this repository and workflow.
- `HOMEBREW_TAP_TOKEN`, which can write to `Sec-CH-Lemon/homebrew-tap`. A
  release fails without it rather than shipping without a formula.
- Nothing for the image: the workflow's own token can push to the
  repository's registry.

## After the tag

The release workflow proves the files it is about to publish. What the
registries then serve is proved by the
[`published e2e`](.github/workflows/published-e2e.yml) workflow, run by hand
for the version:

```bash
gh workflow run published-e2e.yml --ref main -f version=X.Y.Z -f check_brew=true
```

Disable `check_brew` for a pre-release, or for an older version once the tap
has moved past it.

## When a release fails part of the way

Re-run the failed jobs of the same workflow run while `release-artifacts`
still exists, two days after the build, so that what is published is what was
tested.

- **publish-npm** can be re-run: packages already published with the same
  integrity are skipped.
- **publish-pypi** cannot simply be re-run after it uploaded some files: PyPI
  refuses a file it already has. The rest have to be uploaded from the same
  artifact by hand.
- **github-release** fails when the release already exists. Delete the
  release it made, not the tag, before re-running it.
- **homebrew** can be re-run: an unchanged formula is left as it is.
- **image** can be re-run: it pushes the same tags again.

A version is never built twice. A release that cannot be finished from its
own artifact is abandoned, and the next version is tagged.
