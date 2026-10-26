# Releasing

A release is a tag. Pushing `vX.Y.Z` starts
[`.github/workflows/release.yml`](.github/workflows/release.yml). It builds
the release's set once, every file it publishes, holds it to the same gates
as a push to `main`, and stores it in the tag's draft GitHub release before
anything is published. Then it publishes that set to npm, PyPI, GitHub
Releases, the Homebrew tap and the GitHub Container Registry. Nothing reads
the version from a committed file: the tag is the version, and every package
is stamped from it.

## Before the tag

1. `main` is green, and `make check` passes on the commit to be tagged.
2. `[Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) becomes
   `[X.Y.Z] - YYYY-MM-DD`, dated the day of the tag, with an empty
   `[Unreleased]` above it.
3. `make generated-check` passes: Go is formatted and tidy, and the
   stylesheet and `THIRD-PARTY-NOTICES.txt` are what their sources make. The
   release checks this and stops when they are stale.
4. `make dist` builds the set as the tag will, into `dist/set`, to look at
   before a version is spent, or run the workflow as a dry run (below).

## The tag

```bash
git tag -a vX.Y.Z -m vX.Y.Z
git push origin vX.Y.Z
```

A pre-release is `vX.Y.Z-rc.N`, or `-alpha`, `-beta`, `-pre`, `-preview` or
`-dev` with an optional number: spellings npm and PyPI classify the same way.
A tag of any other shape stops the release before it builds anything.

## The set

The set is every file a release publishes, in one directory:

- five archives, `tls-forge_X.Y.Z_<os>_<arch>.tar.gz`, each with the binary,
  `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.txt` and `README.md`;
- six npm packages, packed: `tls-forge` and one per platform;
- the Python source distribution and five wheels, named as PyPI spells the
  version (`1.0.0rc1` for `1.0.0-rc.1`);
- the Homebrew formula and the three licence files;
- `SHA256SUMS`, and `manifest.json`, which binds every file by name, size and
  SHA-256 to the version and the commit it was built from.

[`scripts/release-build.mjs`](scripts/release-build.mjs) builds it, and
[`scripts/release-set.mjs`](scripts/release-set.mjs) verifies it: a file
missing, one more than a release has, one not as the manifest says, or a
manifest of another version or commit stops the release. The set's identity
is the SHA-256 of its `manifest.json`.

## What the workflow does

1. **set**, on a tag that has no release yet, runs the gates (vet, race
   tests, the coverage gate, govulncheck, golangci-lint, the Node.js and
   Python suites, the real-daemon smoke test, the release-script tests, the
   examples and `make generated-check`) and builds the set. On a tag whose
   draft or release holds a set already, it takes that set instead and builds
   nothing. Either way it verifies the set against this commit.
2. **go-platforms** builds, vets and tests the module on Linux, macOS and
   Windows. **package-smoke** installs and runs the set's archive, npm package
   and wheel on Linux (x86-64 and arm64), macOS and Windows, and on the oldest
   Node.js and Python the packages support.
3. **store** signs provenance for every file of the set, when this run built
   it, and stores the set in the tag's draft release. The draft takes only
   what it lacks and never a file over one it has; a file there with another
   digest stops the release. The manifest goes last, so a draft holding one
   holds the whole set.
4. **reference** reads `reference/chrome.json` and **pinned** runs the
   pinned gate for each build it names, on a runner of that platform
   ([docs/pinned.md](docs/pinned.md)). It restores the archived Google Chrome
   from the private archive, holds the profile to it, measures it on the
   bench in `internal/harness` against the fixtures of what a page does, and
   keeps the result, bound to this commit and this set, in the draft beside
   the set. No reference, a reference it cannot restore or check, a profile
   that does not match, or a scenario or page that differs stops the release.
5. **publish-npm** and **publish-pypi**, in the `release` environment, verify
   the set again with every gate result, and publish what each registry
   lacks. npm gets the platform packages first and the main package last,
   since it pins them by exact version, with provenance; a pre-release goes
   under `next`, a release under `latest`. PyPI gets its files through
   trusted publishing, with attestations. What a registry has with the same
   digest is passed over; what it has with another stops the release.
6. **finish** holds the draft to the set once more and publishes it.
7. **homebrew**, for a release and never a pre-release, pushes
   `Formula/tls-forge.rb` to `Sec-CH-Lemon/homebrew-tap`, unless the tap has
   this formula already or one of a later version.
8. **image** builds `linux/amd64` and `linux/arm64` and pushes them to
   `ghcr.io` under the version and `X.Y`; `latest` moves for a release only.
   A version the registry has already is not built again. It pulls both back
   and runs them.

## What it needs

- The `release` environment, which the two publishing jobs run in.
- `NPM_TOKEN`, to create packages that do not exist yet. Once npm's trusted
  publishing is configured for each package, npm prefers OIDC and the secret
  can be deleted.
- A trusted publisher on the PyPI project for this repository and workflow.
- `HOMEBREW_TAP_TOKEN`, which can write to `Sec-CH-Lemon/homebrew-tap`. A
  release fails without it rather than shipping without a formula.
- The reference: `reference/chrome.json` committed, the installers it names in
  a private archive, and `PINNED_ARCHIVE_URL` (with `PINNED_ARCHIVE_TOKEN`
  when the archive wants one) to reach it. Until all three exist, every
  release stops at the gate, as it should.
- Nothing for the image: the workflow's own token can push to the
  repository's registry.
- Immutable releases turned on in the repository's settings is recommended:
  once the draft is published, its files and its tag can no longer change.

Every action the workflows use is pinned to the commit of a release, with the
release named beside it, so that what runs is what was read. Dependabot
proposes the week's updates as one pull request, which is reviewed like any
other change: what each action's new commit changes is part of it.

## A dry run

```bash
gh workflow run release.yml --ref main
```

`dry_run` is on unless it is turned off. Off a tag it builds the engine's
version (`engine/version.json`), the only one a set is built of;
`-f version=X.Y.Z` names it, and any other is refused. A dry run builds and checks the set
as a release does, runs the gate when the reference can be restored, and asks
the draft, npm and PyPI what each has, saying what it would give each. It
stores, signs and publishes nothing. Run on a tag, it takes the set the tag
has, if it has one, and says what a release run again would do.

## When a release fails part of the way

Run it again on its tag:

```bash
gh workflow run release.yml --ref vX.Y.Z -f dry_run=false
```

or re-run the failed jobs of the run. Neither builds the set again once it is
stored: the run takes it from the draft, however long ago it was built and
whether or not the run that built it still exists. Everything published
already is passed over, by digest, and the rest is published from the same
files. A run on a tag says, before anything else, where the set stands:

- **no release, and no registry has the version**: nothing was stored or
  published, and the set is built.
- **a draft with its manifest, or a published release**: the set is taken
  from it.
- **a draft without its manifest**: storing the set did not finish. Re-run the
  failed jobs of the run that built it while its artifact lasts, seven days;
  otherwise delete the draft, from which nothing was published, and run the
  release again.
- **no release, and npm or PyPI has the version**: the set was published from
  and is gone, and the release stops.

A version is never built twice. A release that cannot be finished from its
own set is abandoned, and the next version is tagged.

## Checking what was downloaded

A release carries `SHA256SUMS` beside its files, and GitHub keeps signed
provenance for each of them:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

```bash
gh attestation verify tls-forge_X.Y.Z_linux_amd64.tar.gz --repo Sec-CH-Lemon/tls-forge
```

The npm packages carry npm's provenance, and the PyPI files PyPI's
attestations.

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
