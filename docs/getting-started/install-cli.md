# Install the CLI

The release binary supports macOS and Linux on arm64 and x86-64, and Windows on x86-64. Published artifacts and the current development source can differ; see [release status](../support/release-status.md).

## Release binary

1. Download your platform archive from [GitHub Releases](https://github.com/Sec-CH-Lemon/tls-forge/releases). Releases **after 0.2.2** also carry `SHA256SUMS` and GitHub attestations.
2. When the selected release provides them, check its checksum and attestation before extracting the archive.
3. Extract `tls-forge` (or `tls-forge.exe`) onto `PATH`.

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify tls-forge_X.Y.Z_linux_amd64.tar.gz --repo Sec-CH-Lemon/tls-forge
mkdir -p ~/.local/bin
install -m 0755 tls-forge ~/.local/bin/tls-forge
tls-forge version
```

On macOS, use `shasum -a 256` if `sha256sum` is unavailable. Replace the example archive name with the file you downloaded. The release's actual filenames and available verification artifacts are authoritative.

On Windows, the release archive is also a `.tar.gz`. Extract it in PowerShell, then place `tls-forge.exe` in a directory on your `PATH`:

```powershell
tar -xzf .\tls-forge_X.Y.Z_windows_amd64.tar.gz
$destination = Join-Path $env:LOCALAPPDATA 'tls-forge'
New-Item -ItemType Directory -Force $destination | Out-Null
Copy-Item .\tls-forge.exe $destination
& (Join-Path $destination 'tls-forge.exe') version
```

## Homebrew

```bash
brew tap Sec-CH-Lemon/tap
brew trust --formula Sec-CH-Lemon/tap/tls-forge
brew install tls-forge
tls-forge version
```

Review the third-party tap before granting trust. This installs the published formula, not the current `development` tree.

## Go install

With Go **1.26.10** or newer:

```bash
go install github.com/Sec-CH-Lemon/tls-forge/cmd/tls-forge@latest
```

Go writes the binary to `GOBIN` or `$(go env GOPATH)/bin`. `@latest` selects the latest published module version; use the source-build path for a particular development commit.

## Build from source

```bash
git clone https://github.com/Sec-CH-Lemon/tls-forge.git
cd tls-forge
git checkout development
make build
./bin/tls-forge version
```

`make build` uses the version declared in `engine/version.json`. To build without Make:

```bash
go build -o tls-forge ./cmd/tls-forge
./tls-forge version
```

The project builds without cgo. The `Dockerfile` is another source build path; see [Docker](docker.md). `capture` and `compare` additionally require a Chromium-based browser. The small release image does not contain one.

## Next step

[Verify your installation](verify.md), then [make a request](../guides/requests.md).
