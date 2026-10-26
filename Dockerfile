# Build the command line tool.
#
# Two stages: the Go toolchain never reaches the published image, which is
# alpine plus one static binary. Alpine rather than scratch because this is a
# tool people reach for interactively, and a shell to look around in is worth
# the few megabytes; the binary itself needs nothing from it.

# Each base is pinned by digest as well as by tag: the tag says which release,
# the digest that every build gets the same image of it, which a tag moved
# under it cannot change. Dependabot proposes the next digest
# (.github/dependabot.yml), to be reviewed like any other change.

# Pinned to the machine doing the building, not to the machine the image is
# for. Go cross-compiles, so an arm64 image can be produced on an amd64 runner
# in seconds; letting the builder stage run under emulation instead would mean
# running the entire Go toolchain through QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build

WORKDIR /src

# The module graph changes far less often than the code, so the download lands
# in its own layer and survives edits to everything below.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Stamped from the build argument so `tls-forge version` inside the image says
# something true. Passed by `make docker` and by the release workflow.
ARG VERSION

# Supplied by BuildKit, one pair per platform being built.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -ldflags "-s -w ${VERSION:+-X main.version=${VERSION}}" \
      -o /out/tls-forge ./cmd/tls-forge


FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

# Certificate authorities. Without them the binary reaches every site and
# refuses every one of them, which looks like a network fault rather than a
# missing trust store.
RUN apk add --no-cache ca-certificates

# A user rather than root, and a home directory that exists: `tls-forge proxy`
# writes its signing authority under the user's config directory, and Go has no
# config directory to offer when HOME is unset. The working directory is the
# user's too, made so here rather than left to however WORKDIR makes it, which
# has not always been as the user: `fetch --output` keeps a run under it.
RUN adduser -D -h /home/tlsforge tlsforge \
 && mkdir /work && chown tlsforge:tlsforge /work
ENV HOME=/home/tlsforge
USER tlsforge
WORKDIR /work

COPY --from=build /out/tls-forge /usr/local/bin/tls-forge

# The licences of everything linked into the binary require their notices to
# travel with it, and an image is a form of redistribution.
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.txt /usr/local/share/tls-forge/

ENTRYPOINT ["tls-forge"]
CMD ["--help"]
