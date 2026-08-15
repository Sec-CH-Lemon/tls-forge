# Build the command line tool.
#
# Two stages: the Go toolchain never reaches the published image, which is
# alpine plus one static binary. Alpine rather than scratch because this is a
# tool people reach for interactively, and a shell to look around in is worth
# the few megabytes; the binary itself needs nothing from it.

FROM golang:1.24-alpine AS build

WORKDIR /src

# The module graph changes far less often than the code, so the download lands
# in its own layer and survives edits to everything below.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Stamped from the build argument so `tls-forge version` inside the image says
# something true. Passed by `make docker` and by the release workflow.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
      -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tls-forge ./cmd/tls-forge


FROM alpine:3.21

# Certificate authorities. Without them the binary reaches every site and
# refuses every one of them, which looks like a network fault rather than a
# missing trust store.
RUN apk add --no-cache ca-certificates

# A user rather than root, and a home directory that exists: `tls-forge proxy`
# writes its signing authority under the user's config directory, and Go has no
# config directory to offer when HOME is unset.
RUN adduser -D -h /home/tlsforge tlsforge
ENV HOME=/home/tlsforge
USER tlsforge
WORKDIR /work

COPY --from=build /out/tls-forge /usr/local/bin/tls-forge

# The licences of everything linked into the binary require their notices to
# travel with it, and an image is a form of redistribution.
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.txt /usr/local/share/tls-forge/

ENTRYPOINT ["tls-forge"]
CMD ["--help"]
