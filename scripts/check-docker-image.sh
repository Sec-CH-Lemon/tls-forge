#!/usr/bin/env bash
# What a built image does when it is run: as somebody other than root, who can
# write where it works and where it keeps its configuration. fetch keeps a run
# under its working directory, the proxy makes its authority in the
# configuration directory, and both the proxy and the echo server stop in
# order when Docker stops them.
#
#   scripts/check-docker-image.sh IMAGE
set -euo pipefail

image=${1:?usage: scripts/check-docker-image.sh IMAGE}

docker run --rm --entrypoint sh "$image" -c '
  set -e
  [ "$(id -u)" != 0 ] || { echo "the image runs as root" >&2; exit 1; }
  [ "$(pwd)" = /work ] || { echo "it works in $(pwd), not /work" >&2; exit 1; }
  touch /work/.written && rm /work/.written
  touch "$HOME/.written" && rm "$HOME/.written"
  # Nothing answers on the port, which fails the request and not the keeping
  # of the run. Not 9 (discard), nor any port Chrome sends nothing to: fetch
  # refuses those as a usage error before it keeps anything.
  tls-forge fetch --no-exit-lookup --timeout 2s --output kept http://127.0.0.1:59999/ > /dev/null 2>&1 || true
  ls kept | grep -q "^run-.*\.log$" || { echo "fetch kept no run under /work" >&2; exit 1; }
'

# docker stop sends SIGTERM, which ends each of them with 0, well before the
# ten seconds after which Docker would kill it.
for command in proxy serve; do
  container=$(docker run --detach "$image" "$command")
  sleep 2
  if [ "$command" = proxy ] &&
    ! docker exec "$container" sh -c 'test -s "$HOME/.config/tls-forge/ca.pem"'; then
    echo "the proxy made no authority under its configuration directory" >&2
    docker rm --force "$container" > /dev/null
    exit 1
  fi
  started=$(date +%s)
  docker stop "$container" > /dev/null
  took=$(($(date +%s) - started))
  code=$(docker inspect --format '{{.State.ExitCode}}' "$container")
  docker rm "$container" > /dev/null
  if [ "$code" != 0 ] || [ "$took" -ge 10 ]; then
    echo "$command ended with $code ${took}s after it was stopped" >&2
    exit 1
  fi
done
