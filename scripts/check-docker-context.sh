#!/usr/bin/env bash
# What a Docker build of this checkout is given, with the checkout made dirty
# the way a developer's is. None of what is left behind goes in: a profile
# measured on the machine above all, since everything under profile/data is
# compiled into the binary. Every file git tracks does, but for what the build
# is told to leave out on purpose. Docker's own matching decides, through a
# build that lists its context, rather than a reading of .dockerignore by
# anything else.
#
#   scripts/check-docker-context.sh
#
# What it makes it takes away again, and nothing that was there before.
set -euo pipefail

cd "$(dirname "$0")/.."

# What a developer's checkout holds and a build must not: a binary built in the
# root, environments and dependencies, staged and measured files, outputs.
junk=(
  tls-forge
  bin/tls-forge
  dist/tls-forge.tar.gz
  tmp/page.html
  .venv/pyvenv.cfg
  python/.venv-3.13/pyvenv.cfg
  node/node_modules/left/index.js
  example/node/node_modules/left/index.js
  example/typescript/node_modules/left/index.js
  python/src/tlsforge/bin/tls-forge
  python/tests/__pycache__/left.pyc
  python/.mypy_cache/left.json
  python/.pytest_cache/left
  .coverage
  coverage.out
  profile/data/local/macos.json
  report-20261017T000000Z.html
  report-20261017T000000Z.json
  .claude/worktrees/left/go.mod
)

made_files=()
made_dirs=()
listed=$(mktemp -d)
# Run by the trap below, on every way out.
# shellcheck disable=SC2329
cleanup() {
  for file in ${made_files[@]+"${made_files[@]}"}; do rm -f "$file"; done
  # Innermost first, and only those it made, once emptied.
  local i
  for ((i = ${#made_dirs[@]} - 1; i >= 0; i--)); do rmdir "${made_dirs[i]}" 2>/dev/null || true; done
  rm -rf "$listed"
}
trap cleanup EXIT

for path in "${junk[@]}"; do
  [ -e "$path" ] && continue
  # Each directory it has to make on the way, outermost first.
  missing=()
  dir=$(dirname "$path")
  while [ "$dir" != "." ] && [ ! -d "$dir" ]; do
    missing=("$dir" ${missing[@]+"${missing[@]}"})
    dir=$(dirname "$dir")
  done
  for dir in ${missing[@]+"${missing[@]}"}; do
    mkdir "$dir"
    made_dirs+=("$dir")
  done
  printf 'left behind\n' > "$path"
  made_files+=("$path")
done

docker build --quiet --file - --output "type=local,dest=$listed" . > /dev/null <<'DOCKERFILE'
FROM busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e AS list
COPY . /context
RUN cd /context && find . \( -type f -o -type l \) | sed 's|^\./||' | sort > /context.txt
FROM scratch
COPY --from=list /context.txt /
DOCKERFILE
context="$listed/context.txt"

status=0
for path in "${junk[@]}"; do
  if grep -qxF "$path" "$context"; then
    echo "the build context holds $path" >&2
    status=1
  fi
done
# Every file git tracks, but for the history, CI and the documentation, which
# the build is told to leave out.
while IFS= read -r path; do
  case "$path" in
    .github/* | docs/*) continue ;;
  esac
  if ! grep -qxF "$path" "$context"; then
    echo "the build context lacks $path" >&2
    status=1
  fi
done < <(git ls-files)
exit "$status"
