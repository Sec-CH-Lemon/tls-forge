#!/usr/bin/env bash
# What is generated or tidied, made again beside the checkout and held to what
# is committed, which it leaves as it was: Go formatted, go.mod and go.sum tidy
# and as their sums say, the report's stylesheet as its template makes it, and
# the third-party notices as the modules linked into the binary make them.
#
#   scripts/check-generated.sh
set -euo pipefail

cd "$(dirname "$0")/.."
made=$(mktemp -d)
trap 'rm -rf "$made"' EXIT
status=0

unformatted=$(git ls-files -z '*.go' | xargs -0 gofmt -l)
if [ -n "$unformatted" ]; then
  printf 'not formatted; gofmt -w them:\n%s\n' "$unformatted" >&2
  status=1
fi

if ! go mod tidy -diff; then
  echo "go.mod or go.sum is not tidy; run go mod tidy" >&2
  status=1
fi
if ! go mod verify > /dev/null; then
  echo "a module in the cache is not as go.sum says" >&2
  status=1
fi

if ! (
  cd tools/report-css
  npm ci --silent --no-audit --no-fund
  npx --no-install tailwindcss -i report.in.css -o "$made/report.css" --minify
) > "$made/css.log" 2>&1; then
  echo "the report's stylesheet could not be made:" >&2
  cat "$made/css.log" >&2
  status=1
elif ! cmp -s "$made/report.css" cmd/tls-forge/report.css; then
  echo "cmd/tls-forge/report.css is not what its template makes; run make report-css" >&2
  status=1
fi

if ! ./scripts/notices.sh > "$made/notices.txt"; then
  echo "the third-party notices could not be made" >&2
  status=1
elif ! cmp -s "$made/notices.txt" THIRD-PARTY-NOTICES.txt; then
  echo "THIRD-PARTY-NOTICES.txt is not what the linked modules make; run make notices" >&2
  status=1
fi
exit "$status"
