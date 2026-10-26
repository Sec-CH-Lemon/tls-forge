GO      ?= go
BIN     ?= bin/tls-forge
VERSION ?= $(shell python3 -c 'import json; print(json.load(open("engine/version.json"))["version"])')
COVER   ?= coverage.out
PYTHON  ?= python3
VENV    ?= .venv

.PHONY: all build test cover lint vet fmt node-test python-test python-typecheck docs-check generated-check workflows-check wrapper-smoke release-test check dist capture compare notices report-css docker docker-check clean

all: check

build:
	$(GO) build -ldflags "-X main.version=v$(VERSION)" -o $(BIN) ./cmd/tls-forge

# -timeout well under the CI job's ceiling, so a test that hangs is killed by
# Go — which prints a goroutine dump naming it — rather than by the runner,
# which prints nothing and leaves you guessing. Under -race the root package
# and the CLI's take about five minutes each, waiting more than working.
TESTFLAGS ?= -timeout 20m

test:
	$(GO) test -race $(TESTFLAGS) ./...

# Coverage is a gate, not a report. Every package here is at 100%, because most
# of the interesting code is error handling that using the library normally
# never reaches.
cover:
	$(GO) test -covermode=set -coverprofile=$(COVER) $(TESTFLAGS) ./...
	@$(GO) tool cover -func=$(COVER) | awk '\
		/^total:/ { total=$$3; next } \
		{ if ($$3 != "100.0%") { print "  " $$0; failed=1 } } \
		END { \
			if (failed) { print "\ncoverage below 100%"; exit 1 } \
			print "all packages at " total \
		}'

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run

# A gate, like `cover`: 100% of lines, functions and branches.
node-test:
	cd node && npm test

# A gate too, and a stricter one than Node's: 100% of lines AND branches.
# Python names the branch it missed, so the number is one somebody can act on.
# The suite runs against a stand-in transport — no Go build, no network.
python-test:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q -e 'python[test]'
	cd python && ../$(VENV)/bin/python -m coverage run -m pytest -q
	cd python && ../$(VENV)/bin/python -m coverage report

# A gate too: the Python package's types, as strictly as mypy checks them,
# since py.typed hands them to every caller's type checker, and
# tests/typing_contract.py, whose refusals have to stay refusals. mypy needs
# Python 3.10; the package itself runs on 3.9.
python-typecheck:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q -e 'python[typecheck]'
	cd python && ../$(VENV)/bin/python -m mypy

# A gate as well: every relative link in a Markdown file git tracks names a
# file git tracks, and every fragment a heading, as a clean checkout has them.
docs-check:
	node --test scripts/check-links.test.mjs
	node scripts/check-links.mjs

# A gate as well: what is generated or tidied, made again beside the checkout
# and held to what is committed, the checkout left as it was.
generated-check:
	scripts/check-generated.sh

# A gate as well: every action a workflow uses is pinned to the commit of a
# release, with the release named beside it, as Dependabot keeps it.
workflows-check:
	node --test --experimental-test-coverage \
		--test-coverage-lines=100 --test-coverage-branches=100 --test-coverage-functions=100 \
		--test-coverage-include='scripts/check-actions.mjs' scripts/check-actions.test.mjs
	node scripts/check-actions.mjs

# Cross-language contract test against the real Go daemon. Unit suites use a
# deliberately hostile fake to cover every recovery branch; this one makes
# sure all three implementations still agree on the bytes actually emitted.
wrapper-smoke: build
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q -e 'python[test]'
	cd node && TLSFORGE_REAL_BIN=$(abspath $(BIN)) node --test test/real-daemon.test.js
	cd python && TLSFORGE_REAL_BIN=$(abspath $(BIN)) ../$(VENV)/bin/python -m pytest -q tests/test_real_daemon.py

# Release helpers are outside the language SDKs, so keep their regression tests
# in the repository-level gate rather than hiding them in one wrapper suite. The
# scripts that package, build, check, hold and publish a release's set, and
# restore the reference it is gated on, are a gate as well: every line, branch
# and function of them covered, as in the SDKs. The Python one is measured by
# coverage.py, its data kept out of the checkout.
release-test:
	node --test --experimental-test-coverage \
		--test-coverage-lines=100 --test-coverage-branches=100 --test-coverage-functions=100 \
		--test-coverage-include='scripts/release-*.mjs' --test-coverage-include='scripts/check-release-packages.mjs' \
		--test-coverage-include='scripts/pinned-restore.mjs' --test-coverage-include='scripts/npm-release.mjs' \
		--test-coverage-include='scripts/homebrew-formula.mjs' --test-coverage-exclude='scripts/*.test.mjs' \
		scripts/homebrew-formula.test.mjs scripts/npm-release.test.mjs scripts/release-set.test.mjs \
		scripts/release-publish.test.mjs scripts/release-build.test.mjs scripts/check-release-packages.test.mjs \
		scripts/pinned-restore.test.mjs
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q -e 'python[test]'
	@data=$$(mktemp) && \
		PYTHONDONTWRITEBYTECODE=1 $(VENV)/bin/python -m coverage run --branch --data-file="$$data" \
			--include=scripts/pypi-release.py -m pytest -q -p no:cacheprovider -W error scripts/test_pypi_release.py && \
		$(VENV)/bin/python -m coverage report --data-file="$$data" --fail-under=100 --show-missing; \
		status=$$?; rm -f "$$data"; exit $$status

# Everything CI runs. `test` and `cover` both run the suite — once under the
# race detector, once instrumented — because they catch different things, and
# CI runs them as separate jobs.
check: vet lint test cover node-test python-test python-typecheck docs-check generated-check workflows-check wrapper-smoke release-test

# Assemble everything a release publishes, without publishing any of it.
#
# scripts/release-build.mjs builds a release's set and verifies it, so the
# packaging can be looked at before a version number is spent: a published
# version cannot be taken back on npm, on PyPI or in a git tag someone has
# already fetched. The set's manifest names HEAD, whatever the working tree
# holds. The version is the engine's (engine/version.json), the only one
# release-build.mjs builds a set of. See RELEASING.md.
RELEASE_VERSION ?= $(VERSION)
dist:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q build wheel
	rm -rf dist
	node scripts/release-build.mjs --version $(RELEASE_VERSION) --commit "$$(git rev-parse HEAD)" \
		--out dist/set --python $(VENV)/bin/python
	@echo "\nnothing published. dist/set holds what a tag would build, with its SHA256SUMS and manifest.json."

# Measure the browser on this machine. The profile is named after the browser
# it came from, so it lands in profile/data/ ready to commit.
capture: build
	@mkdir -p profile/data
	$(BIN) capture --save profile/data/.captured.json
	@name=$$(sed -n 's/.*"name": "\(.*\)",/\1/p' profile/data/.captured.json | head -1); \
		mv profile/data/.captured.json profile/data/$$name.json; \
		echo "wrote profile/data/$$name.json"

# Is the impersonation still true? Exits non-zero when it is not, so this can
# gate a release — a browser update is exactly when it stops being true.
compare: build
	$(BIN) compare

IMAGE ?= tls-forge

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

# Build the image and prove the binary inside it runs. A Dockerfile that no
# longer builds is easy to miss, since nothing else in the repository needs it.
docker-check: docker
	scripts/check-docker-context.sh
	docker run --rm $(IMAGE):latest version
	docker run --rm $(IMAGE):latest profiles > /dev/null
	scripts/check-docker-image.sh $(IMAGE):latest

# The npm packages ship a compiled binary with every dependency linked into it,
# and those licences require their notices to travel along. Regenerate whenever
# the dependency set changes.
notices:
	./scripts/notices.sh > THIRD-PARTY-NOTICES.txt

# The report's stylesheet, generated from cmd/tls-forge/report.html by Tailwind
# and committed alongside it.
#
# Committed rather than built, because the report has to stay one self-contained
# file: fetching a stylesheet would need a network to read it, and building one
# would need Node to build tls-forge. Neither is true for anyone but whoever
# edits the template, and TestReportStylesheetCoversTheTemplate fails if they
# edit it and forget this.
report-css:
	cd tools/report-css && npm install --silent && npm run build

clean:
	rm -rf bin dist $(COVER) node/vendor tools/report-css/node_modules $(VENV) \
		python/.coverage python/src/*.egg-info python/src/tlsforge/bin
