GO      ?= go
BIN     ?= bin/tls-forge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COVER   ?= coverage.out
PYTHON  ?= python3
VENV    ?= .venv

.PHONY: all build test cover lint vet fmt node-test python-test wrapper-smoke release-test check dist capture compare notices report-css docker docker-check clean

all: check

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BIN) ./cmd/tls-forge

# -timeout well under the CI job's ceiling, so a test that hangs is killed by
# Go — which prints a goroutine dump naming it — rather than by the runner,
# which prints nothing and leaves you guessing. The whole suite is seconds.
TESTFLAGS ?= -timeout 5m

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

# Cross-language contract test against the real Go daemon. Unit suites use a
# deliberately hostile fake to cover every recovery branch; this one makes
# sure all three implementations still agree on the bytes actually emitted.
wrapper-smoke: build
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q -e 'python[test]'
	cd node && TLSFORGE_REAL_BIN=$(abspath $(BIN)) node --test test/real-daemon.test.js
	cd python && TLSFORGE_REAL_BIN=$(abspath $(BIN)) ../$(VENV)/bin/python -m pytest -q tests/test_real_daemon.py

# Release helpers are outside the language SDKs, so keep their regression tests
# in the repository-level gate rather than hiding them in one wrapper suite.
release-test:
	node --test scripts/homebrew-formula.test.mjs

# Everything CI runs. `test` and `cover` both run the suite — once under the
# race detector, once instrumented — because they catch different things, and
# CI runs them as separate jobs.
check: vet lint test cover node-test python-test wrapper-smoke release-test

# Assemble everything a release publishes, without publishing any of it.
#
# The same path the tag takes, so the packaging can be looked at before a
# version number is spent: a published version cannot be taken back on npm, on
# PyPI or in a git tag someone has already fetched. See RELEASING.md.
RELEASE_VERSION ?= 0.0.0
dist:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install -q build wheel
	rm -rf dist
	@mkdir -p dist/bin
	@for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/amd64; do \
		goos=$${target%/*}; goarch=$${target#*/}; \
		out="dist/bin/tls-forge-$$goos-$$goarch"; \
		[ "$$goos" = windows ] && out="$$out.exe"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch $(GO) build -trimpath \
			-ldflags "-s -w -X main.version=v$(RELEASE_VERSION)" -o "$$out" ./cmd/tls-forge \
			|| exit 1; \
	done
	node scripts/npm-release.mjs --version $(RELEASE_VERSION) --binaries dist/bin --out dist/npm
	$(VENV)/bin/python scripts/pypi-release.py --version $(RELEASE_VERSION) --binaries dist/bin --out dist/pypi
	@echo "\nnothing published. dist/npm and dist/pypi hold what a tag would have sent."

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
	docker run --rm $(IMAGE):latest version
	docker run --rm $(IMAGE):latest profiles > /dev/null

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
