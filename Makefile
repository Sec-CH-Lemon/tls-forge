GO      ?= go
BIN     ?= bin/tls-forge
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COVER   ?= coverage.out

.PHONY: all build test cover lint vet fmt node-test check capture compare notices docker docker-check clean

all: check

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BIN) ./cmd/tls-forge

test:
	$(GO) test -race ./...

# Coverage is a gate, not a report. Every package here is at 100%, because most
# of the interesting code is error handling that using the library normally
# never reaches.
cover:
	$(GO) test -covermode=set -coverprofile=$(COVER) ./...
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

node-test:
	cd node && npm test

# Everything CI runs. `test` and `cover` both run the suite — once under the
# race detector, once instrumented — because they catch different things, and
# CI runs them as separate jobs.
check: vet lint test cover node-test

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

clean:
	rm -rf bin $(COVER) node/vendor
