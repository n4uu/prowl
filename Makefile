VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet lint demo validate-exports clean install

build:
	go build -ldflags "$(LDFLAGS)" -o bin/prowl ./cmd/prowl

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run || \
		echo "golangci-lint not installed, ran go vet only"

# Full hunt against the built-in synthetic dataset. No key, no network.
demo: build
	./bin/prowl demo -out prowl-out

# Checks the demo's STIX and MISP output with the reference libraries.
# Needs: pip install stix2 pymisp
validate-exports: demo
	python3 scripts/validate_exports.py prowl-out

clean:
	rm -rf bin prowl-out

install: build
	install -Dm755 bin/prowl /usr/local/bin/prowl
