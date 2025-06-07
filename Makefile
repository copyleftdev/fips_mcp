.PHONY: build test clean run lint

# Build variables
BINARY_NAME := fips-mcp
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse HEAD)
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# FIPS build flags
FIPS_LDFLAGS := -X 'github.com/copyleftdev/fips-mcp/pkg/version.Version=$(VERSION)' \
                -X 'github.com/copyleftdev/fips-mcp/pkg/version.Commit=$(COMMIT)' \
                -X 'github.com/copyleftdev/fips-mcp/pkg/version.BuildTime=$(BUILD_TIME)' \
                -X 'github.com/copyleftdev/fips-mcp/pkg/version.FIPSEnabled=true'

# Standard build
default: build

# Build the binary
build:
	$(GOBUILD) -v -o bin/$(BINARY_NAME) -ldflags="$(FIPS_LDFLAGS)" ./cmd/$(BINARY_NAME)

# Build with FIPS 140-3 compliance
build-fips:
	GOFIPS140=v1.0.0 $(GOBUILD) -v -o bin/$(BINARY_NAME)-fips -ldflags="$(FIPS_LDFLAGS)" ./cmd/$(BINARY_NAME)

# Run tests
test:
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Run linters
lint:
	golangci-lint run --timeout 5m

# Clean build files
clean:
	$(GOCLEAN)
	rm -f bin/$(BINARY_NAME) bin/$(BINARY_NAME)-fips

# Install dependencies
deps:
	$(GOMOD) download

# Run the application
run:
	$(GOBUILD) -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)
	./bin/$(BINARY_NAME)

# Run with FIPS mode
run-fips:
	GODEBUG=fips140=on ./bin/$(BINARY_NAME)-fips

# Generate code (mocks, protobufs, etc.)
generate:
	$(GOCMD) generate ./...

# Update dependencies
update:
	$(GOMOD) tidy -v

# Show help
help:
	@echo 'Available targets:'
	@echo '  build      - Build the application'
	@echo '  build-fips - Build with FIPS 140-3 compliance'
	@echo '  test       - Run tests'
	@echo '  lint       - Run linters'
	@echo '  clean      - Remove build artifacts'
	@echo '  deps       - Download dependencies'
	@echo '  run        - Run the application'
	@echo '  run-fips   - Run with FIPS 140-3 mode enabled'
	@echo '  generate   - Generate code'
	@echo '  update     - Update dependencies'
