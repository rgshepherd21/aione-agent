MODULE   := github.com/shepherdtech/aione-agent
BINARY   := aione-agent
CMD      := ./cmd/agent

VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILT    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS  := -s -w \
            -X main.version=$(VERSION) \
            -X main.gitCommit=$(COMMIT) \
            -X main.buildTime=$(BUILT)

GOFLAGS  := -trimpath
GOOS     ?= $(shell go env GOOS)
GOARCH   ?= $(shell go env GOARCH)

.PHONY: all build build-all test lint vet fmt clean docker run help

all: build

## build: compile for the current platform
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	  go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD)

## build-all: cross-compile for all supported targets
build-all:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_linux_amd64   $(CMD)
	GOOS=linux   GOARCH=arm64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_linux_arm64   $(CMD)
	GOOS=darwin  GOARCH=amd64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_darwin_amd64  $(CMD)
	GOOS=darwin  GOARCH=arm64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_darwin_arm64  $(CMD)
	GOOS=windows GOARCH=amd64  CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_windows_amd64.exe $(CMD)
	@echo "Checksums:"
	@sha256sum dist/*

## test: run tests with race detector
test:
	go test -race -count=1 ./...

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format source with gofmt
fmt:
	gofmt -w -l .

## tidy: tidy and verify modules
tidy:
	go mod tidy
	go mod verify

## clean: remove built artifacts
clean:
	rm -rf bin/ dist/

## docker: build the container image
docker:
	docker build -t shepherdtech/aione-agent:$(VERSION) -t shepherdtech/aione-agent:latest .

## run: build and run locally (reads AIONE_INSTALL_TOKEN and AIONE_API_URL from env)
run: build
	./bin/$(BINARY) -config configs/agent.yaml

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## //'
