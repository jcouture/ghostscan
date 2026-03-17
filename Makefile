APP ?= ghostscan
MODULE ?= github.com/jcouture/ghostscan
VERSION_PKG ?= $(MODULE)/cmd
BIN_DIR ?= bin
BIN ?= $(BIN_DIR)/$(APP)
GORELEASER ?= go run github.com/goreleaser/goreleaser/v2@v2.12.7
SVU ?= go run github.com/caarlos0/svu/v3@v3.2.2

GOFLAGS ?= -trimpath -buildvcs=false
GOCACHE_DIR ?= $(CURDIR)/.gocache
export GOCACHE := $(GOCACHE_DIR)

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS ?= -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT)
BUILD_FLAGS ?= $(strip $(if $(LDFLAGS),-ldflags "$(LDFLAGS)"))

TEST_PKGS ?= ./...

.PHONY: build clean help fmt fix vet gosec vulncheck tidy precommit test install uninstall release-snapshot tag print-version

.DEFAULT_GOAL := help

## Run unit tests
test:
	@go run gotest.tools/gotestsum@v1.13.0 --format=testdox -- -coverprofile=coverage.out -covermode=atomic $(TEST_PKGS)
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

## Build the binary
build:
	@mkdir -p $(BIN_DIR) $(GOCACHE_DIR)
	@CGO_ENABLED=0 go build $(GOFLAGS) $(BUILD_FLAGS) -o $(BIN) .
	@echo "Built $(BIN)"

## Install to GOPATH/bin
install:
	@CGO_ENABLED=0 go install $(GOFLAGS) $(BUILD_FLAGS) .
	@echo "Installed $(APP) to $$(go env GOPATH)/bin"

## Print the computed release version
print-version:
	@printf '%s\n' "$(VERSION)"

## Uninstall from GOPATH/bin
uninstall:
	@INSTALL_PATH="$${GOBIN:-$$(go env GOPATH)/bin}/$(APP)"; \
	if [ -f "$$INSTALL_PATH" ]; then \
		rm -f "$$INSTALL_PATH"; \
		echo "Uninstalled $(APP) from $$INSTALL_PATH"; \
	else \
		echo "$(APP) not found at $$INSTALL_PATH"; \
	fi

## Format code (writes changes)
fmt:
	@go fmt ./...
	@find . -name '*.go' -not -path './.*' | xargs -r gofmt -s -w
	@echo "Code formatted"

## Apply automated Go fixes
fix:
	@go fix ./...
	@echo "Go fix applied"

## Static analysis (vet)
vet:
	@go vet ./...
	@echo "Vet passed"

## Security analysis (gosec)
gosec:
	@go run github.com/securego/gosec/v2/cmd/gosec@v2.22.1 ./...
	@echo "Gosec passed"

## Vulnerability scanning
vulncheck:
	@go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
	@echo "Vulnerability scan passed"

## Tidy modules (writes go.mod/go.sum if needed)
tidy:
	@go mod tidy -v

## Pre-commit checks (writes fmt/tidy)
precommit: fmt fix tidy vet gosec vulncheck test
	@echo "Pre-commit checks passed"

## Build release artifacts locally without publishing
release-snapshot:
	@$(GORELEASER) release --snapshot --clean
	@echo "Snapshot artifacts written to dist/"

## Create an annotated semver tag (override with VERSION=vX.Y.Z)
tag:
	@VERSION="$${VERSION:-$$($(SVU) next)}"; \
	echo "Creating tag $$VERSION"; \
	git tag -a "$$VERSION" -s -m "Release $$VERSION"; \
	echo "Created $$VERSION"

## Clean build artifacts
clean:
	@echo "GOCACHE_DIR=$(GOCACHE_DIR)"
	@rm -rf "$(BIN_DIR)" dist/ "$(GOCACHE_DIR)"
	@go clean -cache -testcache
	@echo "Cleaned build artifacts"

## Show help
help:
	@echo "$(APP) - Available targets:"
	@echo ""
	@awk '/^##/{help=$$0; sub(/^## */, "", help); next} /^[[:alnum:]_.-]+:/{target=$$1; sub(/:.*/, "", target); if(help){printf "  \\033[36m%-18s\\033[0m %s\\n", target, help; help=""}}' $(MAKEFILE_LIST)
