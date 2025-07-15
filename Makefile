GO_MODULE := $(shell git config --get remote.origin.url | grep -o 'github\.com[:/][^.]*' | tr ':' '/')
CMD_NAME := kanopy-oidc-lib
GIT_COMMIT := $(shell git rev-parse HEAD)
VERSION ?= dirty

RUN ?= .*
PKG ?= ./...
.PHONY: test
test: ## Run tests in local environment
	golangci-lint run --timeout=5m $(PKG)
	go test -cover -race -run=$(RUN) $(PKG)

.PHONY: go-prep
go-prep: ## Prepare go environment
	go mod tidy
	go mod download

.PHONY: license-check
license-check: ## Check licenses of dependencies
	licensed cache
	licensed status

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
