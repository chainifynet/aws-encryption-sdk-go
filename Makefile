SHELL=/usr/bin/env bash

UNIT_TEST_TAGS=
BUILD_TAGS=-tags "example,mocks,codegen,integration,slow"
CI_TAGS="example,mocks,codegen,integration"

GOTESTSUM_FMT="github-actions"
#GOTESTSUM_FMT="standard-verbose"
#GOTESTSUM_FMT="pkgname-and-test-fails"
#GOTESTSUM_FMT="testname"

SDK_PKGS=./pkg/...

RUN_NONE=-run NOTHING
RUN_INTEG=-run '^Test_Integration_'

.DEFAULT_GOAL := help

.PHONY: help
help:	## Show the help menu
	@echo "Usage: make <target>"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all deps mocks mocks-build-tag vet lint lint-ci lint-local unit
all: unit	## Run all the checks and tests
	@echo "All checks and tests"

deps: ## Install development dependencies
	@echo "Installing dependencies"
	@go mod download -x all
	@go install gotest.tools/gotestsum@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.2
	@go install github.com/vektra/mockery/v2@v2.49.1
	@#go get github.com/stretchr/testify/mock@v1.8.4

mocks: ## Generate mocks
	@echo "Generating mocks"
	@mockery
	@#$(MAKE) mocks-build-tag

mocks-build-tag:
	@echo "Adding mocks build tag to mock files"
	@if [ "$$(uname)" = "Darwin" ]; then \
		find ./mocks/ -name '*_mock.go' -exec gsed -i '/^package/ i //go:build mocks\n' {} +; \
	else \
		find ./mocks/ -name '*_mock.go' -exec sed -i '/^package/ i //go:build mocks\n' {} +; \
	fi

lint: mocks vet lint-ci ## Generate mocks and run all linters

lint-ci:
	@echo "Running golangci-lint"
	@golangci-lint run --build-tags=${CI_TAGS} --out-format=colored-line-number ./...

lint-local:
	@echo "Running golangci-lint locally"
	@which golangci-lint
	@golangci-lint --version
	@golangci-lint run --build-tags=${CI_TAGS} ./...

.PHONY: examples lint-examples run-examples

examples: lint-examples run-examples ## Lint and run all examples

lint-examples:
	@for dir in $(shell find ./example -type d -mindepth 1 -maxdepth 1); do \
		echo "Running golangci-lint in: $$dir"; \
		(cd $$dir && go get && go mod tidy && golangci-lint run ./...) || exit $$?; \
	done

run-examples:
	@for dir in $(shell find ./example -type d -mindepth 1 -maxdepth 1); do \
		echo "Running example: $$dir"; \
		(cd $$dir && go get && go mod tidy && go run ./...) || exit $$?; \
		echo "Done"; \
		echo "================"; \
	done

vet: ## Run go vet
	@go vet ${BUILD_TAGS} --all ${SDK_PKGS}

##
# Unit tests
##
.PHONY: unit-race unit-pkg

unit: lint unit-pkg ## Run all unit tests

unit-pkg:
	@gotestsum -f ${GOTESTSUM_FMT} -- -timeout=4m ${BUILD_TAGS} ${SDK_PKGS}

unit-race:
	@gotestsum -f ${GOTESTSUM_FMT} -- -timeout=6m -cpu=4 -race -count=1 ${BUILD_TAGS} ${SDK_PKGS}

##
# Integration tests
##
.PHONY: e2e e2e-deps e2e-test e2e-test-cli e2e-test-short e2e-test-full e2e-test-slow

e2e: lint e2e-deps e2e-test-cli e2e-test-short

e2e-test: e2e-test-cli e2e-test-short	## Run e2e short integration tests

e2e-deps: ## Install e2e dependencies
	@echo "Installing e2e dependencies"
	@pip install aws-encryption-sdk-cli
	@aws-encryption-cli --version
	@aws --version

e2e-test-cli:
	@echo "Running e2e CLI test"
	@gotestsum -f ${GOTESTSUM_FMT} -- -timeout=1m -tags "integration" -run '^Test_Cli_Integration' ./test/e2e/...

e2e-test-short:
	@echo "Running e2e short tests"
	@gotestsum -f ${GOTESTSUM_FMT} -- -short -timeout=10m -tags "integration" ${RUN_INTEG} ./test/e2e/...

e2e-test-full: ## Run all e2e integration tests
	@echo "Running full e2e tests, it will take a while"
	@gotestsum -f ${GOTESTSUM_FMT} -- -timeout=15m -tags "integration" ${RUN_INTEG} ./test/e2e/...

e2e-test-slow: ## Run all slow e2e integration tests
	@echo "Running very slow e2e tests"
	@gotestsum -f testname -- -timeout=30m -tags "integration,slow" ${RUN_INTEG} ./test/e2e/...

##
# Coverage
##

.PHONY: test-cover cover-html

test-cover:	## Run tests with coverage
	@#CGO_ENABLED=1 go test -count=1 -coverpkg=./... -covermode=atomic -coverprofile coverage.out  ./...
	@CGO_ENABLED=1 go test -timeout=10m -tags example,mocks,codegen,integration -cpu=2 -count=1 -coverpkg=./... -covermode=atomic -coverprofile=coverage.out ./pkg/...
	@#CGO_ENABLED=1 go test -tags ${CI_TAGS} -count=1 -coverpkg=./... -covermode=atomic -coverprofile coverage.out ./pkg/...
	@grep -v -E -f .covignore coverage.out > coverage.filtered.out
	@mv coverage.filtered.out coverage.out

cover-html:	## Convert coverage to HTML report
	@go tool cover -html=coverage.out -o coverage.html
