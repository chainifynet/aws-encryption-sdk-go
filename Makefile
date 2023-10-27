SHELL=/usr/bin/env bash

UNIT_TEST_TAGS=
BUILD_TAGS=-tags "example,codegen,integration,slow"

GOTESTSUM_FMT="github-actions"
#GOTESTSUM_FMT="standard-verbose"
#GOTESTSUM_FMT="pkgname-and-test-fails"
#GOTESTSUM_FMT="testname"

SDK_PKGS=./pkg/...

RUN_NONE=-run NOTHING
RUN_INTEG=-run '^Test_Integration_'

.PHONY: all deps vet lint unit
all: unit

deps:
	@echo "Installing dependencies"
	@go mod download all
	@go install gotest.tools/gotestsum@latest

# add golangci-lint later
lint: vet

vet:
	@go vet ${BUILD_TAGS} --all ${SDK_PKGS}

##
# Unit tests
##
.PHONY: unit-race unit-pkg

unit: vet unit-pkg

unit-pkg:
	@gotestsum -f ${GOTESTSUM_FMT} -- -timeout=1m ${BUILD_TAGS} ${SDK_PKGS}

unit-race:
	@gotestsum -f ${GOTESTSUM_FMT} -- -timeout=2m -cpu=4 -race -count=1 ${BUILD_TAGS} ${SDK_PKGS}

##
# Integration tests
##
.PHONY: e2e e2e-deps e2e-test e2e-test-cli e2e-test-short e2e-test-full e2e-test-slow

e2e: vet e2e-deps e2e-test-cli e2e-test-short

e2e-test: e2e-test-cli e2e-test-short

e2e-deps:
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

e2e-test-full:
	@echo "Running full e2e tests, it will take a while"
	@gotestsum -f testname -- -timeout=15m -tags "integration" ${RUN_INTEG} ./test/e2e/...

e2e-test-slow:
	@echo "Running very slow e2e tests"
	@gotestsum -f testname -- -timeout=30m -tags "integration,slow" ${RUN_INTEG} ./test/e2e/...
