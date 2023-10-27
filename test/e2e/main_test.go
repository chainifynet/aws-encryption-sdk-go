// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main_test

import (
	"os"
	"testing"

	"github.com/rs/zerolog"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
)

var log = logger.L().Level(zerolog.DebugLevel)

var (
	key1Arn = os.Getenv("KEY_1_ARN")
	key2Arn = os.Getenv("KEY_2_ARN")
	key3Arn = os.Getenv("KEY_3_ARN")
)

func init() {
	log.Trace().Msg("Setting up the test suite")
}

func TestMain(m *testing.M) {
	code := m.Run()

	log.Trace().Msg("Tearing down the test suite...")
	os.Exit(code)
}

var setupGroupTest = func(t *testing.T) {
	if key1Arn == "" || key2Arn == "" || key3Arn == "" {
		t.Fatalf("KEY_1_ARN, KEY_2_ARN, KEY_3_ARN env variables must be set for this test")
	}
}
