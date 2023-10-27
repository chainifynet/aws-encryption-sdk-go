// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chainifynet/aws-encryption-sdk-go/test/e2e/testutils"
)

func Test_Cli_Integration_AwsEncryptionSdkCliVersion(t *testing.T) {
	setupGroupTest(t)
	tests := []struct {
		name         string
		cliCmd       *testutils.CliCmd
		input        []byte
		wantContains string
	}{
		{"cli_version_4", testutils.NewVersionCmd(), nil, "aws-encryption-sdk-cli/4"},
		{"cli_sdk_version_3", testutils.NewVersionCmd(), nil, "aws-encryption-sdk/3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := test.cliCmd.Run(test.input, false)
			require.NoError(t, err)
			assert.Contains(t, string(out), test.wantContains)
		})
	}
}
