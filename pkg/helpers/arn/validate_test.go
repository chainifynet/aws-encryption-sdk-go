// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrMalformedArn(t *testing.T) {
	assert.ErrorContains(t, ErrMalformedArn, "malformed Key ARN")
}

func TestValidateKeyArn(t *testing.T) {
	tests := []struct {
		name      string
		keyID     string
		wantErr   bool
		errString string
	}{
		{"empty", "", true, "missing required ARN components"},
		{"invalid", "arn", true, "missing required ARN components"},
		{"invalid", "arn:", true, "missing required ARN components"},
		{"invalid", ":", true, "missing required ARN components"},
		{"invalid", ":::::", true, "missing 'arn' string"},
		{"invalid", "arn:::::", true, "missing partition"},
		{"invalid", "some:cloud::::", true, "missing 'arn' string"},
		{"invalid", "arn:cloud::::", true, "missing account"},
		{"invalid", "arn:cloud:::123:", true, "missing region"},
		{"invalid", "arn:cloud::random:123:", true, "unknown service"},
		{"invalid", "arn:cloud:some:random:123:", true, "unknown service"},
		{"invalid", "arn:aws:kms:random:123:", true, "missing resource"},
		{"invalid", "arn:aws:kms:random:123:resource", true, "resource section is malformed"},
		{"invalid", "arn:aws:kms:random:123:resource", true, "resource section is malformed"},
		{"invalid", "arn:aws:kms:random:123:resource/", true, "unknown resource type"},
		{"invalid", "arn:aws:kms:random:123:resource/123", true, "unknown resource type"},
		{"invalid", "arn:aws:kms:random:123:key/", true, "missing resource id"},
		{"invalid", "arn:aws:kms:random:123:alias/123", true, "alias keyID is not supported"},
		{"invalid", "arn:aws:kms:random:123:key/mrk-123", true, "KMS MRK not supported"},

		{"valid", "arn:aws:kms:random:123:key/123", false, ""},
		{"valid", "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyArn(tt.keyID)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedArn)
				require.ErrorContains(t, err, tt.errString)
				return
			}
			require.NoError(t, err)
		})
	}
}
