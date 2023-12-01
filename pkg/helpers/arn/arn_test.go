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

func TestParseArn(t *testing.T) {
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
		{"invalid", "alias/123", true, "missing required ARN components"},
		{"invalid", "key/123", true, "missing required ARN components"},
		{"invalid", "key/mrk-123", true, "missing required ARN components"},
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
		{"valid", "arn:aws:kms:random:123:key/123", false, ""},
		{"valid", "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320", false, ""},
		{"valid", "arn:aws:kms:eu-west-1:123454678901:key/mrk-80bd2fac-c07d-438a-837e-36e19bd4d320", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyArn, err := ParseArn(tt.keyID)
			errValidate := ValidateKeyArn(tt.keyID)
			if tt.wantErr {
				require.Error(t, err)
				require.Error(t, errValidate)
				require.ErrorIs(t, err, ErrMalformedArn)
				require.ErrorIs(t, errValidate, ErrMalformedArn)
				require.ErrorContains(t, err, tt.errString)
				require.ErrorContains(t, errValidate, tt.errString)

				require.EqualError(t, err, errValidate.Error())

				require.Nil(t, keyArn)
				return
			}
			require.NoError(t, err)
			require.NoError(t, errValidate)
			require.NotNil(t, keyArn)
		})
	}
}

func TestKeyArn_String(t *testing.T) {
	tests := []struct {
		name   string
		keyArn KeyArn
		want   string
	}{
		{
			name: "Standard ARN",
			keyArn: KeyArn{
				Partition:    "aws",
				Service:      "kms",
				Region:       "us-west-2",
				Account:      "123456789012",
				ResourceType: "key",
				ResourceID:   "abcd1234",
			},
			want: "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
		},
		{
			name: "Alias ARN",
			keyArn: KeyArn{
				Partition:    "aws",
				Service:      "kms",
				Region:       "eu-west-1",
				Account:      "210987654321",
				ResourceType: "alias",
				ResourceID:   "my-alias",
			},
			want: "arn:aws:kms:eu-west-1:210987654321:alias/my-alias",
		},
		{
			name: "MRK ARN",
			keyArn: KeyArn{
				Partition:    "aws",
				Service:      "kms",
				Region:       "eu-central-1",
				Account:      "123456789012",
				ResourceType: "key",
				ResourceID:   "mrk-1234abcd",
			},
			want: "arn:aws:kms:eu-central-1:123456789012:key/mrk-1234abcd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.keyArn.String())
		})
	}
}

func TestKeyArn_IsMrk(t *testing.T) {
	tests := []struct {
		name   string
		keyArn KeyArn
		want   bool
	}{
		{
			name: "MRK ARN",
			keyArn: KeyArn{
				ResourceType: KeyResourceType,
				ResourceID:   "mrk-1234",
			},
			want: true,
		},
		{
			name: "Standard Key ARN",
			keyArn: KeyArn{
				ResourceType: KeyResourceType,
				ResourceID:   "abcd1234",
			},
			want: false,
		},
		{
			name: "Alias ARN",
			keyArn: KeyArn{
				ResourceType: aliasResourceType,
				ResourceID:   "my-alias",
			},
			want: false,
		},
		{
			name: "Empty Resource Type and ID",
			keyArn: KeyArn{
				ResourceType: "",
				ResourceID:   "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.keyArn.IsMrk())
		})
	}
}
