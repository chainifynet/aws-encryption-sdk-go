// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsMrkArnEqual(t *testing.T) {
	tests := []struct {
		name string
		key1 string
		key2 string
		want bool
	}{
		{
			name: "Identical ARNs",
			key1: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			key2: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			want: true,
		},
		{
			name: "Different region MRK ARNs",
			key1: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			key2: "arn:aws:kms:us-east-1:123456789012:key/mrk-1234",
			want: true,
		},
		{
			name: "Non-MRK and MRK ARNs",
			key1: "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
			key2: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			want: false,
		},
		{
			name: "Invalid First ARN",
			key1: "invalid-arn",
			key2: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			want: false,
		},
		{
			name: "Invalid Second ARN",
			key1: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			key2: "invalid-arn",
			want: false,
		},
		{
			name: "ARNs with Different Account",
			key1: "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			key2: "arn:aws:kms:us-west-2:345678912345:key/mrk-1234",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEqual := IsMrkArnEqual(tt.key1, tt.key2)
			assert.Equal(t, tt.want, gotEqual)
		})
	}
}

func TestIsValidMrkIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{
			name:    "Valid MRK ARN",
			input:   "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Invalid ARN",
			input:   "arn:invalid-format",
			want:    false,
			wantErr: true,
		},
		{
			name:    "Alias",
			input:   "alias/my-alias",
			want:    false,
			wantErr: false,
		},
		{
			name:    "Bare MRK Identifier",
			input:   "mrk-1234",
			want:    false,
			wantErr: false, // Currently, bare MRK IDs are not supported and return false with no error
		},
		{
			name:    "Non-MRK String",
			input:   "random-string",
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := IsValidMrkIdentifier(tt.input)
			assert.Equal(t, tt.want, valid)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidMrkArn(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{
			name:    "Valid MRK ARN",
			input:   "arn:aws:kms:us-west-2:123456789012:key/mrk-1234",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Non-MRK ARN",
			input:   "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
			want:    false,
			wantErr: false,
		},
		{
			name:    "Invalid ARN Format",
			input:   "invalid-arn",
			want:    false,
			wantErr: true,
		},
		{
			name:    "Invalid ARN Non-KMS Service",
			input:   "arn:aws:s3:::example-bucket",
			want:    false,
			wantErr: true,
		},
		{
			name:    "Invalid ARN Alias Resource",
			input:   "arn:aws:kms:us-west-2:123456789012:alias/my-alias",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := IsValidMrkArn(tt.input)
			assert.Equal(t, tt.want, valid)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrMalformedArn)
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
