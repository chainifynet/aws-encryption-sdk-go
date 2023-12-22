// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestValidateMessageVersion(t *testing.T) {
	errFormatFn := func(version suite.MessageFormatVersion) error {
		return fmt.Errorf("invalid message format version %d", version)
	}
	tests := []struct {
		name    string
		version suite.MessageFormatVersion
		want    error
	}{
		{"Version_V1", suite.V1, nil},
		{"Version_V2", suite.V2, nil},
		{"Version_255", math.MaxUint8, errFormatFn(math.MaxUint8)},
		{"Version_0", 0, errFormatFn(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := suite.ValidateMessageVersion(uint8(tt.version))
			assert.Equal(t, tt.want, err)
		})
	}
}

func TestValidateContentType(t *testing.T) {
	errFormatFn := func(contentType suite.ContentType) error {
		return fmt.Errorf("ContentType %d not supported", contentType)
	}
	tests := []struct {
		name        string
		contentType suite.ContentType
		want        error
	}{
		{"Framed Content", suite.FramedContent, nil},
		{"NonFramed Content", suite.NonFramedContent, errFormatFn(suite.NonFramedContent)},
		{"Unsupported Type", suite.ContentType(0), errFormatFn(0)},
		{"Max uint8", suite.ContentType(math.MaxUint8), errFormatFn(suite.ContentType(math.MaxUint8))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := suite.ValidateContentType(tt.contentType)
			assert.Equal(t, tt.want, err)
		})
	}
}

func TestValidateCommitmentPolicy(t *testing.T) {
	type args struct {
		p suite.CommitmentPolicy
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{"Unsupported Zero", args{suite.CommitmentPolicy(0)}, assert.Error},
		{"Unsupported Negative", args{suite.CommitmentPolicy(0)}, assert.Error},
		{"RequireEncryptAllowDecrypt", args{suite.CommitmentPolicyRequireEncryptAllowDecrypt}, assert.NoError},
		{"RequireEncryptRequireDecrypt", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt}, assert.NoError},
		{"ForbidEncryptAllowDecrypt", args{suite.CommitmentPolicyForbidEncryptAllowDecrypt}, assert.NoError},
		{"Unsupported Max int8", args{suite.CommitmentPolicy(math.MaxInt8)}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, suite.ValidateCommitmentPolicy(tt.args.p), fmt.Sprintf("ValidateCommitmentPolicy(%v)", tt.args.p))
		})
	}
}

func TestValidateFrameLength(t *testing.T) {
	tests := []struct {
		name      string
		frameLen  int
		wantErr   bool
		wantError string
	}{
		{name: "ValidMinSize", frameLen: suite.MinFrameSize, wantErr: false},
		{name: "BelowMinSize", frameLen: suite.MinFrameSize - 1, wantErr: true, wantError: fmt.Sprintf("frame length must be larger than %d and a multiple of the block size of the crypto algorithm: %d", suite.MinFrameSize, suite.BlockSize)},
		{name: "ValidMaxSize", frameLen: suite.MaxFrameSize - 127, wantErr: false},
		{name: "AboveMaxSize", frameLen: suite.MaxFrameSize + 1, wantErr: true, wantError: fmt.Sprintf("frame length too large: %d > %d", suite.MaxFrameSize+1, suite.MaxFrameSize)},
		{name: "NonMultipleBlockSize", frameLen: suite.MinFrameSize + 1, wantErr: true, wantError: fmt.Sprintf("frame length must be larger than %d and a multiple of the block size of the crypto algorithm: %d", suite.MinFrameSize, suite.BlockSize)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := suite.ValidateFrameLength(tt.frameLen)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.wantError, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
