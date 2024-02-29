// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestWithAlgorithm(t *testing.T) {
	tests := []struct {
		name       string
		alg        *suite.AlgorithmSuite
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "Valid Commit Algorithm",
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			wantErr: false,
		},
		{
			name:    "Valid Algorithm",
			alg:     suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			wantErr: false,
		},
		{
			name:       "Nil Algorithm",
			alg:        nil,
			wantErr:    true,
			wantErrStr: "algorithm must not be nil",
		},
		{
			name:       "Unsupported Algorithm",
			alg:        &suite.AlgorithmSuite{AlgorithmID: 0x0301},
			wantErr:    true,
			wantErrStr: "algorithm error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &client.EncryptOptions{}
			err := client.WithAlgorithm(tt.alg)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.alg, opts.Algorithm)
			}
		})
	}
}

func TestWithFrameLength(t *testing.T) {
	tests := []struct {
		name        string
		frameLength int
		wantErr     bool
	}{
		{
			name:        "ValidFrameLength",
			frameLength: 1024,
			wantErr:     false,
		},
		{
			name:        "InvalidFrameLength",
			frameLength: -1,
			wantErr:     true,
		},
		{
			name:        "ZeroFrameLength",
			frameLength: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optFunc := client.WithFrameLength(tt.frameLength)
			opt := &client.EncryptOptions{}

			if tt.wantErr {
				require.Error(t, optFunc(opt))
			} else {
				require.NoError(t, optFunc(opt))

				assert.Equal(t, tt.frameLength, opt.FrameLength)

				err := suite.ValidateFrameLength(opt.FrameLength)
				assert.NoError(t, err)
			}
		})
	}
}

func TestWithEncryptionHandler(t *testing.T) {
	tests := []struct {
		name    string
		handler func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler
		wantErr bool
	}{
		{
			name: "ValidHandler",
			handler: func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler {
				return mocks.NewMockEncrypter(t)
			},
			wantErr: false,
		},
		{
			name:    "NilHandler",
			handler: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &client.EncryptOptions{}
			err := client.WithEncryptionHandler(tt.handler)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "handler must not be nil", fmt.Sprint(err))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, opts.Handler)
			}
		})
	}
}

func TestWithDecryptionHandler(t *testing.T) {
	tests := []struct {
		name    string
		handler func(config crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler
		wantErr bool
	}{
		{
			name: "ValidHandler",
			handler: func(config crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler {
				return mocks.NewMockDecrypter(t)
			},
			wantErr: false,
		},
		{
			name:    "NilHandler",
			handler: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &client.DecryptOptions{}
			err := client.WithDecryptionHandler(tt.handler)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "handler must not be nil", fmt.Sprint(err))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, opts.Handler)
			}
		})
	}
}
