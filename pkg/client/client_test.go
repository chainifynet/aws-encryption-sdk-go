// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mocksformat "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func Test_NewClient(t *testing.T) {
	cl1 := client.NewClient()
	assert.NotNil(t, cl1)
}

func Test_NewClientWithConfig(t *testing.T) {
	cfg, _ := clientconfig.NewConfig()

	cl1 := client.NewClientWithConfig(cfg)
	cl2 := client.NewClientWithConfig(cfg)
	assert.NotNil(t, cl1)
	assert.NotNil(t, cl2)
	assert.NotSame(t, cl1, cl2)
	assert.NotSame(t, *cl1, *cl2)
	assert.Equal(t, fmt.Sprintf("%v", cl1), fmt.Sprintf("%v", cl2))
}

func TestClient_Decrypt(t *testing.T) {
	ciphertextMock := []byte("encrypted-data")
	plaintextMock := []byte("decrypted-data")
	tests := []struct {
		name        string
		ciphertext  []byte
		cmm         model.CryptoMaterialsManager
		setupMocks  func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc
		want        []byte
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name:       "Valid Decrypt",
			ciphertext: ciphertextMock,
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc {
				d.EXPECT().Decrypt(mock.Anything, mock.Anything).
					Return(plaintextMock, mocksformat.NewMockMessageHeader(t), nil).Once()

				return []client.DecryptOptionFunc{
					client.WithDecryptionHandler(func(config crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler {
						return d
					}),
				}
			},
			want:    plaintextMock,
			wantErr: false,
		},
		{
			name:       "Invalid CMM",
			ciphertext: ciphertextMock,
			cmm:        nil,
			setupMocks: func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc {
				return []client.DecryptOptionFunc{}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "validation error",
			wantErrType: crypto.ErrDecryption,
		},
		{
			name:       "Nil Ciphertext",
			ciphertext: nil,
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc {
				return []client.DecryptOptionFunc{}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "validation error",
			wantErrType: crypto.ErrDecryption,
		},
		{
			name:       "Empty Ciphertext",
			ciphertext: []byte(""),
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc {
				return []client.DecryptOptionFunc{}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "validation error",
			wantErrType: crypto.ErrDecryption,
		},
		{
			name:       "Invalid Decrypt Handler",
			ciphertext: ciphertextMock,
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc {
				return []client.DecryptOptionFunc{
					client.WithDecryptionHandler(nil),
				}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "invalid decrypt option",
			wantErrType: crypto.ErrDecryption,
		},
		{
			name:       "Decrypt Error",
			ciphertext: ciphertextMock,
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, d *mocks.MockDecrypter) []client.DecryptOptionFunc {
				d.EXPECT().Decrypt(mock.Anything, mock.Anything).
					Return(nil, nil, fmt.Errorf("SDK error: %w", crypto.ErrDecryption)).Once()

				return []client.DecryptOptionFunc{
					client.WithDecryptionHandler(func(config crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler {
						return d
					}),
				}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "SDK error",
			wantErrType: crypto.ErrDecryption,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := client.NewClient()

			decrypterMock := mocks.NewMockDecrypter(t)

			optFns := tt.setupMocks(t, decrypterMock)

			got, header, err := c.Decrypt(ctx, tt.ciphertext, tt.cmm, optFns...)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				assert.Nil(t, got)
				assert.Nil(t, header)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.NotNil(t, header)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestClient_Encrypt(t *testing.T) {
	plaintextMock := []byte("plaintext-data")
	ciphertextMock := []byte("encrypted-data")
	tests := []struct {
		name       string
		source     []byte
		ec         suite.EncryptionContext
		cmm        model.CryptoMaterialsManager
		setupMocks func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc

		want        []byte
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name:   "Valid Encrypt",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				e.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything).
					Return(ciphertextMock, mocksformat.NewMockMessageHeader(t), nil).Once()

				return []client.EncryptOptionFunc{
					client.WithEncryptionHandler(func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler {
						return e
					}),
				}
			},
			want:    ciphertextMock,
			wantErr: false,
		},
		{
			name:   "Valid Encrypt With Params",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				e.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything).
					Return(ciphertextMock, mocksformat.NewMockMessageHeader(t), nil).Once()

				return []client.EncryptOptionFunc{
					client.WithEncryptionHandler(func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler {
						return e
					}),
					client.WithAlgorithm(suite.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384),
					client.WithFrameLength(1024),
				}
			},
			want:    ciphertextMock,
			wantErr: false,
		},
		{
			name:   "Invalid CMM",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: nil,
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				return []client.EncryptOptionFunc{}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "validation error",
			wantErrType: crypto.ErrEncryption,
		},
		{
			name:   "Nil Source",
			source: nil,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				return []client.EncryptOptionFunc{}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "validation error",
			wantErrType: crypto.ErrEncryption,
		},
		{
			name:   "Empty Source",
			source: []byte(""),
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				return []client.EncryptOptionFunc{}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "validation error",
			wantErrType: crypto.ErrEncryption,
		},
		{
			name:   "Invalid Encrypt Handler",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				return []client.EncryptOptionFunc{
					client.WithEncryptionHandler(nil),
				}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "invalid encrypt option",
			wantErrType: crypto.ErrEncryption,
		},
		{
			name:   "Invalid Frame Length",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				return []client.EncryptOptionFunc{
					client.WithFrameLength(-1),
				}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "invalid encrypt option",
			wantErrType: crypto.ErrEncryption,
		},
		{
			name:   "Unsupported Algorithm",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				return []client.EncryptOptionFunc{
					client.WithAlgorithm(&suite.AlgorithmSuite{AlgorithmID: 0x0301}),
				}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "invalid encrypt option",
			wantErrType: crypto.ErrEncryption,
		},
		{
			name:   "Encrypt Error",
			source: plaintextMock,
			ec: suite.EncryptionContext{
				"purpose": "test",
			},
			cmm: mocks.NewMockCryptoMaterialsManager(t),
			setupMocks: func(t *testing.T, e *mocks.MockEncrypter) []client.EncryptOptionFunc {
				e.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil, fmt.Errorf("SDK error: %w", crypto.ErrEncryption)).Once()

				return []client.EncryptOptionFunc{
					client.WithEncryptionHandler(func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler {
						return e
					}),
				}
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "SDK error",
			wantErrType: crypto.ErrEncryption,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := client.NewClient()

			encrypterMock := mocks.NewMockEncrypter(t)

			optFns := tt.setupMocks(t, encrypterMock)

			got, header, err := c.Encrypt(ctx, tt.source, tt.ec, tt.cmm, optFns...)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				assert.Nil(t, got)
				assert.Nil(t, header)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.NotNil(t, header)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
