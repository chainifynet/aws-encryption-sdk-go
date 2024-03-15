// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	typesaws "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	httpaws "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/arn"
)

func TestKmsMasterKey_GenerateDataKey(t *testing.T) {
	type args struct {
		alg *suite.AlgorithmSuite
		ec  suite.EncryptionContext
	}
	tests := []struct {
		name                 string
		keyID                string
		args                 args
		mockKeyID            string
		mockDataKey          []byte
		mockEncryptedDataKey []byte
		wantErr              error
		wantKmsErr           bool
		validateErr          error
	}{
		{
			name:  "generates data key",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey:          []byte("PlaintextPlaintextPlaintextPlain"),
			mockEncryptedDataKey: []byte("ciphertext"),
		},
		{
			name:  "kms error",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey:          []byte("plaintext"),
			mockEncryptedDataKey: []byte("ciphertext"),
			wantErr:              keys.ErrGenerateDataKey,
			wantKmsErr:           true,
		},
		{
			name:  "invalid kms key arn",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "invalid-arn",
			mockDataKey:          []byte(nil),
			mockEncryptedDataKey: []byte(nil),
			wantErr:              keys.ErrGenerateDataKey,
			validateErr:          arn.ErrMalformedArn,
		},
		{
			name:  "invalid kms plaintext length",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey:          []byte("plaintext"),
			mockEncryptedDataKey: []byte(nil),
			wantErr:              keys.ErrGenerateDataKey,
		},
		{
			name:  "invalid kms CiphertextBlob length",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey:          []byte("PlaintextPlaintextPlaintextPlain"),
			mockEncryptedDataKey: []byte(nil),
			wantErr:              keys.ErrGenerateDataKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockKmsClient := mocks.NewMockKMSClient(t)

			if tt.wantKmsErr {
				mockKmsClient.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("KMS error")).Once()
			} else {
				mockKmsClient.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(&kms.GenerateDataKeyOutput{
						KeyId:          aws.String(tt.mockKeyID),
						CiphertextBlob: tt.mockEncryptedDataKey,
						Plaintext:      tt.mockDataKey,
					}, nil).Once()
			}

			kmsMK, err := NewKmsMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			got, err := kmsMK.GenerateDataKey(ctx, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				if tt.validateErr != nil {
					assert.ErrorIs(t, err, tt.validateErr)
				}
				return
			}
			assert.NoError(t, err)

			want := model.NewDataKey(kmsMK.Metadata(), tt.mockDataKey, tt.mockEncryptedDataKey)

			assert.Equal(t, want, got)
		})
	}
}

func TestKmsMasterKey_EncryptDataKey(t *testing.T) {
	type args struct {
		dataKey []byte
		alg     *suite.AlgorithmSuite
		ec      suite.EncryptionContext
	}
	tests := []struct {
		name                 string
		keyID                string
		args                 args
		mockKeyID            string
		mockEncryptedDataKey []byte
		wantErr              error
		wantKmsErr           bool
	}{
		{
			name:  "encrypts data key",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				dataKey: []byte("PlaintextPlaintextPlaintextPlain"),
				alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:      suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockEncryptedDataKey: []byte("ciphertext"),
		},
		{
			name:  "kms error",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				dataKey: []byte("PlaintextPlaintextPlaintextPlain"),
				alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:      suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockEncryptedDataKey: []byte("ciphertext"),
			wantErr:              keys.ErrEncryptKey,
			wantKmsErr:           true,
		},
		{
			name:  "invalid kms key arn",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				dataKey: []byte(nil),
				alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:      suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "invalid-arn",
			mockEncryptedDataKey: []byte(nil),
			wantErr:              keys.ErrEncryptKey,
		},
		{
			name:  "invalid data key length",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				dataKey: []byte("shortDataKey"),
				alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:      suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockEncryptedDataKey: []byte(nil),
			wantErr:              keys.ErrEncryptKey,
		},
		{
			name:  "invalid kms CiphertextBlob length",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				dataKey: []byte("PlaintextPlaintextPlaintextPlain"),
				alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:      suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockEncryptedDataKey: []byte(nil),
			wantErr:              keys.ErrEncryptKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockKmsClient := mocks.NewMockKMSClient(t)

			if tt.wantKmsErr {
				mockKmsClient.EXPECT().Encrypt(mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("KMS error")).Once()
			} else {
				mockKmsClient.EXPECT().Encrypt(mock.Anything, mock.Anything).
					Return(&kms.EncryptOutput{
						KeyId:          aws.String(tt.mockKeyID),
						CiphertextBlob: tt.mockEncryptedDataKey,
					}, nil).Once()
			}

			kmsMK, err := NewKmsMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			dataKey := model.NewDataKey(
				model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: tt.keyID},
				tt.args.dataKey,
				[]byte(nil),
			)

			got, err := kmsMK.EncryptDataKey(ctx, dataKey, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			want := model.NewEncryptedDataKey(kmsMK.Metadata(), tt.mockEncryptedDataKey)

			assert.Equal(t, want, got)
		})
	}
}

func TestKmsMasterKey_decryptDataKey(t *testing.T) {
	type args struct {
		keyID            string
		encryptedDataKey []byte
		alg              *suite.AlgorithmSuite
		ec               suite.EncryptionContext
	}
	tests := []struct {
		name            string
		keyID           string
		args            args
		mockKeyID       string
		mockDataKey     []byte
		wantErr         error
		wantValidateErr bool
		wantKmsErr      interface{}
		kmsErr          error
	}{
		{
			name:  "decrypts data key",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:   "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey: []byte("PlaintextPlaintextPlaintextPlain"),
		},
		{
			name:  "kms error incorrect key",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:   "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey: []byte("PlaintextPlaintextPlaintextPlain"),
			wantKmsErr:  typesaws.IncorrectKeyException{},
			kmsErr:      &smithy.OperationError{ServiceID: "KMS", OperationName: "Decrypt", Err: &httpaws.ResponseError{Response: &httpaws.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}}, Err: &typesaws.IncorrectKeyException{Message: aws.String("incorrect key")}}},
			wantErr:     keys.ErrDecryptKey,
		},
		{
			name:  "kms error invalid ciphertext exception",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:   "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey: []byte("PlaintextPlaintextPlaintextPlain"),
			wantKmsErr:  typesaws.InvalidCiphertextException{},
			kmsErr:      &smithy.OperationError{ServiceID: "KMS", OperationName: "Decrypt", Err: &httpaws.ResponseError{Response: &httpaws.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}}, Err: &typesaws.InvalidCiphertextException{Message: aws.String("invalid ciphertext")}}},
			wantErr:     keys.ErrDecryptKey,
		},
		{
			name:  "invalid edk keyID",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "invalid-arn",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:       "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey:     []byte("PlaintextPlaintextPlaintextPlain"),
			wantValidateErr: true,
			wantErr:         keys.ErrDecryptKey,
		},
		{
			name:  "invalid edk keyID alias",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:alias/alias_name",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:       "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey:     []byte("PlaintextPlaintextPlaintextPlain"),
			wantValidateErr: true,
			wantErr:         keys.ErrDecryptKey,
		},
		{
			name:  "invalid kms keyID",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:   "arn:aws:kms:eu-west-1:123456789011:key/99999999-9999-9999-9999-999999999999",
			mockDataKey: []byte("PlaintextPlaintextPlaintextPlain"),
			wantErr:     keys.ErrDecryptKey,
		},
		{
			name:  "invalid kms plaintext length",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			mockKeyID:   "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockDataKey: []byte("plaintext_invalid"),
			wantErr:     keys.ErrDecryptKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockKmsClient := mocks.NewMockKMSClient(t)

			if !tt.wantValidateErr {
				if tt.wantKmsErr != nil {
					mockKmsClient.EXPECT().Decrypt(mock.Anything, mock.Anything).
						Return(nil, tt.kmsErr).Once()
				} else {
					mockKmsClient.EXPECT().Decrypt(mock.Anything, mock.Anything).
						Return(&kms.DecryptOutput{
							KeyId:     aws.String(tt.mockKeyID),
							Plaintext: tt.mockDataKey,
						}, nil).Once()
				}
			}

			kmsMK, err := NewKmsMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			edk := model.NewEncryptedDataKey(
				model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: tt.args.keyID},
				tt.args.encryptedDataKey,
			)

			got, err := kmsMK.decryptDataKey(ctx, edk, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				if tt.wantKmsErr != nil {
					assert.ErrorAs(t, err, &tt.wantKmsErr) //nolint:gosec
					assert.ErrorIs(t, err, ErrKmsClient)
				}
				return
			}
			assert.NoError(t, err)

			want := model.NewDataKey(kmsMK.Metadata(), tt.mockDataKey, tt.args.encryptedDataKey)

			assert.Equal(t, want, got)
		})
	}
}

func TestKmsMasterKey_validateAllowedDecrypt(t *testing.T) {
	tests := []struct {
		name     string
		keyID    string
		edkKeyID string
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "keyID matches edkKeyID",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			edkKeyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			wantErr:  assert.NoError,
		},
		{
			name:     "keyID not matches edkKeyID",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			edkKeyID: "arn:aws:kms:eu-west-1:123456789011:key/99999999-9999-9999-9999-999999999999",
			wantErr:  assert.Error,
		},
		{
			name:     "keyID not matches edkKeyID different region",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			edkKeyID: "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			wantErr:  assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKmsClient := mocks.NewMockKMSClient(t)
			kmsMK, err := NewKmsMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			tt.wantErr(t, kmsMK.validateAllowedDecrypt(tt.edkKeyID), fmt.Sprintf("validateAllowedDecrypt(%v)", tt.edkKeyID))
		})
	}
}

func TestKmsMasterKey_DecryptDataKey(t *testing.T) {
	type args struct {
		keyID            string
		encryptedDataKey []byte
		alg              *suite.AlgorithmSuite
		ec               suite.EncryptionContext
	}
	tests := []struct {
		name            string
		keyID           string
		args            args
		wantErr         error
		wantValidateErr bool
	}{
		{
			name:  "decrypts data key",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
		},
		{
			name:  "keyID not matches edkKeyID",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-west-1:123456789011:key/99999999-9999-9999-9999-999999999999",
				encryptedDataKey: []byte("ciphertext"),
				alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				ec:               suite.EncryptionContext{"a": "b"},
			},
			wantErr:         keys.ErrDecryptKey,
			wantValidateErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockKmsClient := mocks.NewMockKMSClient(t)

			if !tt.wantValidateErr {
				mockKmsClient.EXPECT().Decrypt(mock.Anything, mock.Anything).
					Return(&kms.DecryptOutput{
						KeyId:     aws.String(tt.args.keyID),
						Plaintext: []byte("PlaintextPlaintextPlaintextPlain"),
					}, nil).Once()
			}

			kmsMK, err := NewKmsMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			edk := model.NewEncryptedDataKey(
				model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: tt.args.keyID},
				tt.args.encryptedDataKey,
			)

			got, err := kmsMK.DecryptDataKey(ctx, edk, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			want := model.NewDataKey(kmsMK.Metadata(), []byte("PlaintextPlaintextPlaintextPlain"), tt.args.encryptedDataKey)
			assert.Equal(t, want, got)
		})
	}
}

func TestNewKmsMasterKey(t *testing.T) {
	mockKmsClient := mocks.NewMockKMSClient(t)
	type args struct {
		client model.KMSClient
		keyID  string
	}
	tests := []struct {
		name    string
		args    args
		want    *MasterKey
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			args: args{
				client: mockKmsClient,
				keyID:  "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			},
			want: &MasterKey{
				BaseKey: keys.NewBaseKey(model.KeyMeta{
					ProviderID: types.KmsProviderID,
					KeyID:      "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				}),
				kmsClient: mockKmsClient,
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid keyID",
			args: args{
				client: mockKmsClient,
				keyID:  "",
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "invalid KMSClient",
			args: args{
				client: nil,
				keyID:  "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			},
			want:    nil,
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKmsMasterKey(tt.args.client, tt.args.keyID)
			if !tt.wantErr(t, err, fmt.Sprintf("NewKmsMasterKey(%v, %v)", tt.args.client, tt.args.keyID)) {
				return
			}
			assert.Equalf(t, tt.want, got, "NewKmsMasterKey(%v, %v)", tt.args.client, tt.args.keyID)
		})
	}
}

func TestKeyFactory_NewMasterKey(t *testing.T) {
	tests := []struct {
		name       string
		args       []interface{}
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "Valid arguments",
			args:    []interface{}{mocks.NewMockKMSClient(t), "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011"},
			wantErr: false,
		},
		{
			name:       "Invalid number of arguments",
			args:       []interface{}{"keyID1"},
			wantErr:    true,
			wantErrStr: "invalid number of arguments",
		},
		{
			name:       "Invalid KMSClient type",
			args:       []interface{}{"notAKMSClient", "keyID1"},
			wantErr:    true,
			wantErrStr: "invalid KMSClient",
		},
		{
			name:       "Invalid keyID type",
			args:       []interface{}{mocks.NewMockKMSClient(t), 123},
			wantErr:    true,
			wantErrStr: "invalid keyID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &KeyFactory{}
			got, err := factory.NewMasterKey(tt.args...)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.IsType(t, &MasterKey{}, got)
			}
		})
	}
}
