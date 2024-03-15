// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewKmsMrkMasterKey(t *testing.T) {
	mockKmsClient := mocks.NewMockKMSClient(t)
	type args struct {
		client model.KMSClient
		keyID  string
	}
	tests := []struct {
		name    string
		args    args
		want    *MrkMasterKey
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			args: args{
				client: mockKmsClient,
				keyID:  "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			},
			want: &MrkMasterKey{
				MasterKey: MasterKey{
					BaseKey: keys.NewBaseKey(model.KeyMeta{
						ProviderID: types.KmsProviderID,
						KeyID:      "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
					}),
					kmsClient: mockKmsClient,
				},
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
			got, err := newKmsMrkMasterKey(tt.args.client, tt.args.keyID)
			if !tt.wantErr(t, err, fmt.Sprintf("newKmsMrkMasterKey(%v, %v)", tt.args.client, tt.args.keyID)) {
				return
			}
			assert.Equalf(t, tt.want, got, "newKmsMrkMasterKey(%v, %v)", tt.args.client, tt.args.keyID)
		})
	}
}

func TestKmsMrkMasterKey_validateAllowedDecrypt(t *testing.T) {
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
		{
			name:     "MRK keyID matches MRK edkKeyID different region",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			edkKeyID: "arn:aws:kms:us-east-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			wantErr:  assert.NoError,
		},
		{
			name:     "MRK keyID not matches MRK edkKeyID",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			edkKeyID: "arn:aws:kms:eu-west-1:123456789011:key/mrk-99999999-9999-9999-9999-999999999999",
			wantErr:  assert.Error,
		},
		{
			name:     "MRK keyID not matches MRK edkKeyID different region",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			edkKeyID: "arn:aws:kms:eu-central-1:123456789011:key/mrk-99999999-9999-9999-9999-999999999999",
			wantErr:  assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKmsClient := mocks.NewMockKMSClient(t)
			kmsMK, err := newKmsMrkMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			tt.wantErr(t, kmsMK.validateAllowedDecrypt(tt.edkKeyID), fmt.Sprintf("validateAllowedDecrypt(%v)", tt.edkKeyID))
		})
	}
}

func TestKmsMrkMasterKey_OwnsDataKey(t *testing.T) {
	tests := []struct {
		name     string
		keyID    string
		mockMeta model.KeyMeta
		want     bool
	}{
		{
			name:     "keyID owns DataKey",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockMeta: model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011"},
			want:     true,
		},
		{
			name:     "keyID owns EncryptedDataKey",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockMeta: model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011"},
			want:     true,
		},
		{
			name:     "keyID not owns EncryptedDataKey",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
			mockMeta: model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: "arn:aws:kms:eu-west-1:123456789011:key/99999999-9999-9999-9999-999999999999"},
			want:     false,
		},

		{
			name:     "MRK keyID owns MRK DataKey same region",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			mockMeta: model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011"},
			want:     true,
		},
		{
			name:     "MRK keyID owns MRK EncryptedDataKey different region",
			keyID:    "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			mockMeta: model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: "arn:aws:kms:eu-central-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011"},
			want:     true,
		},
		{
			name:     "MRK keyID not owns MRK EncryptedDataKey different account",
			keyID:    "arn:aws:kms:eu-west-1:999999999999:key/mrk-12345678-1234-1234-1234-123456789011",
			mockMeta: model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: "arn:aws:kms:eu-central-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011"},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKmsClient := mocks.NewMockKMSClient(t)
			mockKey := mocks.NewMockKey(t)

			mockKey.EXPECT().KeyID().Return(tt.mockMeta.KeyID).Once()
			mockKey.EXPECT().KeyProvider().Return(tt.mockMeta).Once()

			kmsMrkMK, err := newKmsMrkMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			assert.Equalf(t, tt.want, kmsMrkMK.OwnsDataKey(mockKey), "OwnsDataKey(%v)", mockKey)
		})
	}
}

func TestKmsMrkMasterKey_DecryptDataKey(t *testing.T) {
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
			name:  "decrypts MRK data key from different region",
			keyID: "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
			args: args{
				keyID:            "arn:aws:kms:eu-central-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011",
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
				mockKmsClient.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything).
					Return(&kms.DecryptOutput{
						KeyId:     aws.String(tt.keyID),
						Plaintext: []byte("PlaintextPlaintextPlaintextPlain"),
					}, nil).Once()
			}

			kmsMrkMK, err := newKmsMrkMasterKey(mockKmsClient, tt.keyID)
			require.NoError(t, err)

			edk := model.NewEncryptedDataKey(
				model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: tt.args.keyID},
				tt.args.encryptedDataKey,
			)

			got, err := kmsMrkMK.DecryptDataKey(ctx, edk, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			want := model.NewDataKey(
				kmsMrkMK.Metadata(),
				[]byte("PlaintextPlaintextPlaintextPlain"),
				tt.args.encryptedDataKey,
			)
			assert.Equal(t, want, got)
		})
	}
}

func TestMrkKeyFactory_NewMasterKey(t *testing.T) {
	tests := []struct {
		name       string
		args       []interface{}
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "Valid arguments",
			args:    []interface{}{mocks.NewMockKMSClient(t), "arn:aws:kms:eu-west-1:123456789011:key/mrk-12345678-1234-1234-1234-123456789011"},
			wantErr: false,
		},
		{
			name:       "Invalid number of arguments",
			args:       []interface{}{"mrkKeyID1"},
			wantErr:    true,
			wantErrStr: "invalid number of arguments",
		},
		{
			name:       "Invalid KMSClient type",
			args:       []interface{}{"notAKMSClient", "mrkKeyID1"},
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
			factory := &MrkKeyFactory{}
			got, err := factory.NewMasterKey(tt.args...)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.IsType(t, &MrkMasterKey{}, got)
			}
		})
	}
}
