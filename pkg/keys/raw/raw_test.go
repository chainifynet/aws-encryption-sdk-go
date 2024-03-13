// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mocksrand "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/serialization/wrappingkey"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"

	mocksencryption "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
)

func TestRawMasterKey_KeyID(t *testing.T) {
	tests := []struct {
		name    string
		keyMeta model.KeyMeta
		want    string
	}{
		{"valid_key1", model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}, "rawMK1"},
		{"valid_key2", model.KeyMeta{ProviderID: "static", KeyID: "rawMK2"}, "rawMK2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawMK := &MasterKey{
				BaseKey: keys.NewBaseKey(tt.keyMeta),
			}
			assert.Equalf(t, tt.want, rawMK.KeyID(), "KeyID()")
		})
	}
}

func TestRawMasterKey_Metadata(t *testing.T) {
	tests := []struct {
		name    string
		keyMeta model.KeyMeta
		want    model.KeyMeta
	}{
		{"valid_metadata1",
			model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
			model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
		},
		{"valid_metadata2",
			model.KeyMeta{ProviderID: "static", KeyID: "rawMK2"},
			model.KeyMeta{ProviderID: "static", KeyID: "rawMK2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawMK := &MasterKey{
				BaseKey: keys.NewBaseKey(tt.keyMeta),
			}
			assert.Equalf(t, tt.want, rawMK.Metadata(), "Metadata()")
		})
	}
}

func TestRawMasterKey_OwnsDataKey(t *testing.T) {
	tests := []struct {
		name    string
		want    bool
		keyMeta model.KeyMeta
		key     model.Key
	}{
		{"owns_dataKey", true,
			model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
			model.NewDataKey(model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}, nil, nil),
		},
		{"not_owns_dataKey", false,
			model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2"},
			model.NewDataKey(model.KeyMeta{ProviderID: "raw", KeyID: "other"}, nil, nil),
		},
		{"owns_encryptedDataKey", true,
			model.KeyMeta{ProviderID: "static", KeyID: "rawMK3"},
			model.NewEncryptedDataKey(model.KeyMeta{ProviderID: "static", KeyID: "rawMK3"}, nil),
		},
		{"not_owns_encryptedDataKey", false,
			model.KeyMeta{ProviderID: "static", KeyID: "rawMK3"},
			model.NewEncryptedDataKey(model.KeyMeta{ProviderID: "static", KeyID: "other"}, nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wk := wrappingkey.WrappingKey{}
			rawMK := &MasterKey{
				BaseKey:       keys.NewBaseKey(tt.keyMeta),
				keyWrapper:    wk,
				keyInfoPrefix: wk.SerializeKeyInfoPrefix(tt.keyMeta.KeyID),
			}
			assert.Equalf(t, tt.want, rawMK.OwnsDataKey(tt.key), "OwnsDataKey(%v)", tt.key)
		})
	}
}

func TestNewRawMasterKey(t *testing.T) {

	derivedKey1Mock := []byte{0xa6, 0x85, 0x3b, 0xd4, 0xa6, 0x83, 0xb4, 0xc0, 0xc7, 0x27, 0xc5, 0x75, 0xc7, 0xf, 0x66, 0x76, 0x73, 0x3b, 0x6, 0xb1, 0x1e, 0xd6, 0xcb, 0xeb, 0xa8, 0xee, 0x68, 0xa2, 0xe3, 0x26, 0xd6, 0x9d}
	derivedKey2Mock := []byte{0xb, 0xd0, 0xc9, 0xfb, 0x61, 0x3b, 0xb, 0x30, 0xcb, 0x27, 0x65, 0xf3, 0xb5, 0x99, 0xdc, 0x61, 0xeb, 0xc6, 0x70, 0x7f, 0xcb, 0xba, 0xb2, 0x9d, 0x37, 0x18, 0x90, 0x10, 0x27, 0xdf, 0x5d, 0x67}

	type args struct {
		providerID string
		keyID      string
		rawKey     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *MasterKey
		wantErr assert.ErrorAssertionFunc
	}{
		{"key1",
			args{providerID: "raw", keyID: "rawMK1", rawKey: []byte("raw1DataKeyRAWRAWRAW_12345678901")},
			&MasterKey{
				BaseKey:        keys.NewBaseKey(model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}),
				keyInfoPrefix:  []byte{0x72, 0x61, 0x77, 0x4d, 0x4b, 0x31, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0xc},
				derivedDataKey: derivedKey1Mock,
				Encrypter:      encryption.Gcm{}, keyWrapper: wrappingkey.WrappingKey{},
			}, assert.NoError,
		},
		{"key2",
			args{providerID: "static", keyID: "staticKey2", rawKey: []byte("raw2DataKeyRAWRAWRAW_12345678902")},
			&MasterKey{
				BaseKey:        keys.NewBaseKey(model.KeyMeta{ProviderID: "static", KeyID: "staticKey2"}),
				keyInfoPrefix:  []byte{0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x32, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0xc},
				derivedDataKey: derivedKey2Mock,
				Encrypter:      encryption.Gcm{}, keyWrapper: wrappingkey.WrappingKey{},
			}, assert.NoError,
		},
		{"key3_nil",
			args{providerID: "static", keyID: "staticKey3", rawKey: nil},
			nil,
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRawMasterKey(tt.args.providerID, tt.args.keyID, tt.args.rawKey)
			if !tt.wantErr(t, err, fmt.Sprintf("NewRawMasterKey(%v, %v, %v)", tt.args.providerID, tt.args.keyID, tt.args.rawKey)) {
				return
			}
			assert.Equalf(t, tt.want, got, "NewRawMasterKey(%v, %v, %v)", tt.args.providerID, tt.args.keyID, tt.args.rawKey)
		})
	}
}

func TestRawMasterKey_encryptDataKey(t *testing.T) {
	tests := []struct {
		name                     string
		dataKey                  []byte
		alg                      *suite.AlgorithmSuite
		ec                       suite.EncryptionContext
		expectError              bool
		expectedEncryptedDataKey []byte
		encryptErr               error
	}{
		{
			name:                     "encrypts",
			dataKey:                  []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			alg:                      suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:                       suite.EncryptionContext{"a": "b"},
			expectError:              false,
			expectedEncryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
		},
		{
			name:                     "invalid_data_key_length_short",
			dataKey:                  []byte("1234"),
			alg:                      suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:                       nil,
			expectError:              true,
			expectedEncryptedDataKey: nil,
		},
		{
			name:                     "invalid_data_key_length_long",
			dataKey:                  []byte("1234567890123456789012345678901234567890"), // 40
			alg:                      suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:                       nil,
			expectError:              true,
			expectedEncryptedDataKey: nil,
		},
		{
			name:                     "encrypt_error",
			dataKey:                  []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			alg:                      suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:                       suite.EncryptionContext{"a": "b"},
			expectError:              true,
			expectedEncryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
			encryptErr:               errors.New("AES error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := mocksencryption.NewMockEncrypter(t)
			mockRandomGenerator := mocksrand.NewMockRandomGenerator(t)
			mockWrapper := mocks.NewMockWrapper(t)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			if tt.expectError == false || tt.encryptErr != nil {
				mockRandomGenerator.EXPECT().CryptoRandomBytes(mock.Anything).
					Return([]byte("mock_IV"), nil).Once()
			}

			if tt.encryptErr != nil {
				mockEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil, tt.encryptErr).Once()
			} else if !tt.expectError {
				mockEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("mock_EncryptedKey"), []byte("mock_Tag"), nil).Once()
			}

			if !tt.expectError {
				mockWrapper.EXPECT().SerializeEncryptedDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(tt.expectedEncryptedDataKey).Once()
			}

			rawMK := &MasterKey{
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}

			encryptedDataKey, err := rawMK.encryptDataKey(tt.dataKey, tt.alg, tt.ec)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedEncryptedDataKey, encryptedDataKey)
		})
	}
}

func TestRawMasterKey_GenerateDataKey(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	type args struct {
		alg *suite.AlgorithmSuite
		ec  suite.EncryptionContext
	}
	tests := []struct {
		name                           string
		mockDataKey                    []byte
		mockSerializedEncryptedDataKey []byte
		fields                         fields
		args                           args
		wantErr                        error
	}{
		{
			name:                           "generates_data_key",
			mockDataKey:                    []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			mockSerializedEncryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
			fields:                         fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: nil,
		},
		{
			name:                           "dataKey_length_short",
			mockDataKey:                    []byte("1234"),
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: keys.ErrGenerateDataKey,
		},
		{
			name:                           "dataKey_length_long",
			mockDataKey:                    []byte("1234567890123456789012345678901234567890"), // 40
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: keys.ErrGenerateDataKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockEncrypter := mocksencryption.NewMockEncrypter(t)
			mockRandomGenerator := mocksrand.NewMockRandomGenerator(t)
			mockWrapper := mocks.NewMockWrapper(t)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			mockRandomGenerator.EXPECT().CryptoRandomBytes(mock.Anything).
				Return(tt.mockDataKey, nil)
			if tt.wantErr == nil {
				mockRandomGenerator.EXPECT().CryptoRandomBytes(mock.Anything).
					Return([]byte("mock_IV"), nil)
				mockEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("mock_EncryptedKey"), []byte("mock_Tag"), nil)
				mockWrapper.EXPECT().SerializeEncryptedDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockSerializedEncryptedDataKey)
			}

			rawMK := &MasterKey{
				BaseKey:    keys.NewBaseKey(tt.fields.metadata),
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.GenerateDataKey(ctx, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			want := model.NewDataKey(
				tt.fields.metadata,
				tt.mockDataKey,
				tt.mockSerializedEncryptedDataKey,
			)

			assert.NoError(t, err)

			assert.Equalf(t, want, got, "GenerateDataKey(%v, %v)", tt.args.alg, tt.args.ec)
		})
	}
}

func TestRawMasterKey_EncryptDataKey(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	type args struct {
		dk  model.DataKeyI
		alg *suite.AlgorithmSuite
		ec  suite.EncryptionContext
	}
	tests := []struct {
		name                           string
		mockSerializedEncryptedDataKey []byte
		fields                         fields
		args                           args
		wantErr                        error
	}{
		{
			name:                           "encrypts_data_key",
			mockSerializedEncryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
			fields:                         fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				model.NewDataKey(model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}, []byte("raw1DataKeyRAWRAWRAW_12345678901"), nil),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: nil,
		},
		{
			name:                           "dataKey_length_short",
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}},
			args: args{
				model.NewDataKey(model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}, []byte("1234"), nil),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: keys.ErrEncryptKey,
		},
		{
			name:                           "dataKey_length_long",
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}},
			args: args{
				model.NewDataKey(model.KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}, []byte("1234567890123456789012345678901234567890"), nil), // 40
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: keys.ErrEncryptKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockEncrypter := mocksencryption.NewMockEncrypter(t)
			mockRandomGenerator := mocksrand.NewMockRandomGenerator(t)
			mockWrapper := mocks.NewMockWrapper(t)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			if tt.wantErr == nil {
				mockRandomGenerator.EXPECT().CryptoRandomBytes(mock.Anything).
					Return([]byte("mock_IV"), nil).Once()
				mockEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("mock_EncryptedKey"), []byte("mock_Tag"), nil).Once()
				mockWrapper.EXPECT().SerializeEncryptedDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockSerializedEncryptedDataKey).Once()
			}

			rawMK := &MasterKey{
				BaseKey:    keys.NewBaseKey(tt.fields.metadata),
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.EncryptDataKey(ctx, tt.args.dk, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			want := model.NewEncryptedDataKey(
				tt.fields.metadata,
				tt.mockSerializedEncryptedDataKey,
			)

			assert.Equalf(t, want, got, "EncryptDataKey(%v, %v, %v)", tt.args.dk, tt.args.alg, tt.args.ec)
		})
	}
}

func TestRawMasterKey_decryptDataKey(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	type args struct {
		encryptedDataKey []byte
		alg              *suite.AlgorithmSuite
		ec               suite.EncryptionContext
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       []byte
		wantErr    error
		decryptErr error
	}{
		{
			name:   "decrypts_key",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			wantErr: nil,
		},
		{
			name:   "encrypted_data_key_length_short",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}},
			args: args{
				[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_Tags"), // 48
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: errors.New("encrypted data key length is invalid"),
		},
		{
			name:   "encrypted_data_key_length_long",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}},
			args: args{
				[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV_IV_IV_IV_IV"), // 72
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: errors.New("encrypted data key length is invalid"),
		},
		{
			name:   "decrypt_error",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:       []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			wantErr:    errors.New("AES error"),
			decryptErr: errors.New("AES error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := mocksencryption.NewMockEncrypter(t)
			mockRandomGenerator := mocksrand.NewMockRandomGenerator(t)
			mockWrapper := mocks.NewMockWrapper(t)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			if tt.wantErr == nil || tt.decryptErr != nil {
				mockWrapper.EXPECT().DeserializeEncryptedDataKey(mock.Anything, mock.Anything).
					Return([]byte("mock_encryptedData"), []byte("mock_IV")).Once()
			}

			if tt.decryptErr != nil {
				mockEncrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, tt.decryptErr).Once()
			} else if tt.wantErr == nil {
				mockEncrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(tt.want, nil).Once()
			}

			rawMK := &MasterKey{
				BaseKey:    keys.NewBaseKey(tt.fields.metadata),
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.decryptDataKey(tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "decryptDataKey(%v, %v, %v)", tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)
		})
	}
}

func TestRawMasterKey_DecryptDataKey(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	type args struct {
		encryptedDataKey model.EncryptedDataKeyI
		alg              *suite.AlgorithmSuite
		ec               suite.EncryptionContext
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       []byte
		wantErr    error
		decryptErr error
	}{
		{
			name:   "decrypts_key",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				model.NewEncryptedDataKey(
					model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
					[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			wantErr: nil,
		},
		{
			name:   "decrypts_other_key",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1_THIS"}},
			args: args{
				model.NewEncryptedDataKey(
					model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2_OTHER"},
					[]byte("encryptedKeysOther_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			wantErr: nil,
		},
		{
			name:   "encrypted_data_key_nil",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				nil,
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: keys.ErrDecryptKey,
		},
		{
			name:   "encrypted_data_key_length_short",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}},
			args: args{
				model.NewEncryptedDataKey(
					model.KeyMeta{ProviderID: "raw", KeyID: "rawMK2"},
					[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_Tags"), // 48
				),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: keys.ErrDecryptKey,
		},
		{
			name:   "encrypted_data_key_length_long",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}},
			args: args{
				model.NewEncryptedDataKey(
					model.KeyMeta{ProviderID: "raw", KeyID: "rawMK3"},
					[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV_IV_IV_IV_IV"), // 72
				),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: keys.ErrDecryptKey,
		},
		{
			name:   "decrypt_error",
			fields: fields{model.KeyMeta{ProviderID: "raw", KeyID: "rawMK4"}},
			args: args{
				model.NewEncryptedDataKey(
					model.KeyMeta{ProviderID: "raw", KeyID: "rawMK4"},
					[]byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				),
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:       nil,
			wantErr:    keys.ErrDecryptKey,
			decryptErr: errors.New("AES error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockEncrypter := mocksencryption.NewMockEncrypter(t)
			mockRandomGenerator := mocksrand.NewMockRandomGenerator(t)
			mockWrapper := mocks.NewMockWrapper(t)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			if tt.wantErr == nil || tt.decryptErr != nil {
				mockWrapper.EXPECT().DeserializeEncryptedDataKey(mock.Anything, mock.Anything).
					Return([]byte("mock_encryptedData"), []byte("mock_IV")).Once()
			}

			if tt.decryptErr != nil {
				mockEncrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, tt.decryptErr).Once()
			} else if tt.wantErr == nil {
				mockEncrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(tt.want, nil).Once()
			}

			rawMK := &MasterKey{
				BaseKey:    keys.NewBaseKey(tt.fields.metadata),
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.DecryptDataKey(ctx, tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			want := model.NewDataKey(
				tt.fields.metadata,
				tt.want,
				tt.args.encryptedDataKey.EncryptedDataKey(),
			)

			assert.Equalf(t, want, got, "DecryptDataKey(%v, %v, %v)", tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)
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
			args:    []interface{}{"provider1", "key1", []byte("raw1DataKeyRAWRAWRAW_12345678901")},
			wantErr: false,
		},
		{
			name:       "Invalid number of arguments",
			args:       []interface{}{"provider1", "key1"},
			wantErr:    true,
			wantErrStr: "invalid number of arguments",
		},
		{
			name:       "Invalid providerID type",
			args:       []interface{}{123, "key1", []byte("rawKey1")},
			wantErr:    true,
			wantErrStr: "invalid providerID",
		},
		{
			name:       "Invalid keyID type",
			args:       []interface{}{"provider1", 456, []byte("rawKey1")},
			wantErr:    true,
			wantErrStr: "invalid keyID",
		},
		{
			name:       "Invalid rawKey type",
			args:       []interface{}{"provider1", "key1", "notByteSlice"},
			wantErr:    true,
			wantErrStr: "invalid rawKey",
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
			}
		})
	}
}
