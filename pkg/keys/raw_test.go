// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization/wrappingkey"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

func TestRawMasterKey_KeyID(t *testing.T) {
	tests := []struct {
		name    string
		keyMeta KeyMeta
		want    string
	}{
		{"valid_key1", KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}, "rawMK1"},
		{"valid_key2", KeyMeta{ProviderID: "static", KeyID: "rawMK2"}, "rawMK2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawMK := &RawMasterKey{
				metadata: tt.keyMeta,
			}
			assert.Equalf(t, tt.want, rawMK.KeyID(), "KeyID()")
		})
	}
}

func TestRawMasterKey_Metadata(t *testing.T) {
	tests := []struct {
		name    string
		keyMeta KeyMeta
		want    KeyMeta
	}{
		{"valid_metadata1",
			KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
			KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
		},
		{"valid_metadata2",
			KeyMeta{ProviderID: "static", KeyID: "rawMK2"},
			KeyMeta{ProviderID: "static", KeyID: "rawMK2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawMK := &RawMasterKey{
				metadata: tt.keyMeta,
			}
			assert.Equalf(t, tt.want, rawMK.Metadata(), "Metadata()")
		})
	}
}

func TestRawMasterKey_OwnsDataKey(t *testing.T) {
	tests := []struct {
		name    string
		want    bool
		keyMeta KeyMeta
		key     Key
	}{
		{"owns_dataKey", true,
			KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
			&DataKey{provider: KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
		},
		{"not_owns_dataKey", false,
			KeyMeta{ProviderID: "raw", KeyID: "rawMK2"},
			&DataKey{provider: KeyMeta{ProviderID: "raw", KeyID: "other"}},
		},
		{"owns_encryptedDataKey", true,
			KeyMeta{ProviderID: "static", KeyID: "rawMK3"},
			&EncryptedDataKey{provider: KeyMeta{ProviderID: "static", KeyID: "rawMK3"}},
		},
		{"not_owns_encryptedDataKey", false,
			KeyMeta{ProviderID: "static", KeyID: "rawMK3"},
			&EncryptedDataKey{provider: KeyMeta{ProviderID: "static", KeyID: "other"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawMK := &RawMasterKey{
				metadata: tt.keyMeta,
			}
			assert.Equalf(t, tt.want, rawMK.OwnsDataKey(tt.key), "OwnsDataKey(%v)", tt.key)
		})
	}
}

func TestNewRawMasterKey(t *testing.T) {

	derivedKey1Mock := []byte{0xa6, 0x85, 0x3b, 0xd4, 0xa6, 0x83, 0xb4, 0xc0, 0xc7, 0x27, 0xc5, 0x75, 0xc7, 0xf, 0x66, 0x76, 0x73, 0x3b, 0x6, 0xb1, 0x1e, 0xd6, 0xcb, 0xeb, 0xa8, 0xee, 0x68, 0xa2, 0xe3, 0x26, 0xd6, 0x9d}
	derivedKey2Mock := []byte{0xb, 0xd0, 0xc9, 0xfb, 0x61, 0x3b, 0xb, 0x30, 0xcb, 0x27, 0x65, 0xf3, 0xb5, 0x99, 0xdc, 0x61, 0xeb, 0xc6, 0x70, 0x7f, 0xcb, 0xba, 0xb2, 0x9d, 0x37, 0x18, 0x90, 0x10, 0x27, 0xdf, 0x5d, 0x67}
	derivedKey3NilMock := []byte{0xab, 0x16, 0x7c, 0x74, 0x7e, 0xaf, 0xfd, 0x13, 0x75, 0x96, 0xdd, 0x31, 0xfd, 0x49, 0xa6, 0xbe, 0x53, 0x20, 0x7b, 0x1, 0x25, 0xd2, 0xf0, 0x57, 0xc7, 0x28, 0x53, 0xb6, 0x62, 0x9, 0xc, 0x3d}

	type args struct {
		providerID string
		keyID      string
		rawKey     []byte
	}
	tests := []struct {
		name string
		args args
		want *RawMasterKey
	}{
		{"key1",
			args{providerID: "raw", keyID: "rawMK1", rawKey: []byte("raw1DataKeyRAWRAWRAW_12345678901")},
			&RawMasterKey{
				metadata:       KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
				derivedDataKey: derivedKey1Mock,
				Encrypter:      encryption.Gcm{}, keyWrapper: wrappingkey.WrappingKey{},
			},
		},
		{"key2",
			args{providerID: "static", keyID: "staticKey2", rawKey: []byte("raw2DataKeyRAWRAWRAW_12345678902")},
			&RawMasterKey{
				metadata:       KeyMeta{ProviderID: "static", KeyID: "staticKey2"},
				derivedDataKey: derivedKey2Mock,
				Encrypter:      encryption.Gcm{}, keyWrapper: wrappingkey.WrappingKey{},
			},
		},
		{"key3_nil",
			args{providerID: "static", keyID: "staticKey3", rawKey: nil},
			&RawMasterKey{
				metadata:       KeyMeta{ProviderID: "static", KeyID: "staticKey3"},
				derivedDataKey: derivedKey3NilMock,
				Encrypter:      encryption.Gcm{}, keyWrapper: wrappingkey.WrappingKey{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewRawMasterKey(tt.args.providerID, tt.args.keyID, tt.args.rawKey), "NewRawMasterKey(%v, %v, %v)", tt.args.providerID, tt.args.keyID, tt.args.rawKey)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEncrypter := new(MockEncrypter)
			mockRandomGenerator := new(MockRandomGenerator)
			mockWrapper := new(MockWrapper)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			mockRandomGenerator.On("CryptoRandomBytes", mock.Anything).
				Return([]byte("mock_IV"), nil)
			mockEncrypter.On("Encrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return([]byte("mock_EncryptedKey"), []byte("mock_Tag"), nil)
			mockWrapper.On("SerializeEncryptedDataKey", mock.Anything, mock.Anything, mock.Anything).
				Return(tt.expectedEncryptedDataKey, nil)

			rawMK := &RawMasterKey{
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}

			encryptedDataKey, err := rawMK.encryptDataKey(tt.dataKey, tt.alg, tt.ec)

			if tt.expectError {
				assert.Error(t, err)
				mockRandomGenerator.AssertNumberOfCalls(t, "CryptoRandomBytes", 0)
				mockEncrypter.AssertNumberOfCalls(t, "Encrypt", 0)
				mockWrapper.AssertNumberOfCalls(t, "SerializeEncryptedDataKey", 0)
				return
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedEncryptedDataKey, encryptedDataKey)
			}

			mockRandomGenerator.AssertExpectations(t)
			mockEncrypter.AssertExpectations(t)
			mockWrapper.AssertExpectations(t)
		})
	}
}

func TestRawMasterKey_GenerateDataKey(t *testing.T) {
	type fields struct {
		metadata KeyMeta
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
			fields:                         fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
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
			fields:                         fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: ErrGenerateDataKey,
		},
		{
			name:                           "dataKey_length_long",
			mockDataKey:                    []byte("1234567890123456789012345678901234567890"), // 40
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: ErrGenerateDataKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockEncrypter := new(MockEncrypter)
			mockRandomGenerator := new(MockRandomGenerator)
			mockWrapper := new(MockWrapper)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			mockRandomGenerator.On("CryptoRandomBytes", mock.Anything).
				Return(tt.mockDataKey, nil)
			mockRandomGenerator.On("CryptoRandomBytes", mock.Anything).
				Return([]byte("mock_IV"), nil)
			mockEncrypter.On("Encrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return([]byte("mock_EncryptedKey"), []byte("mock_Tag"), nil)
			mockWrapper.On("SerializeEncryptedDataKey", mock.Anything, mock.Anything, mock.Anything).
				Return(tt.mockSerializedEncryptedDataKey, nil)

			rawMK := &RawMasterKey{
				metadata:   tt.fields.metadata,
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.GenerateDataKey(ctx, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				mockRandomGenerator.AssertNumberOfCalls(t, "CryptoRandomBytes", 1)
				mockEncrypter.AssertNumberOfCalls(t, "Encrypt", 0)
				mockWrapper.AssertNumberOfCalls(t, "SerializeEncryptedDataKey", 0)
				return
			}
			want := &DataKey{
				provider:         tt.fields.metadata,
				dataKey:          tt.mockDataKey,
				encryptedDataKey: tt.mockSerializedEncryptedDataKey,
			}
			assert.NoError(t, err)

			assert.Equalf(t, want, got, "GenerateDataKey(%v, %v)", tt.args.alg, tt.args.ec)

			mockRandomGenerator.AssertExpectations(t)
			mockEncrypter.AssertExpectations(t)
			mockWrapper.AssertExpectations(t)
		})
	}
}

func TestRawMasterKey_EncryptDataKey(t *testing.T) {
	type fields struct {
		metadata KeyMeta
	}
	type args struct {
		dk  DataKeyI
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
			fields:                         fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				&DataKey{provider: KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}, dataKey: []byte("raw1DataKeyRAWRAWRAW_12345678901")},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: nil,
		},
		{
			name:                           "dataKey_length_short",
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}},
			args: args{
				&DataKey{provider: KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}, dataKey: []byte("1234")},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: ErrEncryptKey,
		},
		{
			name:                           "dataKey_length_long",
			mockSerializedEncryptedDataKey: nil,
			fields:                         fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}},
			args: args{
				&DataKey{provider: KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}, dataKey: []byte("1234567890123456789012345678901234567890")}, // 40
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			wantErr: ErrEncryptKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockEncrypter := new(MockEncrypter)
			mockRandomGenerator := new(MockRandomGenerator)
			mockWrapper := new(MockWrapper)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			mockRandomGenerator.On("CryptoRandomBytes", mock.Anything).
				Return([]byte("mock_IV"), nil)
			mockEncrypter.On("Encrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return([]byte("mock_EncryptedKey"), []byte("mock_Tag"), nil)
			mockWrapper.On("SerializeEncryptedDataKey", mock.Anything, mock.Anything, mock.Anything).
				Return(tt.mockSerializedEncryptedDataKey, nil)

			rawMK := &RawMasterKey{
				metadata:   tt.fields.metadata,
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.EncryptDataKey(ctx, tt.args.dk, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				mockRandomGenerator.AssertNumberOfCalls(t, "CryptoRandomBytes", 0)
				mockEncrypter.AssertNumberOfCalls(t, "Encrypt", 0)
				mockWrapper.AssertNumberOfCalls(t, "SerializeEncryptedDataKey", 0)
				return
			}
			assert.NoError(t, err)

			want := &EncryptedDataKey{
				provider:         tt.fields.metadata,
				encryptedDataKey: tt.mockSerializedEncryptedDataKey,
			}

			assert.Equalf(t, want, got, "EncryptDataKey(%v, %v, %v)", tt.args.dk, tt.args.alg, tt.args.ec)

			mockRandomGenerator.AssertExpectations(t)
			mockEncrypter.AssertExpectations(t)
			mockWrapper.AssertExpectations(t)
		})
	}
}

func TestRawMasterKey_decryptDataKey(t *testing.T) {
	type fields struct {
		metadata KeyMeta
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
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
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
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}},
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
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}},
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
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
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
			mockEncrypter := new(MockEncrypter)
			mockRandomGenerator := new(MockRandomGenerator)
			mockWrapper := new(MockWrapper)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			mockWrapper.On("DeserializeEncryptedDataKey", mock.Anything, mock.Anything).
				Return([]byte("mock_encryptedData"), []byte("mock_IV"))

			if tt.decryptErr != nil {
				mockEncrypter.On("Decrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte(nil), tt.decryptErr)
			} else {
				mockEncrypter.On("Decrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(tt.want, nil)
			}

			rawMK := &RawMasterKey{
				metadata:   tt.fields.metadata,
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.decryptDataKey(tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				if tt.decryptErr == nil {
					mockRandomGenerator.AssertNumberOfCalls(t, "CryptoRandomBytes", 0)
					mockEncrypter.AssertNumberOfCalls(t, "Decrypt", 0)
					mockWrapper.AssertNumberOfCalls(t, "DeserializeEncryptedDataKey", 0)
					return
				}
				mockRandomGenerator.AssertExpectations(t)
				mockEncrypter.AssertExpectations(t)
				mockWrapper.AssertExpectations(t)
				return
			}
			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "decryptDataKey(%v, %v, %v)", tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)

			mockRandomGenerator.AssertExpectations(t)
			mockEncrypter.AssertExpectations(t)
			mockWrapper.AssertExpectations(t)
		})
	}
}

func TestRawMasterKey_DecryptDataKey(t *testing.T) {
	type fields struct {
		metadata KeyMeta
	}
	type args struct {
		encryptedDataKey EncryptedDataKeyI
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
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				&EncryptedDataKey{
					provider:         KeyMeta{ProviderID: "raw", KeyID: "rawMK1"},
					encryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			wantErr: nil,
		},
		{
			name:   "decrypts_other_key",
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1_THIS"}},
			args: args{
				&EncryptedDataKey{
					provider:         KeyMeta{ProviderID: "raw", KeyID: "rawMK2_OTHER"},
					encryptedDataKey: []byte("encryptedKeysOther_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    []byte("raw1DataKeyRAWRAWRAW_12345678901"),
			wantErr: nil,
		},
		{
			name:   "encrypted_data_key_nil",
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK1"}},
			args: args{
				nil,
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: ErrDecryptKey,
		},
		{
			name:   "encrypted_data_key_length_short",
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK2"}},
			args: args{
				&EncryptedDataKey{
					provider:         KeyMeta{ProviderID: "raw", KeyID: "rawMK2"},
					encryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_Tags"), // 48
				},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: ErrDecryptKey,
		},
		{
			name:   "encrypted_data_key_length_long",
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK3"}},
			args: args{
				&EncryptedDataKey{
					provider:         KeyMeta{ProviderID: "raw", KeyID: "rawMK3"},
					encryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV_IV_IV_IV_IV"), // 72
				},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:    nil,
			wantErr: ErrDecryptKey,
		},
		{
			name:   "decrypt_error",
			fields: fields{KeyMeta{ProviderID: "raw", KeyID: "rawMK4"}},
			args: args{
				&EncryptedDataKey{
					provider:         KeyMeta{ProviderID: "raw", KeyID: "rawMK4"},
					encryptedDataKey: []byte("encryptedKeyKeyKey_1234567890132mockTag_Tag_TagsmockIV_IV_IV"),
				},
				suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				suite.EncryptionContext{"a": "b"},
			},
			want:       nil,
			wantErr:    ErrDecryptKey,
			decryptErr: errors.New("AES error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockEncrypter := new(MockEncrypter)
			mockRandomGenerator := new(MockRandomGenerator)
			mockWrapper := new(MockWrapper)

			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()

			rand.CryptoRandGen = mockRandomGenerator

			mockWrapper.On("DeserializeEncryptedDataKey", mock.Anything, mock.Anything).
				Return([]byte("mock_encryptedData"), []byte("mock_IV"))

			if tt.decryptErr != nil {
				mockEncrypter.On("Decrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte(nil), tt.decryptErr)
			} else {
				mockEncrypter.On("Decrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(tt.want, nil)
			}

			rawMK := &RawMasterKey{
				metadata:   tt.fields.metadata,
				Encrypter:  mockEncrypter,
				keyWrapper: mockWrapper,
			}
			got, err := rawMK.DecryptDataKey(ctx, tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				if tt.decryptErr == nil {
					mockRandomGenerator.AssertNumberOfCalls(t, "CryptoRandomBytes", 0)
					mockEncrypter.AssertNumberOfCalls(t, "Decrypt", 0)
					mockWrapper.AssertNumberOfCalls(t, "DeserializeEncryptedDataKey", 0)
					return
				}
				mockRandomGenerator.AssertExpectations(t)
				mockEncrypter.AssertExpectations(t)
				mockWrapper.AssertExpectations(t)
				return
			}
			assert.NoError(t, err)

			want := &DataKey{
				provider:         tt.args.encryptedDataKey.KeyProvider(),
				dataKey:          tt.want,
				encryptedDataKey: tt.args.encryptedDataKey.EncryptedDataKey(),
			}

			assert.Equalf(t, want, got, "DecryptDataKey(%v, %v, %v)", tt.args.encryptedDataKey, tt.args.alg, tt.args.ec)

			mockRandomGenerator.AssertExpectations(t)
			mockEncrypter.AssertExpectations(t)
			mockWrapper.AssertExpectations(t)
		})
	}
}
