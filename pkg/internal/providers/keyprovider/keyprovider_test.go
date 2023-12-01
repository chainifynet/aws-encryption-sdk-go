// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewKeyProvider(t *testing.T) {
	type args struct {
		providerID    string
		providerKind  types.ProviderKind
		vendOnDecrypt bool
	}
	tests := []struct {
		name string
		args args
		want *KeyProvider
	}{
		{
			name: "Raw Key Provider",
			args: args{
				providerID:    "raw",
				providerKind:  types.Raw,
				vendOnDecrypt: false,
			},
			want: &KeyProvider{
				providerID:    "raw",
				providerKind:  types.Raw,
				vendOnDecrypt: false,
			},
		},
		{
			name: "KMS Key Provider without discovery",
			args: args{
				providerID:    types.KmsProviderID,
				providerKind:  types.AwsKms,
				vendOnDecrypt: false,
			},
			want: &KeyProvider{
				providerID:    types.KmsProviderID,
				providerKind:  types.AwsKms,
				vendOnDecrypt: false,
			},
		},
		{
			name: "KMS Key Provider with discovery",
			args: args{
				providerID:    types.KmsProviderID,
				providerKind:  types.AwsKms,
				vendOnDecrypt: true,
			},
			want: &KeyProvider{
				providerID:    types.KmsProviderID,
				providerKind:  types.AwsKms,
				vendOnDecrypt: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewKeyProvider(tt.args.providerID, tt.args.providerKind, tt.args.vendOnDecrypt)
			assert.Equalf(t, tt.want, got, "NewKeyProvider(%v, %v, %v)", tt.args.providerID, tt.args.providerKind, tt.args.vendOnDecrypt)

			assert.Equal(t, tt.args.providerID, got.ID())
			assert.Equal(t, tt.args.providerKind, got.Kind())
			assert.Equal(t, tt.args.vendOnDecrypt, got.VendOnDecrypt())
		})
	}
}

func TestKeyProvider_String(t *testing.T) {
	type fields struct {
		providerID   string
		providerKind types.ProviderKind
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Raw Key Provider",
			fields: fields{
				providerID:   "raw",
				providerKind: types.Raw,
			},
			want: "raw:RAW",
		},
		{
			name: "KMS Key Provider",
			fields: fields{
				providerID:   types.KmsProviderID,
				providerKind: types.AwsKms,
			},
			want: "aws-kms:AWS_KMS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := &KeyProvider{
				providerID:   tt.fields.providerID,
				providerKind: tt.fields.providerKind,
			}
			assert.Equal(t, tt.want, kp.String())
			assert.Equal(t, tt.want, fmt.Sprintf("%#v", kp))
		})
	}
}

func TestKeyProvider_DecryptDataKey(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func(*testing.T, *mocks.MockMasterKeyProvider, *mocks.MockEncryptedDataKey, model.DataKeyI)
		kp          *KeyProvider
		alg         *suite.AlgorithmSuite
		ec          suite.EncryptionContext
		want        model.DataKeyI
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Valid decryption",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "raw", KeyID: "test1"})

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				masterKey := mocks.NewMockMasterKey(t)
				masterKey.EXPECT().KeyID().Return("test1")
				masterKey.EXPECT().OwnsDataKey(mock.Anything).Return(true)
				masterKey.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(dk, nil)

				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{masterKey})

				mkp.EXPECT().ProviderID().Return("raw")
			},
			kp:      &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:      suite.EncryptionContext{"test": "ok"},
			want:    mocks.NewMockDataKey(t),
			wantErr: false,
		},
		{
			name: "Valid decryption with second MasterKey",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "raw", KeyID: "test2"})
				edk.EXPECT().KeyID().Return("test2")

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				mkp.EXPECT().ProviderID().Return("raw")

				masterKey := mocks.NewMockMasterKey(t)
				masterKey.EXPECT().KeyID().Return("test1")
				masterKey.EXPECT().OwnsDataKey(mock.Anything).Return(true)
				masterKey.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, keys.ErrDecryptKey)

				masterKey2 := mocks.NewMockMasterKey(t)
				masterKey2.EXPECT().KeyID().Return("test2")
				masterKey2.EXPECT().OwnsDataKey(mock.Anything).Return(true)
				masterKey2.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(dk, nil)

				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{masterKey, masterKey2})
			},
			kp:      &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:      suite.EncryptionContext{"test": "ok"},
			want:    mocks.NewMockDataKey(t),
			wantErr: false,
		},
		{
			name: "Invalid provider ID",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "static", KeyID: "key2"})

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(fmt.Errorf("validate provider ID error"))
			},
			kp:          &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "DecryptDataKey validate expected error",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},

		{
			name: "MasterKey MasterKeyForDecrypt does not own encrypted data key",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "aws-kms", KeyID: "key3"})

				mkp.EXPECT().ProviderID().Return("aws-kms")

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{})

				masterKey := mocks.NewMockMasterKey(t)
				masterKey.EXPECT().KeyID().Return("test1")
				masterKey.EXPECT().OwnsDataKey(mock.Anything).Return(false)

				mkp.EXPECT().MasterKeyForDecrypt(mock.Anything, mock.Anything).
					Return(masterKey, nil)
			},
			kp:          &KeyProvider{providerID: "aws-kms", vendOnDecrypt: true},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "unable to decrypt data key:",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},

		{
			name: "Error in MasterKeyForDecrypt is forbidden",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "aws-kms", KeyID: "key3"})
				edk.EXPECT().KeyID().Return("key3")

				mkp.EXPECT().ProviderID().Return("aws-kms")

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{})

				mkp.EXPECT().MasterKeyForDecrypt(mock.Anything, mock.Anything).
					Return(nil, providers.ErrMasterKeyProviderDecryptForbidden)
			},
			kp:          &KeyProvider{providerID: "aws-kms", vendOnDecrypt: true},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "DecryptDataKey MKP.MasterKeyForDecrypt is forbidden for keyID",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
		{
			name: "Error in MasterKeyForDecrypt",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "aws-kms", KeyID: "key3"})
				edk.EXPECT().KeyID().Return("key3")

				mkp.EXPECT().ProviderID().Return("aws-kms")

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{})

				mkp.EXPECT().MasterKeyForDecrypt(mock.Anything, mock.Anything).
					Return(nil, providers.ErrMasterKeyProviderDecrypt)
			},
			kp:          &KeyProvider{providerID: "aws-kms", vendOnDecrypt: true},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "unable to decrypt data key:",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
		{
			name: "No MasterKeys for decryption",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "aws-kms", KeyID: "key3"})

				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{})
			},
			kp:          &KeyProvider{providerID: "aws-kms", vendOnDecrypt: false},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "unable to decrypt data key:",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
		{
			name: "Error during data key decryption by a MasterKey",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "aws-kms", KeyID: "key3"})
				edk.EXPECT().KeyID().Return("key3")

				mkp.EXPECT().ProviderID().Return("aws-kms")
				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				masterKey := mocks.NewMockMasterKey(t)
				masterKey.EXPECT().KeyID().Return("test1")
				masterKey.EXPECT().OwnsDataKey(mock.Anything).Return(true)
				masterKey.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, keys.ErrDecryptKey)
				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{masterKey})
			},
			kp:          &KeyProvider{providerID: "aws-kms", vendOnDecrypt: false},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "unable to decrypt data key, member key error",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
		{
			name: "Error during data key decryption by two MasterKeys",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edk *mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "aws-kms", KeyID: "key3"})
				edk.EXPECT().KeyID().Return("key3")

				mkp.EXPECT().ProviderID().Return("aws-kms")
				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil)

				masterKey := mocks.NewMockMasterKey(t)
				masterKey.EXPECT().KeyID().Return("test1")
				masterKey.EXPECT().OwnsDataKey(mock.Anything).Return(true)
				masterKey.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, keys.ErrDecryptKey)

				masterKey2 := mocks.NewMockMasterKey(t)
				masterKey2.EXPECT().KeyID().Return("test2")
				masterKey2.EXPECT().OwnsDataKey(mock.Anything).Return(true)
				masterKey2.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("some other error"))

				mkp.EXPECT().MasterKeyForDecrypt(mock.Anything, mock.Anything).
					Return(masterKey2, nil)
				mkp.EXPECT().MasterKeysForDecryption().Return([]model.MasterKey{masterKey})
			},
			kp:          &KeyProvider{providerID: "aws-kms", vendOnDecrypt: true},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "unable to decrypt data key, member key error",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mkp := mocks.NewMockMasterKeyProvider(t)
			edk := mocks.NewMockEncryptedDataKey(t)

			tt.setupMocks(t, mkp, edk, tt.want)

			got, err := tt.kp.DecryptDataKey(ctx, mkp, edk, tt.alg, tt.ec)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestKeyProvider_DecryptDataKeyFromList(t *testing.T) { //nolint:gocognit
	tests := []struct {
		name        string
		setupMocks  func(*testing.T, *mocks.MockMasterKeyProvider, []*mocks.MockEncryptedDataKey, model.DataKeyI)
		kp          *KeyProvider
		setupEDKs   func(*testing.T) []*mocks.MockEncryptedDataKey
		alg         *suite.AlgorithmSuite
		ec          suite.EncryptionContext
		want        model.DataKeyI
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Valid decryption first EDK",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edks []*mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil).Once()
				for i, edk := range edks {
					edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "raw", KeyID: "test" + strconv.Itoa(i)})

					if i == 0 { // simulating decryption success on the first key
						mkp.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(dk, nil).Once()
						break // only setting up mock for the first successful decryption
					}
				}
			},
			kp: &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			setupEDKs: func(t *testing.T) []*mocks.MockEncryptedDataKey {
				return []*mocks.MockEncryptedDataKey{
					mocks.NewMockEncryptedDataKey(t),
					mocks.NewMockEncryptedDataKey(t),
				}
			},
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:      suite.EncryptionContext{"test": "ok"},
			want:    mocks.NewMockDataKey(t),
			wantErr: false,
		},
		{
			name: "Valid decryption with second EDK",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edks []*mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil).Twice()
				for i, edk := range edks {
					edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "raw", KeyID: "key" + strconv.Itoa(i)})

					if i == 0 {
						mkp.EXPECT().DecryptDataKey(mock.Anything, edk, mock.Anything, mock.Anything).
							Return(nil, providers.ErrMasterKeyProviderDecrypt).Once()
					}

					if i == 1 {
						mkp.EXPECT().DecryptDataKey(mock.Anything, edk, mock.Anything, mock.Anything).
							Return(dk, nil).Once()
					}
				}
			},
			kp: &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			setupEDKs: func(t *testing.T) []*mocks.MockEncryptedDataKey {
				return []*mocks.MockEncryptedDataKey{
					mocks.NewMockEncryptedDataKey(t),
					mocks.NewMockEncryptedDataKey(t),
				}
			},
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:      suite.EncryptionContext{"test": "ok"},
			want:    mocks.NewMockDataKey(t),
			wantErr: false,
		},
		{
			name: "Not standard error in EDK decryption",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edks []*mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				mkp.EXPECT().ValidateProviderID(mock.Anything).Return(nil).Once()
				for i, edk := range edks {
					edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "raw", KeyID: "testkey" + strconv.Itoa(i)})

					if i == 0 {
						mkp.EXPECT().DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(nil, fmt.Errorf("some other error")).Once()
					}
				}
			},
			kp: &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			setupEDKs: func(t *testing.T) []*mocks.MockEncryptedDataKey {
				return []*mocks.MockEncryptedDataKey{
					mocks.NewMockEncryptedDataKey(t),
				}
			},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        mocks.NewMockDataKey(t),
			wantErr:     true,
			wantErrStr:  "unable to decrypt any data key, member error:",
			wantErrType: providers.ErrMasterKeyProvider,
		},
		{
			name: "No EDKs",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edks []*mocks.MockEncryptedDataKey, dk model.DataKeyI) {
			},
			kp: &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			setupEDKs: func(t *testing.T) []*mocks.MockEncryptedDataKey {
				return []*mocks.MockEncryptedDataKey{}
			},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "unable to decrypt any data key:",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
		{
			name: "Validation error in provider ID",
			setupMocks: func(t *testing.T, mkp *mocks.MockMasterKeyProvider, edks []*mocks.MockEncryptedDataKey, dk model.DataKeyI) {
				mkp.EXPECT().ValidateProviderID(mock.Anything).
					Return(fmt.Errorf("validate provider ID error")).Once()
				for _, edk := range edks {
					edk.EXPECT().KeyProvider().Return(model.KeyMeta{ProviderID: "invalid", KeyID: "key2"}).
						Times(3)
				}
			},
			kp: &KeyProvider{providerID: "raw", providerKind: types.Raw, vendOnDecrypt: false},
			setupEDKs: func(t *testing.T) []*mocks.MockEncryptedDataKey {
				return []*mocks.MockEncryptedDataKey{
					mocks.NewMockEncryptedDataKey(t),
				}
			},
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:          suite.EncryptionContext{"test": "ok"},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "DecryptDataKeyFromList validate expected error",
			wantErrType: providers.ErrMasterKeyProviderDecrypt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mkp := mocks.NewMockMasterKeyProvider(t)
			edkMocks := tt.setupEDKs(t)
			mkp.EXPECT().ProviderID().
				Return(tt.kp.providerID).Maybe()

			tt.setupMocks(t, mkp, edkMocks, tt.want)

			var edks []model.EncryptedDataKeyI
			for _, edkMock := range edkMocks {
				edks = append(edks, edkMock)
			}

			got, err := tt.kp.DecryptDataKeyFromList(ctx, mkp, edks, tt.alg, tt.ec)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
