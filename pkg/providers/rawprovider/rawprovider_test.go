// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/common"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestRawKeyProvider_KeyProviderMethods(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(*testing.T) *mocks.MockKeyProvider
		wantID     string
		wantKind   types.ProviderKind
	}{
		{
			name: "empty NONE",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("").Once()
				kp.EXPECT().Kind().Return(types.ProviderKind(0)).Once()
				return kp
			},
			wantID:   "",
			wantKind: types.ProviderKind(0),
		},
		{
			name: "raw KeyProvider",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("raw").Once()
				kp.EXPECT().Kind().Return(types.Raw).Once()
				return kp
			},
			wantID:   "raw",
			wantKind: types.Raw,
		},
		{
			name: "KMS KeyProvider",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return(types.KmsProviderID).Once()
				kp.EXPECT().Kind().Return(types.AwsKms).Once()
				return kp
			},
			wantID:   types.KmsProviderID,
			wantKind: types.AwsKms,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyProviderMock := tt.setupMocks(t)
			rawKP := &RawKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}
			assert.Equal(t, tt.wantID, rawKP.ProviderID())
			assert.Equal(t, tt.wantKind, rawKP.ProviderKind())
		})
	}
}

func TestRawKeyProvider_ValidateProviderID(t *testing.T) {
	tests := []struct {
		name       string
		otherID    string
		setupMocks func(*testing.T) *mocks.MockKeyProvider
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "empty otherID",
			otherID: "",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("").Once()
				return kp
			},
			wantErr: false,
		},
		{
			name:    "matching otherID",
			otherID: "raw",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("raw").Once()
				return kp
			},
			wantErr: false,
		},
		{
			name:    "raw provider non-matching otherID",
			otherID: "aws-kms",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("raw").Twice()
				return kp
			},
			wantErr:    true,
			wantErrStr: "providerID doesnt match to with MasterKeyProvider ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyProviderMock := tt.setupMocks(t)
			rawKP := &RawKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}
			got := rawKP.ValidateProviderID(tt.otherID)
			if tt.wantErr {
				assert.Error(t, got)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, got, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, got)
			}
		})
	}
}

func TestRawKeyProvider_MasterKeyForDecrypt(t *testing.T) {
	ctx := context.Background()
	rawKP := &RawKeyProvider[model.MasterKey]{}
	got, err := rawKP.MasterKeyForDecrypt(ctx, model.KeyMeta{})
	assert.Nil(t, got)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "MasterKeyForDecrypt not allowed for RawKeyProvider")

	for _, e := range []error{
		providers.ErrMasterKeyProvider,
		providers.ErrMasterKeyProviderDecrypt,
	} {
		assert.ErrorIs(t, err, e)
	}
}

func TestRawKeyProvider_getStaticKey(t *testing.T) {
	tests := []struct {
		name       string
		staticKeys map[string][]byte
		keyID      string
		wantKey    []byte
		wantErr    bool
		wantErrStr string
	}{
		{
			name: "Key Exists",
			staticKeys: map[string][]byte{
				"key1": []byte("dataForKey1"),
			},
			keyID:   "key1",
			wantKey: []byte("dataForKey1"),
			wantErr: false,
		},
		{
			name: "Key Does Not Exist",
			staticKeys: map[string][]byte{
				"key2": []byte("dataForKey2"),
			},
			keyID:      "nonExistingKey",
			wantErr:    true,
			wantErrStr: "staticKey doesnt exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawKP := &RawKeyProvider[model.MasterKey]{
				options: Options{
					staticKeys: tt.staticKeys,
				},
			}

			got, err := rawKP.getStaticKey(tt.keyID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantKey, got)
			}
		})
	}
}

func TestRawKeyProvider_ValidateMasterKey(t *testing.T) {
	tests := []struct {
		name       string
		staticKeys map[string][]byte
		keyID      string
		wantErr    bool
		wantErrStr string
	}{
		{
			name: "Valid Key",
			staticKeys: map[string][]byte{
				"validKey": make([]byte, _rawMinKeyLength),
			},
			keyID:   "validKey",
			wantErr: false,
		},
		{
			name:       "Empty Key ID",
			staticKeys: map[string][]byte{},
			keyID:      "",
			wantErr:    true,
			wantErrStr: "staticKey doesnt exists",
		},
		{
			name: "Key Too Short",
			staticKeys: map[string][]byte{
				"shortKey": make([]byte, _rawMinKeyLength-1),
			},
			keyID:      "shortKey",
			wantErr:    true,
			wantErrStr: "static key length",
		},
		{
			name: "Key Does Not Exist",
			staticKeys: map[string][]byte{
				"validKey": make([]byte, _rawMinKeyLength),
			},
			keyID:      "nonExistingKey",
			wantErr:    true,
			wantErrStr: "staticKey doesnt exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawKP := &RawKeyProvider[model.MasterKey]{
				options: Options{
					staticKeys: tt.staticKeys,
				},
			}

			err := rawKP.ValidateMasterKey(tt.keyID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRawKeyProvider_NewMasterKey(t *testing.T) {
	tests := []struct {
		name          string
		keyID         string
		options       Options
		setupMocks    func(*testing.T, *RawKeyProvider[model.MasterKey], string, *mocks.MockKeyProvider, *mocks.MockMasterKeyFactory)
		wantErr       bool
		wantErrStr    string
		expectedKeyID string
	}{
		{
			name:  "Successful key creation",
			keyID: "valid-key-id",
			options: Options{
				staticKeys: map[string][]byte{"valid-key-id": make([]byte, 32)},
			},
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("raw").Twice()
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID)
				kf.EXPECT().NewMasterKey(rawKP.keyProvider.ID(), keyID, mock.Anything).
					Return(masterKeyMock, nil)
			},
			expectedKeyID: "valid-key-id",
		},
		{
			name:  "Error in getStaticKey",
			keyID: "invalid-key-id",
			options: Options{
				staticKeys: map[string][]byte{"valid-key-id": make([]byte, 32)},
			},
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, kf *mocks.MockMasterKeyFactory) {
				// no expectations due to error in getStaticKey
			},
			wantErr:    true,
			wantErrStr: "staticKey doesnt exists",
		},
		{
			name:  "Error in keyFactory NewMasterKey",
			keyID: "valid-key-id",
			options: Options{
				staticKeys: map[string][]byte{"valid-key-id": make([]byte, 32)},
			},
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("raw").Twice()
				kf.EXPECT().NewMasterKey(rawKP.keyProvider.ID(), keyID, mock.Anything).
					Return(nil, assert.AnError)
			},
			wantErr:    true,
			wantErrStr: assert.AnError.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			keyFactoryMock := mocks.NewMockMasterKeyFactory(t)
			keyProviderMock := mocks.NewMockKeyProvider(t)

			tt.options.keyFactory = keyFactoryMock
			rawKP := &RawKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
				options:     tt.options,
			}

			expectedKeyID := tt.keyID
			if tt.expectedKeyID != "" {
				expectedKeyID = tt.expectedKeyID
			}

			tt.setupMocks(t, rawKP, expectedKeyID, keyProviderMock, keyFactoryMock)

			key, err := rawKP.NewMasterKey(ctx, tt.keyID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
				assert.Equal(t, expectedKeyID, key.KeyID())
			}
		})
	}
}

func TestRawKeyProvider_MasterKeysForEncryption(t *testing.T) {
	masterKeyMock := mocks.NewMockMasterKey(t)
	memberKeyMock1 := mocks.NewMockMasterKey(t)
	memberKeyMock2 := mocks.NewMockMasterKey(t)
	tests := []struct {
		name                 string
		primaryMasterKey     *common.KeyEntry[model.MasterKey]
		keyEntriesForEncrypt map[string]*common.KeyEntry[model.MasterKey]
		wantPrimaryMasterKey model.MasterKey
		wantMemberKeys       []model.MasterKey
		wantErr              bool
		wantErrStr           string
		wantErrType          error
		wantErrChain         []error
	}{
		{
			name:                 "No Primary Key",
			primaryMasterKey:     nil,
			keyEntriesForEncrypt: make(map[string]*common.KeyEntry[model.MasterKey]),
			wantErr:              true,
			wantErrStr:           "no primary key",
			wantErrType:          providers.ErrMasterKeyProviderNoPrimaryKey,
			wantErrChain: []error{
				providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderEncrypt, providers.ErrMasterKeyProviderNoPrimaryKey,
			},
		},
		{
			name:                 "Primary Key with No Member Keys",
			primaryMasterKey:     common.NewKeyEntryPtr[model.MasterKey](masterKeyMock),
			keyEntriesForEncrypt: make(map[string]*common.KeyEntry[model.MasterKey]),
			wantPrimaryMasterKey: masterKeyMock,
			wantMemberKeys:       nil,
		},
		{
			name:             "Primary Key with Member Keys",
			primaryMasterKey: common.NewKeyEntryPtr[model.MasterKey](masterKeyMock),
			keyEntriesForEncrypt: map[string]*common.KeyEntry[model.MasterKey]{
				"key1": common.NewKeyEntryPtr[model.MasterKey](memberKeyMock1),
				"key2": common.NewKeyEntryPtr[model.MasterKey](memberKeyMock2),
			},
			wantPrimaryMasterKey: masterKeyMock,
			wantMemberKeys:       []model.MasterKey{memberKeyMock1, memberKeyMock2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			encryptionCtx := suite.EncryptionContext{"purpose": "testing"}

			rawKP := &RawKeyProvider[model.MasterKey]{
				primaryMasterKey:     tt.primaryMasterKey,
				keyEntriesForEncrypt: tt.keyEntriesForEncrypt,
			}

			primary, members, err := rawKP.MasterKeysForEncryption(ctx, encryptionCtx)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrChain != nil {
					for _, e := range tt.wantErrChain {
						assert.ErrorIs(t, err, e)
					}
				}
				assert.Nil(t, primary)
				assert.Nil(t, members)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantPrimaryMasterKey, primary)
				assert.Equal(t, tt.wantMemberKeys, members)
			}
		})
	}
}

func TestRawKeyProvider_MasterKeysForDecryption(t *testing.T) {
	tests := []struct {
		name                   string
		keyEntriesForEncrypt   map[string]*common.KeyEntry[model.MasterKey]
		expectedMasterKeyCount int
	}{
		{
			name: "Unique keys",
			keyEntriesForEncrypt: map[string]*common.KeyEntry[model.MasterKey]{
				"key1": common.NewKeyEntryPtr[model.MasterKey](mocks.NewMockMasterKey(t)),
				"key2": common.NewKeyEntryPtr[model.MasterKey](mocks.NewMockMasterKey(t)),
			},
			expectedMasterKeyCount: 2,
		},
		{
			name: "One key",
			keyEntriesForEncrypt: map[string]*common.KeyEntry[model.MasterKey]{
				"key3": common.NewKeyEntryPtr[model.MasterKey](mocks.NewMockMasterKey(t)),
			},
			expectedMasterKeyCount: 1,
		},
		{
			name:                   "No keys",
			keyEntriesForEncrypt:   make(map[string]*common.KeyEntry[model.MasterKey]),
			expectedMasterKeyCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawKP := &RawKeyProvider[model.MasterKey]{
				keyEntriesForEncrypt: tt.keyEntriesForEncrypt,
			}

			masterKeys := rawKP.MasterKeysForDecryption()
			assert.Len(t, masterKeys, tt.expectedMasterKeyCount)
		})
	}
}

func TestRawKeyProvider_DecryptDataKey(t *testing.T) {
	tests := []struct {
		name             string
		setupMocks       func(*testing.T, *mocks.MockKeyProvider, model.DataKeyI)
		encryptedDataKey model.EncryptedDataKeyI
		alg              *suite.AlgorithmSuite
		ec               suite.EncryptionContext
		want             model.DataKeyI
		wantErr          bool
	}{
		{
			name: "Successful decryption",
			setupMocks: func(t *testing.T, kp *mocks.MockKeyProvider, dk model.DataKeyI) {
				kp.EXPECT().
					DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(dk, nil).Once()
			},
			encryptedDataKey: mocks.NewMockEncryptedDataKey(t),
			alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:               suite.EncryptionContext{"test": "ok"},
			want:             mocks.NewMockDataKey(t),
			wantErr:          false,
		},
		{
			name: "Error during decryption",
			setupMocks: func(t *testing.T, keyProviderMock *mocks.MockKeyProvider, dk model.DataKeyI) {
				keyProviderMock.EXPECT().
					DecryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			encryptedDataKey: mocks.NewMockEncryptedDataKey(t),
			alg:              suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:               suite.EncryptionContext{"test": "ok"},
			want:             nil,
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			keyProviderMock := mocks.NewMockKeyProvider(t)
			tt.setupMocks(t, keyProviderMock, tt.want)

			rawKP := &RawKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}

			got, err := rawKP.DecryptDataKey(ctx, tt.encryptedDataKey, tt.alg, tt.ec)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestRawKeyProvider_DecryptDataKeyFromList(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(*testing.T, *mocks.MockKeyProvider, model.DataKeyI)
		edks       []model.EncryptedDataKeyI
		alg        *suite.AlgorithmSuite
		ec         suite.EncryptionContext
		want       model.DataKeyI
		wantErr    bool
	}{
		{
			name: "Successful decryption",
			setupMocks: func(t *testing.T, kp *mocks.MockKeyProvider, dk model.DataKeyI) {
				kp.EXPECT().
					DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(dk, nil).Once()
			},
			edks:    []model.EncryptedDataKeyI{mocks.NewMockEncryptedDataKey(t)},
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:      suite.EncryptionContext{"test": "ok"},
			want:    mocks.NewMockDataKey(t),
			wantErr: false,
		},
		{
			name: "Error during decryption",
			setupMocks: func(t *testing.T, kp *mocks.MockKeyProvider, dk model.DataKeyI) {
				kp.EXPECT().
					DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			edks:    []model.EncryptedDataKeyI{mocks.NewMockEncryptedDataKey(t)},
			alg:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			ec:      suite.EncryptionContext{"test": "ok"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			keyProviderMock := mocks.NewMockKeyProvider(t)
			tt.setupMocks(t, keyProviderMock, tt.want)

			rawKP := &RawKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}

			got, err := rawKP.DecryptDataKeyFromList(ctx, tt.edks, tt.alg, tt.ec)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNewWithOpts(t *testing.T) {
	type args struct {
		providerID string
		optFns     []func(options *Options) error
	}
	tests := []struct {
		name        string
		args        args
		setupMocks  func(*testing.T, []func(options *Options) error) []func(options *Options) error
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Valid Raw Provider",
			args: args{
				providerID: "raw",
				optFns: []func(options *Options) error{
					WithStaticKey("key1", make([]byte, _rawMinKeyLength)),
				},
			},
		},
		{
			name: "Error in Option",
			args: args{
				providerID: "raw",
				optFns: []func(options *Options) error{
					func(o *Options) error {
						return assert.AnError
					},
				},
			},
			wantErr:     true,
			wantErrStr:  "provider option error",
			wantErrType: providers.ErrConfig,
		},
		{
			name: "Invalid Provider ID",
			args: args{
				providerID: "aws-kms",
				optFns: []func(options *Options) error{
					WithStaticKey("key1", make([]byte, _rawMinKeyLength)),
				},
			},
			wantErr:     true,
			wantErrStr:  "providerID is reserved",
			wantErrType: providers.ErrConfig,
		},
		{
			name: "Valid options with error from MasterKeyFactory",
			args: args{
				providerID: "raw",
				optFns: []func(options *Options) error{
					WithStaticKey("key1", make([]byte, _rawMinKeyLength)),
				},
			},
			setupMocks: func(t *testing.T, optFns []func(options *Options) error) []func(options *Options) error {
				kf := mocks.NewMockMasterKeyFactory(t)
				kf.EXPECT().NewMasterKey(mock.Anything, mock.Anything, mock.Anything).Return(nil, assert.AnError)
				optFns = append(optFns, WithKeyFactory(kf))
				return optFns
			},
			wantErr:     true,
			wantErrStr:  "add MasterKey error",
			wantErrType: providers.ErrMasterKeyProvider,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.args.optFns = tt.setupMocks(t, tt.args.optFns)
			}
			got, err := NewWithOpts(tt.args.providerID, tt.args.optFns...)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func Test_newRawProvider(t *testing.T) {
	type args struct {
		options *Options
	}
	tests := []struct {
		name string
		args args
		want *RawKeyProvider[model.MasterKey]
	}{
		{
			name: "Raw Provider",
			args: args{
				options: &Options{keyProvider: nil},
			},
			want: &RawKeyProvider[model.MasterKey]{
				keyEntriesForEncrypt: make(map[string]*common.KeyEntry[model.MasterKey]),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, newRawProvider(tt.args.options), "newRawProvider(%v)", tt.args.options)
		})
	}
}

func TestRawKeyProvider_AddMasterKey(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		setupMocks   func(*testing.T, *RawKeyProvider[model.MasterKey], string, *mocks.MockMasterKeyFactory)
		encryptIndex []string
		staticKeys   []string
		wantErr      bool
		wantErrStr   string
	}{
		{
			name:  "Valid keyID",
			keyID: "key1",
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kf *mocks.MockMasterKeyFactory) {
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID)
				kf.EXPECT().NewMasterKey(mock.Anything, keyID, mock.Anything).Return(masterKeyMock, nil)
			},
			staticKeys: []string{"key1"},
		},
		{
			name:  "Valid keyID KeyFactory Error",
			keyID: "key2",
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kf *mocks.MockMasterKeyFactory) {
				kf.EXPECT().NewMasterKey(mock.Anything, keyID, mock.Anything).Return(nil, assert.AnError)
			},
			wantErr:    true,
			staticKeys: []string{"key2"},
		},
		{
			name:  "Invalid keyID Validation Error",
			keyID: "key3",
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kf *mocks.MockMasterKeyFactory) {
				// no mock expectation as validation will fail before reaching factory
			},
			wantErr:    true,
			wantErrStr: "staticKey doesnt exists",
			staticKeys: []string{"key2"},
		},
		{
			name:  "Existing keyID",
			keyID: "key3",
			setupMocks: func(t *testing.T, rawKP *RawKeyProvider[model.MasterKey], keyID string, kf *mocks.MockMasterKeyFactory) {
				// no mock expectation as key already exists
			},
			encryptIndex: []string{"key3"},
			staticKeys:   []string{"key3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFactoryMock := mocks.NewMockMasterKeyFactory(t)
			keyProviderMock := mocks.NewMockKeyProvider(t)
			keyProviderMock.EXPECT().ID().Return("raw").Maybe()

			var primaryMasterKey *common.KeyEntry[model.MasterKey]
			keyEntriesForEncrypt := make(map[string]*common.KeyEntry[model.MasterKey])
			staticKeys := make(map[string][]byte)

			for _, keyID := range tt.staticKeys {
				staticKeys[keyID] = make([]byte, _rawMinKeyLength)
			}

			for i, keyID := range tt.encryptIndex {
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID).Maybe()
				keyEntriesForEncrypt[keyID] = common.NewKeyEntryPtr[model.MasterKey](masterKeyMock)

				if i == 0 {
					primaryMasterKey = common.NewKeyEntryPtr[model.MasterKey](masterKeyMock)
				}
			}

			rawKP := &RawKeyProvider[model.MasterKey]{
				options: Options{
					staticKeys: staticKeys,
					keyFactory: keyFactoryMock,
				},
				keyEntriesForEncrypt: keyEntriesForEncrypt,
				primaryMasterKey:     primaryMasterKey,
				keyProvider:          keyProviderMock,
			}

			tt.setupMocks(t, rawKP, tt.keyID, keyFactoryMock)

			got, err := rawKP.AddMasterKey(tt.keyID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.keyID, got.KeyID())
				assert.Contains(t, rawKP.keyEntriesForEncrypt, tt.keyID)
				if primaryMasterKey == nil {
					assert.Equal(t, tt.keyID, rawKP.primaryMasterKey.GetEntry().KeyID())
				}
			}
		})
	}
}
