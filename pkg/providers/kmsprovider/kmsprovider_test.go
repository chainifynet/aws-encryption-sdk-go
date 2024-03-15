// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/common"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		keyIDs      []string
		wantErr     bool
		wantErrType error
	}{
		{
			name:    "empty keyIDs",
			keyIDs:  []string{},
			wantErr: false,
		},
		{
			name:    "nil keyIDs",
			keyIDs:  nil,
			wantErr: false,
		},
		{
			name: "valid keyIDs",
			keyIDs: []string{
				"arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
			wantErr: false,
		},
		{
			name:        "invalid keyIDs",
			keyIDs:      []string{"invalid-arn"},
			wantErr:     true,
			wantErrType: providers.ErrConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.keyIDs...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func Test_newKmsProvider(t *testing.T) {
	type args struct {
		options *Options
		pType   ProviderType
	}
	tests := []struct {
		name string
		args args
		want *KmsKeyProvider[model.MasterKey]
	}{
		{
			name: "Strict with nil options",
			args: args{
				options: &Options{keyProvider: nil},
				pType:   StrictKmsProvider,
			},
			want: &KmsKeyProvider[model.MasterKey]{
				regionalClients:      make(map[string]model.KMSClient),
				keyEntriesForDecrypt: make(map[string]common.KeyEntry[model.MasterKey]),
				keyEntriesForEncrypt: make(map[string]common.KeyEntry[model.MasterKey]),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, newKmsProvider(tt.args.options, tt.args.pType), "newKmsProvider(%v, %v)", tt.args.options, tt.args.pType)
		})
	}
}

func TestNewWithOpts(t *testing.T) {
	type args struct {
		keyIDs []string
		optFns []func(options *Options) error
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
			name: "valid keyIDs",
			args: args{
				keyIDs: []string{
					"arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
					"arn:aws:kms:eu-west-1:123456789011:key/12345678-1234-1234-1234-123456789011",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid keyIDs",
			args: args{
				keyIDs: []string{"invalid-arn"},
			},
			wantErr:     true,
			wantErrType: providers.ErrConfig,
		},
		{
			name: "valid keyIDs with discovery",
			args: args{
				keyIDs: []string{
					"arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				},
				optFns: []func(options *Options) error{
					WithDiscovery(),
				},
			},
			wantErr:     true,
			wantErrType: providers.ErrConfig,
		},
		{
			name: "error in option",
			args: args{
				keyIDs: nil,
				optFns: []func(options *Options) error{
					func(o *Options) error {
						return fmt.Errorf("some error in option")
					},
				},
			},
			wantErr:     true,
			wantErrStr:  "provider config error",
			wantErrType: providers.ErrConfig,
		},
		{
			name: "valid keyID arn following error from MasterKeyFactory",
			args: args{
				keyIDs: []string{
					"arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				},
			},
			setupMocks: func(t *testing.T, optFns []func(options *Options) error) []func(options *Options) error {
				mkf := mocks.NewMockMasterKeyFactory(t)
				mkf.EXPECT().NewMasterKey(mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("NewMasterKey error")).Once()

				optFns = append(optFns, WithKeyFactory(mkf))
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
			got, err := NewWithOpts(tt.args.keyIDs, tt.args.optFns...)
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

func TestKmsKeyProvider_KeyProviderMethods(t *testing.T) {
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
			kmsKP := &KmsKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}
			assert.Equal(t, tt.wantID, kmsKP.ProviderID())
			assert.Equal(t, tt.wantKind, kmsKP.ProviderKind())
		})
	}
}

func TestKmsKeyProvider_ValidateProviderID(t *testing.T) {
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
			otherID: "aws-kms",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("aws-kms").Once()
				return kp
			},
			wantErr: false,
		},
		{
			name:    "aws-kms provider non-matching otherID",
			otherID: "raw",
			setupMocks: func(t *testing.T) *mocks.MockKeyProvider {
				kp := mocks.NewMockKeyProvider(t)
				kp.EXPECT().ID().Return("aws-kms").Twice()
				return kp
			},
			wantErr:    true,
			wantErrStr: "providerID doesnt match to with MasterKeyProvider ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyProviderMock := tt.setupMocks(t)
			kmsKP := &KmsKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}
			got := kmsKP.ValidateProviderID(tt.otherID)
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

func TestKmsKeyProvider_ValidateMasterKey(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "empty keyID",
			keyID:      "",
			wantErr:    true,
			wantErrStr: "invalid keyID",
		},
		{
			name:       "invalid keyID",
			keyID:      "invalid-arn",
			wantErr:    true,
			wantErrStr: "invalid keyID",
		},
		{
			name:    "valid keyID",
			keyID:   "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
			wantErr: false,
		},
		{
			name:    "valid MRK keyID",
			keyID:   "arn:aws:kms:us-east-2:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kmsKP := &KmsKeyProvider[model.MasterKey]{}
			err := kmsKP.ValidateMasterKey(tt.keyID)
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

func TestKmsKeyProvider_DecryptDataKeyFromList(t *testing.T) {
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
					Return(nil, fmt.Errorf("decryption error")).Once()
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

			kmsKP := &KmsKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}

			got, err := kmsKP.DecryptDataKeyFromList(ctx, tt.edks, tt.alg, tt.ec)

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

func TestKmsKeyProvider_DecryptDataKey(t *testing.T) {
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
					Return(nil, fmt.Errorf("decryption error")).Once()
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

			kmsKP := &KmsKeyProvider[model.MasterKey]{
				keyProvider: keyProviderMock,
			}

			got, err := kmsKP.DecryptDataKey(ctx, tt.encryptedDataKey, tt.alg, tt.ec)

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

func TestKmsKeyProvider_addRegionalClient(t *testing.T) {
	tests := []struct {
		name            string
		setupMocks      func(*testing.T, *mocks.MockKMSClientFactory)
		region          string
		initialClients  map[string]model.KMSClient
		options         Options
		wantErr         bool
		wantErrStr      string
		expectedClients int
	}{
		{
			name:   "Successful client addition",
			region: "us-west-2",
			setupMocks: func(t *testing.T, cf *mocks.MockKMSClientFactory) {
				cf.EXPECT().
					NewFromConfig(mock.Anything, mock.Anything).
					Return(mocks.NewMockKMSClient(t)).Once()
			},
			initialClients:  make(map[string]model.KMSClient),
			options:         Options{},
			wantErr:         false,
			expectedClients: 1,
		},
		{
			name:   "Client already exists",
			region: "us-east-1",
			setupMocks: func(t *testing.T, cf *mocks.MockKMSClientFactory) {
				// No expectations as the client is already present
			},
			initialClients: map[string]model.KMSClient{
				"us-east-1": mocks.NewMockKMSClient(t),
			},
			options:         Options{},
			wantErr:         false,
			expectedClients: 1, // No new client should be added
		},
		{
			name:   "Error loading AWS config",
			region: "eu-central-1",
			setupMocks: func(t *testing.T, cf *mocks.MockKMSClientFactory) {
				// No expectation set for clientFactoryMock as config loading fails
			},
			initialClients: make(map[string]model.KMSClient),
			options: Options{
				awsConfigLoaders: []func(*config.LoadOptions) error{
					func(o *config.LoadOptions) error {
						return fmt.Errorf("config load error")
					},
				},
			},
			wantErr:         true,
			wantErrStr:      "unable to load AWS config",
			expectedClients: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			clientFactoryMock := mocks.NewMockKMSClientFactory(t)
			tt.setupMocks(t, clientFactoryMock)

			tt.options.clientFactory = clientFactoryMock

			kmsKP := &KmsKeyProvider[model.MasterKey]{
				regionalClients: tt.initialClients,
				options:         tt.options,
			}

			err := kmsKP.addRegionalClient(ctx, tt.region)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedClients, len(kmsKP.regionalClients))
		})
	}
}

func TestKmsKeyProvider_getClient(t *testing.T) {
	tests := []struct {
		name           string
		keyID          string
		setupMocks     func(*testing.T, *KmsKeyProvider[model.MasterKey])
		defaultRegion  string
		initialClients map[string]model.KMSClient
		wantErr        bool
		wantErrStr     string
	}{
		{
			name:          "Successful new client retrieval",
			keyID:         "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			defaultRegion: "us-east-1",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey]) {
				cf := mocks.NewMockKMSClientFactory(t)
				kmsClient := mocks.NewMockKMSClient(t)
				cf.EXPECT().
					NewFromConfig(mock.Anything, mock.Anything).
					Return(kmsClient).Once()
				kmsKP.options.clientFactory = cf
				kmsKP.regionalClients["us-west-1"] = mocks.NewMockKMSClient(t)
			},
			initialClients: make(map[string]model.KMSClient),
		},
		{
			name:          "Successful existing client retrieval",
			keyID:         "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			defaultRegion: "us-east-1",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey]) {
				kmsKP.options.clientFactory = mocks.NewMockKMSClientFactory(t)
				kmsKP.regionalClients["us-west-2"] = mocks.NewMockKMSClient(t)
			},
			initialClients: make(map[string]model.KMSClient),
		},
		{
			name:           "Error from regionForKeyID",
			keyID:          "invalid-key-id",
			defaultRegion:  "",
			setupMocks:     func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey]) {},
			initialClients: make(map[string]model.KMSClient),
			wantErr:        true,
			wantErrStr:     "KMS client error",
		},
		{
			name:          "Error from addRegionalClient",
			keyID:         "arn:aws:kms:eu-central-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			defaultRegion: "eu-central-1",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey]) {
				kmsKP.options.clientFactory = mocks.NewMockKMSClientFactory(t)
				kmsKP.options.awsConfigLoaders = []func(*config.LoadOptions) error{
					func(o *config.LoadOptions) error {
						return fmt.Errorf("config load error")
					},
				}
			},
			initialClients: make(map[string]model.KMSClient),
			wantErr:        true,
			wantErrStr:     "KMS client error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			kmsKP := &KmsKeyProvider[model.MasterKey]{
				options: Options{
					defaultRegion: tt.defaultRegion,
				},
				regionalClients: tt.initialClients,
			}

			tt.setupMocks(t, kmsKP)

			client, err := kmsKP.getClient(ctx, tt.keyID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestKmsKeyProvider_MasterKeysForDecryption(t *testing.T) {
	tests := []struct {
		name                   string
		keyEntriesForDecrypt   map[string]common.KeyEntry[model.MasterKey]
		keyEntriesForEncrypt   map[string]common.KeyEntry[model.MasterKey]
		expectedMasterKeyCount int
	}{
		{
			name: "Unique keys in both maps",
			keyEntriesForDecrypt: map[string]common.KeyEntry[model.MasterKey]{
				"key1": common.NewKeyEntry[model.MasterKey](mocks.NewMockMasterKey(t)),
			},
			keyEntriesForEncrypt: map[string]common.KeyEntry[model.MasterKey]{
				"key2": common.NewKeyEntry[model.MasterKey](mocks.NewMockMasterKey(t)),
			},
			expectedMasterKeyCount: 2,
		},
		{
			name: "Duplicate keys in both maps",
			keyEntriesForDecrypt: map[string]common.KeyEntry[model.MasterKey]{
				"key1": common.NewKeyEntry[model.MasterKey](mocks.NewMockMasterKey(t)),
			},
			keyEntriesForEncrypt: map[string]common.KeyEntry[model.MasterKey]{
				"key1": common.NewKeyEntry[model.MasterKey](mocks.NewMockMasterKey(t)),
			},
			expectedMasterKeyCount: 1,
		},
		{
			name:                   "No keys",
			keyEntriesForDecrypt:   map[string]common.KeyEntry[model.MasterKey]{},
			keyEntriesForEncrypt:   map[string]common.KeyEntry[model.MasterKey]{},
			expectedMasterKeyCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kmsKP := &KmsKeyProvider[model.MasterKey]{
				keyEntriesForDecrypt: tt.keyEntriesForDecrypt,
				keyEntriesForEncrypt: tt.keyEntriesForEncrypt,
			}

			masterKeys := kmsKP.MasterKeysForDecryption()
			assert.Len(t, masterKeys, tt.expectedMasterKeyCount)
		})
	}
}

func TestKmsKeyProvider_NewMasterKey(t *testing.T) {
	tests := []struct {
		name          string
		keyID         string
		providerType  ProviderType
		options       Options
		setupMocks    func(*testing.T, *KmsKeyProvider[model.MasterKey], string, *mocks.MockKMSClientFactory, *mocks.MockMasterKeyFactory)
		wantErr       bool
		wantErrStr    string
		wantErrType   error
		expectedKeyID string
	}{
		{
			name:         "Successful key creation",
			keyID:        "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			providerType: StrictKmsProvider,
			options:      Options{},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client)
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID)
				kf.EXPECT().NewMasterKey(client, mock.Anything).Return(masterKeyMock, nil)
			},
			wantErr:       false,
			expectedKeyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
		},
		{
			name:         "Error in getClient",
			keyID:        "invalid-arn",
			providerType: StrictKmsProvider,
			options:      Options{},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				// no need to set expectations as getClient will fail
			},
			wantErr:    true,
			wantErrStr: "KMS client error: InvalidRegionError",
		},
		{
			name:         "Error keyFactory NewMasterKey",
			keyID:        "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			providerType: StrictKmsProvider,
			options:      Options{},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client)
				kf.EXPECT().NewMasterKey(client, mock.Anything).Return(nil, fmt.Errorf("NewMasterKey error"))
			},
			wantErr: true,
		},
		{
			name:         "MRKAware Discovery Error in getClient",
			keyID:        "arn:aws:kms:NONE:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef",
			providerType: MrkAwareDiscoveryKmsProvider,
			options: Options{
				mrkAware:        true,
				discoveryRegion: "us-east-1",
			},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				// no need to set expectations as getClient will fail
			},
			wantErr:    true,
			wantErrStr: "KMS client error: UnknownRegionError",
		},
		{
			name:         "Discovery filter blocks keyID",
			keyID:        "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			providerType: DiscoveryKmsProvider,
			options: Options{
				discovery: true,
				discoveryFilter: &discoveryFilter{
					partition:  "aws",
					accountIDs: []string{"333355559999"},
				},
			},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				// no expectations since the discovery filter will block the keyID
			},
			wantErr:     true,
			wantErrStr:  "keyID is not allowed by discovery filter",
			wantErrType: providers.ErrFilterKeyNotAllowed,
		},
		{
			name:         "MRKAware Discovery filter blocks non-MRK keyID",
			keyID:        "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			providerType: MrkAwareDiscoveryKmsProvider,
			options: Options{
				discovery: true,
				discoveryFilter: &discoveryFilter{
					partition:  "aws",
					accountIDs: []string{"333355559999"},
				},
				mrkAware: true,
			},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				// no expectations since the discovery filter will block the keyID
			},
			wantErr:     true,
			wantErrStr:  "keyID is not allowed by discovery filter",
			wantErrType: providers.ErrFilterKeyNotAllowed,
		},
		{
			name:         "MRKAware Discovery filter allows MRK keyID",
			keyID:        "arn:aws:kms:us-west-2:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef",
			providerType: MrkAwareDiscoveryKmsProvider,
			options: Options{
				discovery: true,
				discoveryFilter: &discoveryFilter{
					partition:  "aws",
					accountIDs: []string{"123456789012"},
				},
				discoveryRegion: "us-east-1",
				mrkAware:        true,
			},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client)
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID)
				kf.EXPECT().NewMasterKey(client, mock.Anything).Return(masterKeyMock, nil)
			},
			wantErr:       false,
			expectedKeyID: "arn:aws:kms:us-east-1:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			clientFactoryMock := mocks.NewMockKMSClientFactory(t)
			keyFactoryMock := mocks.NewMockMasterKeyFactory(t)
			kmsKP := &KmsKeyProvider[model.MasterKey]{
				regionalClients: make(map[string]model.KMSClient),
				providerType:    tt.providerType,
				options:         tt.options,
			}

			tt.setupMocks(t, kmsKP, tt.expectedKeyID, clientFactoryMock, keyFactoryMock)

			kmsKP.options.clientFactory = clientFactoryMock
			kmsKP.options.keyFactory = keyFactoryMock

			key, err := kmsKP.NewMasterKey(ctx, tt.keyID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)

				assert.Equal(t, tt.expectedKeyID, key.KeyID())
			}
		})
	}
}

func TestKmsKeyProvider_AddMasterKey(t *testing.T) {
	tests := []struct {
		name         string
		keyID        string
		setupMocks   func(*testing.T, *KmsKeyProvider[model.MasterKey], string, *mocks.MockKMSClientFactory, *mocks.MockMasterKeyFactory)
		encryptIndex []string
		wantErr      bool
		wantErrStr   string
	}{
		{
			name:  "Valid keyID",
			keyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client)
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID)
				kf.EXPECT().NewMasterKey(client, mock.Anything).Return(masterKeyMock, nil)
			},
		},
		{
			name:  "Valid keyID KeyFactory Error",
			keyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client)
				kf.EXPECT().NewMasterKey(client, mock.Anything).Return(nil, assert.AnError)
			},
			wantErr: true,
		},
		{
			name:  "Invalid keyID Validation Error",
			keyID: "invalid-key-id",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				// no mock expectation as validation will fail before reaching factory
			},
			wantErr:    true,
			wantErrStr: "invalid keyID",
		},
		{
			name:  "Existing keyID",
			keyID: "arn:aws:kms:us-west-2:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef",
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				// no mock expectation as key already exists
			},
			encryptIndex: []string{
				"arn:aws:kms:us-west-2:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientFactoryMock := mocks.NewMockKMSClientFactory(t)
			keyFactoryMock := mocks.NewMockMasterKeyFactory(t)
			var primaryMasterKey *common.KeyEntry[model.MasterKey]

			keyEntriesForEncrypt := make(map[string]common.KeyEntry[model.MasterKey])
			for i, keyID := range tt.encryptIndex {
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID).Maybe()
				keyEntriesForEncrypt[keyID] = common.NewKeyEntry[model.MasterKey](masterKeyMock)
				if i == 0 {
					primaryMasterKey = common.NewKeyEntryPtr[model.MasterKey](masterKeyMock)
				}
			}

			kmsKP := &KmsKeyProvider[model.MasterKey]{
				options: Options{
					clientFactory: clientFactoryMock,
					keyFactory:    keyFactoryMock,
				},
				regionalClients:      make(map[string]model.KMSClient),
				keyEntriesForEncrypt: keyEntriesForEncrypt,
				primaryMasterKey:     primaryMasterKey,
			}

			tt.setupMocks(t, kmsKP, tt.keyID, clientFactoryMock, keyFactoryMock)

			got, err := kmsKP.AddMasterKey(tt.keyID)

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
				assert.Contains(t, kmsKP.keyEntriesForEncrypt, tt.keyID)
				if primaryMasterKey == nil {
					assert.Equal(t, tt.keyID, kmsKP.primaryMasterKey.GetEntry().KeyID())
				}
			}
		})
	}
}

func TestKmsKeyProvider_MasterKeyForDecrypt(t *testing.T) { //nolint:gocognit
	tests := []struct {
		name                string
		metadata            model.KeyMeta
		setupMocks          func(*testing.T, *KmsKeyProvider[model.MasterKey], string, *mocks.MockKeyProvider, *mocks.MockKMSClientFactory, *mocks.MockMasterKeyFactory)
		encryptIndex        []string
		decryptIndex        []string
		wantRegionalClients []string
		wantErr             bool
		wantErrStr          string
		wantErrType         error
		wantErrChain        []error
		wantKeyID           string
	}{
		{
			name:     "Valid Key Found in Encrypt index",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()
			},
			encryptIndex: []string{
				"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			},
		},
		{
			name:     "Valid Key New Master Key Created",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client).Once()
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID).Maybe()
				kf.EXPECT().NewMasterKey(client, keyID).Return(masterKeyMock, nil).Once()
			},
			wantRegionalClients: []string{"us-west-2"},
		},
		{
			name:     "Invalid Provider ID",
			metadata: model.KeyMeta{ProviderID: "invalid-provider", KeyID: "key-id"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Twice()
			},
			wantErr:     true,
			wantErrStr:  "providerID validation",
			wantErrType: providers.ErrMasterKeyProvider,
		},
		{
			name:     "Invalid Key ID",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "invalid-key-id"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()
			},
			wantErr:     true,
			wantErrStr:  "keyID validation",
			wantErrType: providers.ErrMasterKeyProviderDecryptForbidden,
			wantErrChain: []error{
				providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecryptForbidden,
			},
		},
		{
			name:     "Key not found create Master Key error",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client).Once()
				kf.EXPECT().NewMasterKey(client, keyID).Return(nil, fmt.Errorf("some error")).Once()
			},
			wantRegionalClients: []string{"us-west-2"},
			wantErr:             true,
			wantErrStr:          "NewMasterKey error",
			wantErrType:         providers.ErrMasterKeyProviderDecrypt,
			wantErrChain: []error{
				providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecrypt,
			},
		},
		{
			name:     "Valid Key Found in Decrypt index",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()
			},
			decryptIndex: []string{
				"arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
		},
		{
			name:     "Valid Key disallowed by Discovery filter",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()

				kmsKP.options.discovery = true
				kmsKP.options.discoveryFilter = &discoveryFilter{
					partition:  "aws",
					accountIDs: []string{"333355559999"},
				}
				kmsKP.providerType = DiscoveryKmsProvider
			},
			wantErr:     true,
			wantErrStr:  "NewMasterKey filter",
			wantErrType: providers.ErrFilterKeyNotAllowed,
			wantErrChain: []error{
				providers.ErrFilterKeyNotAllowed, providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecryptForbidden,
			},
		},
		{
			name:     "MRKAware Discovery filter allows MRK keyID",
			metadata: model.KeyMeta{ProviderID: "aws-kms", KeyID: "arn:aws:kms:us-west-2:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef"},
			setupMocks: func(t *testing.T, kmsKP *KmsKeyProvider[model.MasterKey], keyID string, kp *mocks.MockKeyProvider, cf *mocks.MockKMSClientFactory, kf *mocks.MockMasterKeyFactory) {
				kp.EXPECT().ID().Return("aws-kms").Once()
				client := mocks.NewMockKMSClient(t)
				cf.EXPECT().NewFromConfig(mock.Anything, mock.Anything).Return(client).Twice()
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID).Once()
				kf.EXPECT().NewMasterKey(client, keyID).Return(masterKeyMock, nil).Once()

				kmsKP.options.discovery = true
				kmsKP.options.discoveryFilter = &discoveryFilter{
					partition:  "aws",
					accountIDs: []string{"123456789012"},
				}
				kmsKP.options.discoveryRegion = "eu-central-1"
				kmsKP.options.mrkAware = true
				kmsKP.providerType = MrkAwareDiscoveryKmsProvider
			},
			// for MRK aware discovery, the regional clients will be the discovery region and the region of the keyID
			wantRegionalClients: []string{"us-west-2", "eu-central-1"},
			wantKeyID:           "arn:aws:kms:eu-central-1:123456789012:key/mrk-abcd1234-a123-456a-a12b-a123b4cd56ef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			keyProviderMock := mocks.NewMockKeyProvider(t)
			clientFactoryMock := mocks.NewMockKMSClientFactory(t)
			keyFactoryMock := mocks.NewMockMasterKeyFactory(t)

			keyEntriesForEncrypt := make(map[string]common.KeyEntry[model.MasterKey])
			for _, keyID := range tt.encryptIndex {
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID).Maybe()
				keyEntriesForEncrypt[keyID] = common.NewKeyEntry[model.MasterKey](masterKeyMock)
			}

			keyEntriesForDecrypt := make(map[string]common.KeyEntry[model.MasterKey])
			for _, keyID := range tt.decryptIndex {
				masterKeyMock := mocks.NewMockMasterKey(t)
				masterKeyMock.EXPECT().KeyID().Return(keyID).Maybe()
				keyEntriesForDecrypt[keyID] = common.NewKeyEntry[model.MasterKey](masterKeyMock)
			}

			kmsKP := &KmsKeyProvider[model.MasterKey]{
				options: Options{
					clientFactory: clientFactoryMock,
					keyFactory:    keyFactoryMock,
				},
				keyProvider:          keyProviderMock,
				keyEntriesForEncrypt: keyEntriesForEncrypt,
				keyEntriesForDecrypt: keyEntriesForDecrypt,
				regionalClients:      make(map[string]model.KMSClient),
			}

			expectedKeyID := tt.metadata.KeyID
			if tt.wantKeyID != "" {
				expectedKeyID = tt.wantKeyID
			}

			tt.setupMocks(t, kmsKP, expectedKeyID, keyProviderMock, clientFactoryMock, keyFactoryMock)

			got, err := kmsKP.MasterKeyForDecrypt(ctx, tt.metadata)

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
				assert.Nil(t, got)
				// should not have added the key to the decrypt index if it failed
				assert.Len(t, kmsKP.keyEntriesForDecrypt, len(tt.decryptIndex))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, expectedKeyID, got.KeyID())
				if structs.Contains(tt.decryptIndex, expectedKeyID) || structs.Contains(tt.encryptIndex, expectedKeyID) {
					// should not have added the key to the decrypt index if it was already there
					assert.Len(t, kmsKP.keyEntriesForDecrypt, len(tt.decryptIndex))
				} else {
					// should have added the key to the decrypt index if it was not there
					assert.Len(t, kmsKP.keyEntriesForDecrypt, len(tt.decryptIndex)+1)

					// key should be in the decrypt index
					// keyID key is always the keyID of the requested metadata in decrypt index
					// e.g. if the requested metadata keyID is MRK, the keyID in decrypt index will be the requested keyID
					// however, the actual kmsClient (with region), and master key will be the MRK keyID in the discovery region
					assert.Contains(t, kmsKP.keyEntriesForDecrypt, tt.metadata.KeyID)
				}
			}
			// should not have added the key to the encrypt index ever
			assert.Len(t, kmsKP.keyEntriesForEncrypt, len(tt.encryptIndex))

			// ensure the regional clients are as expected
			assert.Len(t, kmsKP.regionalClients, len(tt.wantRegionalClients))

			// ensure the regional clients are as expected
			// for MRK aware discovery, the regional clients will be the discovery region and the region of the keyID
			for _, r := range tt.wantRegionalClients {
				assert.Contains(t, kmsKP.regionalClients, r)
			}
		})
	}
}

func TestKmsKeyProvider_MasterKeysForEncryption(t *testing.T) {
	masterKeyMock := mocks.NewMockMasterKey(t)
	memberKeyMock1 := mocks.NewMockMasterKey(t)
	memberKeyMock2 := mocks.NewMockMasterKey(t)
	tests := []struct {
		name                 string
		primaryMasterKey     *common.KeyEntry[model.MasterKey]
		keyEntriesForEncrypt map[string]common.KeyEntry[model.MasterKey]
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
			keyEntriesForEncrypt: make(map[string]common.KeyEntry[model.MasterKey]),
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
			keyEntriesForEncrypt: make(map[string]common.KeyEntry[model.MasterKey]),
			wantPrimaryMasterKey: masterKeyMock,
			wantMemberKeys:       nil,
		},
		{
			name:             "Primary Key with Member Keys",
			primaryMasterKey: common.NewKeyEntryPtr[model.MasterKey](masterKeyMock),
			keyEntriesForEncrypt: map[string]common.KeyEntry[model.MasterKey]{
				"key1": common.NewKeyEntry[model.MasterKey](memberKeyMock1),
				"key2": common.NewKeyEntry[model.MasterKey](memberKeyMock2),
			},
			wantPrimaryMasterKey: masterKeyMock,
			wantMemberKeys:       []model.MasterKey{memberKeyMock1, memberKeyMock2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			encryptionCtx := suite.EncryptionContext{"purpose": "testing"}

			kmsKP := &KmsKeyProvider[model.MasterKey]{
				primaryMasterKey:     tt.primaryMasterKey,
				keyEntriesForEncrypt: tt.keyEntriesForEncrypt,
			}

			primary, members, err := kmsKP.MasterKeysForEncryption(ctx, encryptionCtx)

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
