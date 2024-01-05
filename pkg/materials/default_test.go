// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials_test

import (
	"context"
	"crypto/ecdsa"
	randpkg "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

type mockProvider struct {
	model.MasterKeyProvider
	ID   string
	Kind types.ProviderKind
}

func (mock *mockProvider) ProviderID() string {
	return mock.ID
}

func (mock *mockProvider) ProviderKind() types.ProviderKind {
	return mock.Kind
}

type errorReader struct{}

func (r errorReader) Read(_ []byte) (n int, err error) {
	return 0, fmt.Errorf("test error")
}

func TestNewDefault(t *testing.T) {
	tests := []struct {
		name    string
		primary model.MasterKeyProvider
		extra   []model.MasterKeyProvider
		wantErr error
	}{
		{
			name:    "Test with nil primary provider",
			primary: nil,
			extra:   nil,
			wantErr: materials.ErrCMM,
		},
		{
			name:    "Test with nil primary provider and extra providers",
			primary: nil,
			extra:   []model.MasterKeyProvider{&mockProvider{ID: "provider2", Kind: types.Raw}},
			wantErr: materials.ErrCMM,
		},
		{
			name:    "Test with nil extra providers",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra:   nil,
			wantErr: nil,
		},
		{
			name:    "Test with no extra providers",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra:   []model.MasterKeyProvider{},
			wantErr: nil,
		},
		{
			name:    "Test with extra providers with no duplicates",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra: []model.MasterKeyProvider{
				&mockProvider{ID: "provider2", Kind: types.Raw},
				&mockProvider{ID: "provider3", Kind: types.AwsKms},
			},
			wantErr: nil,
		},
		{
			name:    "Test with extra Raw type providers having same ID",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra: []model.MasterKeyProvider{
				&mockProvider{ID: "provider2", Kind: types.Raw},
				&mockProvider{ID: "provider2", Kind: types.Raw},
			},
			wantErr: materials.ErrCMM,
		},
		{
			name:    "Test with primary and extra Raw type providers having same ID",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra: []model.MasterKeyProvider{
				&mockProvider{ID: "provider1", Kind: types.Raw},
				&mockProvider{ID: "provider2", Kind: types.AwsKms},
			},
			wantErr: materials.ErrCMM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := materials.NewDefault(tt.primary, tt.extra...)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestDefaultCryptoMaterialsManager_GetInstance(t *testing.T) {
	type fields struct {
		primary model.MasterKeyProvider
		extra   []model.MasterKeyProvider
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Test with no extra providers",
			fields: fields{
				primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
				extra:   nil,
			},
		},
		{
			name: "Test with extra provider",
			fields: fields{
				primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
				extra: []model.MasterKeyProvider{
					&mockProvider{ID: "provider2", Kind: types.Raw},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm, err := materials.NewDefault(tt.fields.primary, tt.fields.extra...)
			assert.NoError(t, err)
			assert.NotNil(t, dm)
			assert.Equal(t, dm, dm.GetInstance())
			assert.EqualValues(t, dm, dm.GetInstance())
			assert.NotSame(t, dm, dm.GetInstance())
		})
	}
}

func TestDefaultCryptoMaterialsManager_GetEncryptionMaterials(t *testing.T) {
	type masterKeyData struct {
		KeyMeta model.KeyMeta
		dk      model.DataKeyI
		edk     model.EncryptedDataKeyI
	}
	type prov struct {
		ID                   string
		Kind                 types.ProviderKind
		primaryMasterKeyData masterKeyData
		memberMasterKeyData  []masterKeyData
	}
	type mockConfig struct {
		primary prov
		extra   []prov
	}

	// provider 1 mock data
	mockKeyMetaProv1Key1 := model.WithKeyMeta("provider1", "key1")
	mockKeyMetaProv1Key2 := model.WithKeyMeta("provider1", "key2")

	mockDataKeyProv1Key1 := model.NewDataKey(mockKeyMetaProv1Key1, []byte("dataKey1"), []byte("encryptedDataKey1"))
	mockDataKeyProv1Key2 := model.NewDataKey(mockKeyMetaProv1Key2, []byte("dataKey2"), []byte("encryptedDataKey2"))

	mockEDKProv1Key1 := model.NewEncryptedDataKey(mockKeyMetaProv1Key1, mockDataKeyProv1Key1.EncryptedDataKey())
	mockEDKProv1Key2 := model.NewEncryptedDataKey(mockKeyMetaProv1Key2, mockDataKeyProv1Key2.EncryptedDataKey())

	// provider 2 mock data
	mockKeyMetaProv2Key5 := model.WithKeyMeta("provider2", "key5")
	mockKeyMetaProv2Key6 := model.WithKeyMeta("provider2", "key6")

	mockDataKeyProv2Key5 := model.NewDataKey(mockKeyMetaProv2Key5, []byte("dataKey5"), []byte("encryptedDataKey5"))
	mockDataKeyProv2Key6 := model.NewDataKey(mockKeyMetaProv2Key6, []byte("dataKey6"), []byte("encryptedDataKey6"))

	mockEDKProv2Key5 := model.NewEncryptedDataKey(mockKeyMetaProv2Key5, mockDataKeyProv2Key5.EncryptedDataKey())
	mockEDKProv2Key6 := model.NewEncryptedDataKey(mockKeyMetaProv2Key6, mockDataKeyProv2Key6.EncryptedDataKey())
	tests := []struct {
		name        string
		setupMocks  func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider)
		conf        mockConfig
		req         model.EncryptionMaterialsRequest
		want        model.EncryptionMaterial
		wantErr     bool
		wantRandErr bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Primary no extra providers non-signing algorithm",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// Primary MasterKeyProvider MasterKey
				primaryMasterKey := mocks.NewMockMasterKey(t)
				primaryMasterKey.EXPECT().Metadata().Return(c.primary.primaryMasterKeyData.KeyMeta).
					Times(len(c.primary.memberMasterKeyData))
				primaryMasterKey.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.primaryMasterKeyData.dk, nil).
					Once()

				// Primary MasterKeyProvider Member MasterKeys
				primaryMemberKeys := make([]model.MasterKey, 0, len(c.primary.memberMasterKeyData))
				for _, mk := range c.primary.memberMasterKeyData {
					primaryMemberKey := mocks.NewMockMasterKey(t)
					primaryMemberKey.EXPECT().Metadata().Return(mk.KeyMeta).Once()
					if mk.KeyMeta.KeyID != c.primary.primaryMasterKeyData.KeyMeta.KeyID {
						// because the only primaryMasterKey calls GenerateDataKey
						// and other memberMasterKeys use EncryptDataKey
						primaryMemberKey.EXPECT().EncryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(mk.edk, nil).Once()
					}
					primaryMemberKeys = append(primaryMemberKeys, primaryMemberKey)
				}

				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(primaryMasterKey, primaryMemberKeys, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
					memberMasterKeyData: []masterKeyData{
						{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
						{KeyMeta: mockKeyMetaProv1Key2, dk: mockDataKeyProv1Key2, edk: mockEDKProv1Key2},
					},
				},
				extra: nil,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
					mockEDKProv1Key2,
				},
				suite.EncryptionContext{"purpose": "test"},
				nil,
			),
			wantErr: false,
		},
		{
			name: "ECDSA GenerateKey error with signing algorithm",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// no expectations here because ECDSA error expected
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{},
					memberMasterKeyData:  nil,
				},
				extra: nil,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want:        nil,
			wantErr:     true,
			wantRandErr: true,
			wantErrStr:  "ECDSA key error",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary key provider MasterKeysForEncryption error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(nil, nil, fmt.Errorf("test error")).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{},
					memberMasterKeyData:  nil,
				},
				extra: nil,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "primary KeyProvider error",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary key GenerateDataKey error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// Primary MasterKeyProvider MasterKey
				primaryMasterKey := mocks.NewMockMasterKey(t)
				primaryMasterKey.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("generate data key")).
					Once()

				// Primary MasterKeyProvider Member MasterKeys
				primaryMemberKeys := make([]model.MasterKey, 0, len(c.primary.memberMasterKeyData))
				for range c.primary.memberMasterKeyData {
					primaryMemberKey := mocks.NewMockMasterKey(t)
					primaryMemberKeys = append(primaryMemberKeys, primaryMemberKey)
				}

				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(primaryMasterKey, primaryMemberKeys, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
					memberMasterKeyData: []masterKeyData{
						{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
						{KeyMeta: mockKeyMetaProv1Key2, dk: mockDataKeyProv1Key2, edk: mockEDKProv1Key2},
					},
				},
				extra: nil,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "key error: CMM error\ngenerate data key",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary member key EncryptDataKey error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// Primary MasterKeyProvider MasterKey
				primaryMasterKey := mocks.NewMockMasterKey(t)
				primaryMasterKey.EXPECT().Metadata().Return(c.primary.primaryMasterKeyData.KeyMeta).
					Times(len(c.primary.memberMasterKeyData))
				primaryMasterKey.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.primaryMasterKeyData.dk, nil).
					Once()

				// Primary MasterKeyProvider Member MasterKeys
				primaryMemberKeys := make([]model.MasterKey, 0, len(c.primary.memberMasterKeyData))
				for _, mk := range c.primary.memberMasterKeyData {
					primaryMemberKey := mocks.NewMockMasterKey(t)
					primaryMemberKey.EXPECT().Metadata().Return(mk.KeyMeta).Once()
					if mk.KeyMeta.KeyID != c.primary.primaryMasterKeyData.KeyMeta.KeyID {
						// because the only primaryMasterKey calls GenerateDataKey
						// and other memberMasterKeys use EncryptDataKey
						primaryMemberKey.EXPECT().EncryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(nil, fmt.Errorf("encrypt data key")).Once()
					}
					primaryMemberKeys = append(primaryMemberKeys, primaryMemberKey)
				}

				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(primaryMasterKey, primaryMemberKeys, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
					memberMasterKeyData: []masterKeyData{
						{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
						{KeyMeta: mockKeyMetaProv1Key2, dk: mockDataKeyProv1Key2, edk: mockEDKProv1Key2},
					},
				},
				extra: nil,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "key error: CMM error\nencrypt data key",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary with extra providers",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// Primary MasterKeyProvider MasterKey
				primaryMasterKey := mocks.NewMockMasterKey(t)

				primaryMasterKey.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.primaryMasterKeyData.dk, nil).
					Once()

				// Primary MasterKeyProvider Member MasterKeys
				primaryMemberKeys := make([]model.MasterKey, 0, len(c.primary.memberMasterKeyData))
				for _, mk := range c.primary.memberMasterKeyData {
					primaryMemberKey := mocks.NewMockMasterKey(t)
					primaryMemberKey.EXPECT().Metadata().Return(mk.KeyMeta).Once()
					if mk.KeyMeta.KeyID != c.primary.primaryMasterKeyData.KeyMeta.KeyID {
						// because the only primaryMasterKey calls GenerateDataKey
						// and other memberMasterKeys use EncryptDataKey
						primaryMemberKey.EXPECT().EncryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(mk.edk, nil).Once()
					}
					primaryMemberKeys = append(primaryMemberKeys, primaryMemberKey)
				}

				// Extra MasterKeyProviders
				totalExtraMemberKeys := 0
				for i, mkp := range extra {
					// Extra primary MasterKeyProvider MasterKey
					extraPrimaryMasterKey := mocks.NewMockMasterKey(t)

					extraProv := c.extra[i]
					extraMemberKeys := make([]model.MasterKey, 0, len(extraProv.memberMasterKeyData))
					for _, mk := range extraProv.memberMasterKeyData {
						extraMemberKey := mocks.NewMockMasterKey(t)
						extraMemberKey.EXPECT().Metadata().Return(mk.KeyMeta).Once()
						extraMemberKey.EXPECT().EncryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(mk.edk, nil).Once()
						extraMemberKeys = append(extraMemberKeys, extraMemberKey)
						totalExtraMemberKeys++
					}

					mkp.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
						Return(extraPrimaryMasterKey, extraMemberKeys, nil).Once()
				}

				primaryMasterKey.EXPECT().Metadata().Return(c.primary.primaryMasterKeyData.KeyMeta).
					Times(len(c.primary.memberMasterKeyData) + totalExtraMemberKeys)

				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(primaryMasterKey, primaryMemberKeys, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
					memberMasterKeyData: []masterKeyData{
						{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
						{KeyMeta: mockKeyMetaProv1Key2, dk: mockDataKeyProv1Key2, edk: mockEDKProv1Key2},
					},
				},
				extra: []prov{
					{ID: "provider2", Kind: types.AwsKms,
						primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv2Key5, dk: mockDataKeyProv2Key5, edk: mockEDKProv2Key5},
						memberMasterKeyData: []masterKeyData{
							{KeyMeta: mockKeyMetaProv2Key5, dk: mockDataKeyProv2Key5, edk: mockEDKProv2Key5},
							{KeyMeta: mockKeyMetaProv2Key6, dk: mockDataKeyProv2Key6, edk: mockEDKProv2Key6},
						},
					},
				},
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
					mockEDKProv1Key2,
					mockEDKProv2Key5,
					mockEDKProv2Key6,
				},
				suite.EncryptionContext{"purpose": "test", "department": "it"},
				&ecdsa.PrivateKey{},
			),
			wantErr: false,
		},
		{
			name: "Primary with skipping no primary key error from extra provider",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// Primary MasterKeyProvider MasterKey
				primaryMasterKey := mocks.NewMockMasterKey(t)

				primaryMasterKey.EXPECT().GenerateDataKey(mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.primaryMasterKeyData.dk, nil).
					Once()

				// Primary MasterKeyProvider Member MasterKeys
				primaryMemberKeys := make([]model.MasterKey, 0, len(c.primary.memberMasterKeyData))
				for _, mk := range c.primary.memberMasterKeyData {
					primaryMemberKey := mocks.NewMockMasterKey(t)
					primaryMemberKey.EXPECT().Metadata().Return(mk.KeyMeta).Once()
					if mk.KeyMeta.KeyID != c.primary.primaryMasterKeyData.KeyMeta.KeyID {
						// because the only primaryMasterKey calls GenerateDataKey
						// and other memberMasterKeys use EncryptDataKey
						primaryMemberKey.EXPECT().EncryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(mk.edk, nil).Once()
					}
					primaryMemberKeys = append(primaryMemberKeys, primaryMemberKey)
				}

				// Extra MasterKeyProviders
				totalExtraMemberKeys := 0
				for i, mkp := range extra {

					extraProv := c.extra[i]
					extraMemberKeys := make([]model.MasterKey, 0, len(extraProv.memberMasterKeyData))
					for _, mk := range extraProv.memberMasterKeyData {
						extraMemberKey := mocks.NewMockMasterKey(t)
						extraMemberKey.EXPECT().Metadata().Return(mk.KeyMeta).Once()
						extraMemberKey.EXPECT().EncryptDataKey(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
							Return(mk.edk, nil).Once()
						extraMemberKeys = append(extraMemberKeys, extraMemberKey)
						totalExtraMemberKeys++
					}

					mkp.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
						Return(nil, extraMemberKeys, providers.ErrMasterKeyProviderNoPrimaryKey).Once()
				}

				primaryMasterKey.EXPECT().Metadata().Return(c.primary.primaryMasterKeyData.KeyMeta).
					Times(len(c.primary.memberMasterKeyData) + totalExtraMemberKeys)

				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(primaryMasterKey, primaryMemberKeys, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
					memberMasterKeyData: []masterKeyData{
						{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
						{KeyMeta: mockKeyMetaProv1Key2, dk: mockDataKeyProv1Key2, edk: mockEDKProv1Key2},
					},
				},
				extra: []prov{
					{ID: "provider2", Kind: types.AwsKms,
						primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv2Key5, dk: mockDataKeyProv2Key5, edk: mockEDKProv2Key5},
						memberMasterKeyData: []masterKeyData{
							{KeyMeta: mockKeyMetaProv2Key5, dk: mockDataKeyProv2Key5, edk: mockEDKProv2Key5},
							{KeyMeta: mockKeyMetaProv2Key6, dk: mockDataKeyProv2Key6, edk: mockEDKProv2Key6},
						},
					},
				},
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
					mockEDKProv1Key2,
					mockEDKProv2Key5,
					mockEDKProv2Key6,
				},
				suite.EncryptionContext{"purpose": "test", "department": "it"},
				&ecdsa.PrivateKey{},
			),
			wantErr: false,
		},
		{
			name: "Primary with error from extra member provider",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				// Primary MasterKeyProvider MasterKey
				primaryMasterKey := mocks.NewMockMasterKey(t)

				// Primary MasterKeyProvider Member MasterKeys
				primaryMemberKeys := make([]model.MasterKey, 0, len(c.primary.memberMasterKeyData))
				for range c.primary.memberMasterKeyData {
					primaryMemberKey := mocks.NewMockMasterKey(t)
					primaryMemberKeys = append(primaryMemberKeys, primaryMemberKey)
				}

				// Extra MasterKeyProviders
				for _, mkp := range extra {
					mkp.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
						Return(nil, nil, fmt.Errorf("test error")).Once()
				}

				primary.EXPECT().MasterKeysForEncryption(mock.Anything, mock.Anything).
					Return(primaryMasterKey, primaryMemberKeys, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms,
					primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
					memberMasterKeyData: []masterKeyData{
						{KeyMeta: mockKeyMetaProv1Key1, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
						{KeyMeta: mockKeyMetaProv1Key2, dk: mockDataKeyProv1Key2, edk: mockEDKProv1Key2},
					},
				},
				extra: []prov{
					{ID: "provider2", Kind: types.AwsKms,
						primaryMasterKeyData: masterKeyData{KeyMeta: mockKeyMetaProv2Key5, dk: mockDataKeyProv2Key5, edk: mockEDKProv2Key5},
						memberMasterKeyData: []masterKeyData{
							{KeyMeta: mockKeyMetaProv2Key5, dk: mockDataKeyProv2Key5, edk: mockEDKProv2Key5},
							{KeyMeta: mockKeyMetaProv2Key6, dk: mockDataKeyProv2Key6, edk: mockEDKProv2Key6},
						},
					},
				},
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "member KeyProvider error",
			wantErrType: materials.ErrCMM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.wantRandErr {
				defer func() {
					rand.Reader = randpkg.Reader
				}()
				rand.Reader = errorReader{}
			}

			ctx := context.Background()

			// Primary MasterKeyProvider
			primaryMock := mocks.NewMockMasterKeyProvider(t)

			if len(tt.conf.extra) > 0 {
				primaryMock.EXPECT().ProviderID().Return(tt.conf.primary.ID).Once()
			}

			extraMocks := make([]*mocks.MockMasterKeyProvider, 0, len(tt.conf.extra))
			for _, conf := range tt.conf.extra {
				extraProviderMock := mocks.NewMockMasterKeyProvider(t)
				extraProviderMock.EXPECT().ProviderID().Return(conf.ID).Once()
				extraProviderMock.EXPECT().ProviderKind().Return(conf.Kind).Once()
				extraMocks = append(extraMocks, extraProviderMock)
			}

			tt.setupMocks(t, tt.conf, primaryMock, extraMocks)

			extraProviders := make([]model.MasterKeyProvider, 0, len(extraMocks))
			for _, mkp := range extraMocks {
				extraProviders = append(extraProviders, mkp)
			}

			dm, errCMM := materials.NewDefault(primaryMock, extraProviders...)
			assert.NoError(t, errCMM)
			got, err := dm.GetEncryptionMaterials(ctx, tt.req)
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
				assert.Equal(t, tt.want.DataEncryptionKey(), got.DataEncryptionKey())
				assert.Equal(t, tt.want.EncryptedDataKeys(), got.EncryptedDataKeys())
				if tt.req.Algorithm.IsSigning() {
					assert.NotNil(t, got.SigningKey())
					assert.Contains(t, got.EncryptionContext(), materials.EcPublicKeyField)
				} else {
					assert.Equal(t, tt.want.SigningKey(), got.SigningKey())
					assert.NotContains(t, got.EncryptionContext(), materials.EcPublicKeyField)
					assert.Equal(t, tt.want.EncryptionContext(), got.EncryptionContext())
				}
			}
		})
	}
}

func TestDefaultCryptoMaterialsManager_DecryptMaterials(t *testing.T) {
	type prov struct {
		ID   string
		Kind types.ProviderKind
		dk   model.DataKeyI
	}
	type mockConfig struct {
		primary prov
		extra   []prov
	}

	// provider 1 mock data
	mockKeyMetaProv1Key1 := model.WithKeyMeta("provider1", "key1")
	mockKeyMetaProv1Key2 := model.WithKeyMeta("provider1", "key2")

	mockDataKeyProv1Key1 := model.NewDataKey(mockKeyMetaProv1Key1, []byte("dataKey1"), []byte("encryptedDataKey1"))
	mockDataKeyProv1Key2 := model.NewDataKey(mockKeyMetaProv1Key2, []byte("dataKey2"), []byte("encryptedDataKey2"))

	mockEDKProv1Key1 := model.NewEncryptedDataKey(mockKeyMetaProv1Key1, mockDataKeyProv1Key1.EncryptedDataKey())
	mockEDKProv1Key2 := model.NewEncryptedDataKey(mockKeyMetaProv1Key2, mockDataKeyProv1Key2.EncryptedDataKey())

	// provider 2 mock data
	mockKeyMetaProv2Key5 := model.WithKeyMeta("provider2", "key5")
	mockDataKeyProv2Key5 := model.NewDataKey(mockKeyMetaProv2Key5, []byte("dataKey5"), []byte("encryptedDataKey5"))
	mockEDKProv2Key5 := model.NewEncryptedDataKey(mockKeyMetaProv2Key5, mockDataKeyProv2Key5.EncryptedDataKey())

	mockVerificationKey64 := "A34gtM6+iGkyC/hSGoavmhXrKAs1jlUdlwKyCHkzt9hw4NTrQOkq/WbezgBdz6JDyw=="
	mockVerificationKey := []byte{0x3, 0x7e, 0x20, 0xb4, 0xce, 0xbe, 0x88, 0x69, 0x32, 0xb, 0xf8, 0x52, 0x1a, 0x86, 0xaf, 0x9a, 0x15, 0xeb, 0x28, 0xb, 0x35, 0x8e, 0x55, 0x1d, 0x97, 0x2, 0xb2, 0x8, 0x79, 0x33, 0xb7, 0xd8, 0x70, 0xe0, 0xd4, 0xeb, 0x40, 0xe9, 0x2a, 0xfd, 0x66, 0xde, 0xce, 0x0, 0x5d, 0xcf, 0xa2, 0x43, 0xcb}

	tests := []struct {
		name        string
		setupMocks  func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider)
		conf        mockConfig
		req         model.DecryptionMaterialsRequest
		want        model.DecryptionMaterial
		wantErr     bool
		wantRandErr bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Primary no extra providers non-signing algorithm",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.dk, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra:   nil,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:    model.NewDecryptionMaterials(mockDataKeyProv1Key1, nil),
			wantErr: false,
		},
		{
			name: "Primary unacceptable error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("test error")).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra:   nil,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "primary KeyProvider error",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary nil dataKey without error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra:   nil,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "no data key:",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary decrypt error and extra succeed",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, providers.ErrMasterKeyProviderDecrypt).Once()

				for i, mkp := range extra {
					mkp.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return(c.extra[i].dk, nil).Once()
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra: []prov{
					{ID: "provider2", Kind: types.AwsKms, dk: mockDataKeyProv2Key5},
				},
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv2Key5},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:    model.NewDecryptionMaterials(mockDataKeyProv2Key5, nil),
			wantErr: false,
		},
		{
			name: "Primary decrypt error and extra decrypt error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, providers.ErrMasterKeyProviderDecrypt).Once()

				for _, mkp := range extra {
					mkp.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return(nil, providers.ErrMasterKeyProviderDecrypt).Once()
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra: []prov{
					{ID: "provider2", Kind: types.AwsKms, dk: mockDataKeyProv2Key5},
				},
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv2Key5},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "no data key, last error:",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary decrypt error and extra unacceptable error",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, providers.ErrMasterKeyProviderDecrypt).Once()

				for _, mkp := range extra {
					mkp.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
						Return(nil, fmt.Errorf("test error")).Once()
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra: []prov{
					{ID: "provider2", Kind: types.AwsKms, dk: mockDataKeyProv2Key5},
				},
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv2Key5},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "member KeyProvider error:",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Primary no extra providers signing algorithm",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.dk, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra:   nil,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{
					"purpose":               "test",
					"aws-crypto-public-key": mockVerificationKey64,
				},
			},
			want:    model.NewDecryptionMaterials(mockDataKeyProv1Key1, mockVerificationKey),
			wantErr: false,
		},
		{
			name: "Missing context key with signing algorithm",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.dk, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra:   nil,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "missing aws-crypto-public-key in encryption context:",
			wantErrType: materials.ErrCMM,
		},
		{
			name: "Invalid context key value with signing algorithm",
			setupMocks: func(t *testing.T, c mockConfig, primary *mocks.MockMasterKeyProvider, extra []*mocks.MockMasterKeyProvider) {
				primary.EXPECT().DecryptDataKeyFromList(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(c.primary.dk, nil).Once()
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				extra:   nil,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{
					"purpose":               "test",
					"aws-crypto-public-key": "YWJjZA=====",
				},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "ECDSA key error: CMM error\nillegal base64",
			wantErrType: materials.ErrCMM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Primary MasterKeyProvider
			primaryMock := mocks.NewMockMasterKeyProvider(t)

			if len(tt.conf.extra) > 0 {
				primaryMock.EXPECT().ProviderID().Return(tt.conf.primary.ID).Once()
			}

			extraMocks := make([]*mocks.MockMasterKeyProvider, 0, len(tt.conf.extra))
			for _, conf := range tt.conf.extra {
				extraProviderMock := mocks.NewMockMasterKeyProvider(t)
				extraProviderMock.EXPECT().ProviderID().Return(conf.ID).Once()
				extraProviderMock.EXPECT().ProviderKind().Return(conf.Kind).Once()
				extraMocks = append(extraMocks, extraProviderMock)
			}

			tt.setupMocks(t, tt.conf, primaryMock, extraMocks)

			extraProviders := make([]model.MasterKeyProvider, 0, len(extraMocks))
			for _, mkp := range extraMocks {
				extraProviders = append(extraProviders, mkp)
			}

			dm, errCMM := materials.NewDefault(primaryMock, extraProviders...)
			assert.NoError(t, errCMM)
			got, err := dm.DecryptMaterials(ctx, tt.req)
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
				assert.Equal(t, tt.want.DataKey(), got.DataKey())
				assert.Equal(t, tt.want.VerificationKey(), got.VerificationKey())
			}
		})
	}
}
