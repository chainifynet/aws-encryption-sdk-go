// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewCaching(t *testing.T) {
	tests := []struct {
		name    string
		c       model.Cache
		primary model.MasterKeyProvider
		opts    []materials.CachingOptionFunc
		wantErr error
	}{
		{
			name:    "Test with nil primary provider",
			c:       mocks.NewMockCache(t),
			primary: nil,
			opts:    nil,
			wantErr: materials.ErrInvalidConfig,
		},
		{
			name:    "Test with nil primary provider and extra providers",
			c:       mocks.NewMockCache(t),
			primary: nil,
			opts: []materials.CachingOptionFunc{
				materials.WithAdditionalProviders(&mockProvider{ID: "provider2", Kind: types.Raw}),
			},
			wantErr: materials.ErrInvalidConfig,
		},
		{
			name:    "Test with nil extra providers",
			c:       mocks.NewMockCache(t),
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			opts:    nil,
			wantErr: nil,
		},
		{
			name:    "Test with extra Raw type providers having same ID",
			c:       mocks.NewMockCache(t),
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			opts: []materials.CachingOptionFunc{
				materials.WithAdditionalProviders(
					&mockProvider{ID: "provider2", Kind: types.Raw},
					&mockProvider{ID: "provider2", Kind: types.Raw}),
			},
			wantErr: materials.ErrCMM,
		},
		{
			name:    "Test cache config error",
			c:       mocks.NewMockCache(t),
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			opts: []materials.CachingOptionFunc{
				materials.WithMaxMessages(0),
			},
			wantErr: materials.ErrInvalidConfig,
		},
		{
			name:    "Test WithMaterialsManager and primary provider",
			c:       mocks.NewMockCache(t),
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			opts: []materials.CachingOptionFunc{
				materials.WithMaterialsManager(mocks.NewMockCryptoMaterialsManager(t)),
			},
			wantErr: nil,
		},
		{
			name:    "Test WithMaterialsManager and primary nil",
			c:       mocks.NewMockCache(t),
			primary: nil,
			opts: []materials.CachingOptionFunc{
				materials.WithMaterialsManager(mocks.NewMockCryptoMaterialsManager(t)),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := materials.NewCaching(tt.c, tt.primary, tt.opts...)
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

func TestCachingCryptoMaterialsManager_GetInstance(t *testing.T) {
	type fields struct {
		primary model.MasterKeyProvider
		opts    []materials.CachingOptionFunc
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Test with no extra providers",
			fields: fields{
				primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			},
		},
		{
			name: "Test with extra provider",
			fields: fields{
				primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
				opts: []materials.CachingOptionFunc{
					materials.WithAdditionalProviders(
						&mockProvider{ID: "provider2", Kind: types.Raw},
						&mockProvider{ID: "provider3", Kind: types.Raw}),
				},
			},
		},
		{
			name: "Test with extra providers and CryptoMaterialsManager",
			fields: fields{
				primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
				opts: []materials.CachingOptionFunc{
					materials.WithAdditionalProviders(
						&mockProvider{ID: "provider2", Kind: types.Raw},
						&mockProvider{ID: "provider3", Kind: types.Raw}),
					materials.WithMaterialsManager(mocks.NewMockCryptoMaterialsManager(t)),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCache := mocks.NewMockCache(t)
			dm, err := materials.NewCaching(mockCache, tt.fields.primary, tt.fields.opts...)
			assert.NoError(t, err)
			assert.NotNil(t, dm)
			assert.Equal(t, dm, dm.GetInstance())
			assert.EqualValues(t, dm, dm.GetInstance())
			assert.NotSame(t, dm, dm.GetInstance())
		})
	}
}

func TestCachingCryptoMaterialsManager_GetEncryptionMaterials(t *testing.T) {
	type prov struct {
		ID   string
		Kind types.ProviderKind
		dk   model.DataKeyI
		edk  model.EncryptedDataKeyI
	}
	type mockConfig struct {
		primary prov
		times   int
	}

	// provider 1 mock data
	mockKeyMetaProv1Key1 := model.WithKeyMeta("provider1", "key1")
	mockDataKeyProv1Key1 := model.NewDataKey(mockKeyMetaProv1Key1, []byte("dataKey1"), []byte("encryptedDataKey1"))
	mockEDKProv1Key1 := model.NewEncryptedDataKey(mockKeyMetaProv1Key1, mockDataKeyProv1Key1.EncryptedDataKey())

	cacheKey1 := "cacheKey1"

	type setupParams struct {
		t          *testing.T
		mc         mockConfig
		c          *mocks.MockCache
		defaultCMM *mocks.MockCryptoMaterialsManager
		keyHasher  *mocks.MockCacheHasher
		opts       *[]materials.CachingOptionFunc
		req        model.EncryptionMaterialsRequest
	}

	tests := []struct {
		name        string
		setupMocks  func(*setupParams)
		conf        mockConfig
		req         model.EncryptionMaterialsRequest
		want        model.EncryptionMaterial
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Cache miss and cache hit",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return(cacheKey1).Times(p.mc.times)

				// cache miss
				p.c.EXPECT().GetEncryptionEntry(cacheKey1, p.req.PlaintextLength).Return(nil, false).Times(1)

				encMaterials := mocks.NewMockEncryptionMaterial(t)
				encMaterials.EXPECT().DataEncryptionKey().Return(p.mc.primary.dk).Times(p.mc.times)
				encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{p.mc.primary.edk}).Times(p.mc.times)
				encMaterials.EXPECT().EncryptionContext().Return(p.req.EncryptionContext).Times(p.mc.times)

				if p.req.Algorithm.IsSigning() {
					encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Times(p.mc.times)
				} else {
					encMaterials.EXPECT().SigningKey().Return(nil).Times(p.mc.times)
				}

				p.defaultCMM.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(encMaterials, nil).Once()

				entry := mocks.NewMockCacheEntry(t)
				entry.EXPECT().Value().Return(encMaterials).Times(p.mc.times)

				p.c.EXPECT().PutEncryptionEntry(cacheKey1, encMaterials, p.req.PlaintextLength, mock.Anything).
					Return(entry).Once()

				// cache hit for times minus 1
				if p.mc.times > 1 {
					timesCacheGet := p.mc.times - 1
					p.c.EXPECT().GetEncryptionEntry(cacheKey1, p.req.PlaintextLength).Return(entry, true).Times(timesCacheGet)

					// cache entry is not too old, 2 seconds age
					entry.EXPECT().Age().Return(time.Since(time.Now().Add(-2 * time.Second)).Seconds()).Times(timesCacheGet)
					entry.EXPECT().Messages().Return(1).Times(timesCacheGet)
					entry.EXPECT().Bytes().Return(1).Times(timesCacheGet)
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
				times:   10,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
				PlaintextLength:   100,
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
				},
				suite.EncryptionContext{"purpose": "test", "department": "it"},
				nil,
			),
			wantErr: false,
		},
		{
			name: "Cache miss hit invalidate put and return",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
					materials.WithMaxMessages(1),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return(cacheKey1).Times(p.mc.times)

				// cache miss
				p.c.EXPECT().GetEncryptionEntry(cacheKey1, p.req.PlaintextLength).Return(nil, false).Times(1)

				encMaterials := mocks.NewMockEncryptionMaterial(t)
				encMaterials.EXPECT().DataEncryptionKey().Return(p.mc.primary.dk).Times(p.mc.times)
				encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{p.mc.primary.edk}).Times(p.mc.times)
				encMaterials.EXPECT().EncryptionContext().Return(p.req.EncryptionContext).Times(p.mc.times)

				if p.req.Algorithm.IsSigning() {
					encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Times(p.mc.times)
				} else {
					encMaterials.EXPECT().SigningKey().Return(nil).Times(p.mc.times)
				}

				p.defaultCMM.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(encMaterials, nil).Times(p.mc.times)

				entry := mocks.NewMockCacheEntry(t)
				entry.EXPECT().Value().Return(encMaterials).Times(p.mc.times)

				p.c.EXPECT().PutEncryptionEntry(cacheKey1, encMaterials, p.req.PlaintextLength, mock.Anything).
					Return(entry).Times(p.mc.times)

				// cache hit for times minus 1
				if p.mc.times > 1 {
					timesCacheGet := p.mc.times - 1
					p.c.EXPECT().GetEncryptionEntry(cacheKey1, p.req.PlaintextLength).Return(entry, true).Times(timesCacheGet)

					// cache entry is not too old, 2 seconds age
					entry.EXPECT().Age().Return(time.Since(time.Now().Add(-2 * time.Second)).Seconds()).Times(timesCacheGet)
					entry.EXPECT().Messages().Return(2).Times(timesCacheGet)
					entry.EXPECT().Bytes().Return(1).Times(timesCacheGet)

					entry.EXPECT().Invalidate().Times(timesCacheGet)
					p.c.EXPECT().DeleteEntry(cacheKey1).Return(true).Times(timesCacheGet)
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
				times:   10,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
				PlaintextLength:   100,
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
				},
				suite.EncryptionContext{"purpose": "test", "department": "it"},
				&ecdsa.PrivateKey{},
			),
			wantErr: false,
		},
		{
			name: "Should not cache if plaintext zero",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
				)

				encMaterials := mocks.NewMockEncryptionMaterial(t)
				encMaterials.EXPECT().DataEncryptionKey().Return(p.mc.primary.dk).Times(p.mc.times)
				encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{p.mc.primary.edk}).Times(p.mc.times)
				encMaterials.EXPECT().EncryptionContext().Return(p.req.EncryptionContext).Times(p.mc.times)

				if p.req.Algorithm.IsSigning() {
					encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Times(p.mc.times)
				} else {
					encMaterials.EXPECT().SigningKey().Return(nil).Times(p.mc.times)
				}

				p.defaultCMM.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(encMaterials, nil).Times(p.mc.times)
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
				times:   1,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
				PlaintextLength:   0,
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
				},
				suite.EncryptionContext{"purpose": "test", "department": "it"},
				&ecdsa.PrivateKey{},
			),
			wantErr: false,
		},
		{
			name: "Large plaintext should not cache",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
					materials.WithMaxBytes(1024),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return(cacheKey1).Times(p.mc.times)

				// cache miss
				p.c.EXPECT().GetEncryptionEntry(cacheKey1, p.req.PlaintextLength).Return(nil, false).Times(p.mc.times)

				encMaterials := mocks.NewMockEncryptionMaterial(t)
				encMaterials.EXPECT().DataEncryptionKey().Return(p.mc.primary.dk).Times(p.mc.times)
				encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{p.mc.primary.edk}).Times(p.mc.times)
				encMaterials.EXPECT().EncryptionContext().Return(p.req.EncryptionContext).Times(p.mc.times)

				if p.req.Algorithm.IsSigning() {
					encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Times(p.mc.times)
				} else {
					encMaterials.EXPECT().SigningKey().Return(nil).Times(p.mc.times)
				}

				p.defaultCMM.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(encMaterials, nil).Times(p.mc.times)
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
				times:   10,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
				PlaintextLength:   2000,
			},
			want: model.NewEncryptionMaterials(
				mockDataKeyProv1Key1,
				[]model.EncryptedDataKeyI{
					mockEDKProv1Key1,
				},
				suite.EncryptionContext{"purpose": "test", "department": "it"},
				nil,
			),
			wantErr: false,
		},
		{
			name: "Cache miss error getting materials from CMM",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return(cacheKey1).Times(p.mc.times)

				// cache miss
				p.c.EXPECT().GetEncryptionEntry(cacheKey1, p.req.PlaintextLength).Return(nil, false).Times(p.mc.times)

				p.defaultCMM.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(nil, materials.ErrCMM).Times(p.mc.times)
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1, edk: mockEDKProv1Key1},
				times:   10,
			},
			req: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptionContext: suite.EncryptionContext{"purpose": "test", "department": "it"},
				PlaintextLength:   2000,
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "CMM error",
			wantErrType: materials.ErrCMM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Cache
			cacheMock := mocks.NewMockCache(t)

			// Cache Hasher
			keyHasherMock := mocks.NewMockCacheHasher(t)

			// Default CryptoMaterialsManager
			defaultCmmMock := mocks.NewMockCryptoMaterialsManager(t)

			// Primary MasterKeyProvider
			primaryMock := mocks.NewMockMasterKeyProvider(t)

			optFns := make([]materials.CachingOptionFunc, 0)

			tt.setupMocks(&setupParams{
				t:          t,
				mc:         tt.conf,
				c:          cacheMock,
				defaultCMM: defaultCmmMock,
				keyHasher:  keyHasherMock,
				opts:       &optFns,
				req:        tt.req,
			})

			dm, errCMM := materials.NewCaching(cacheMock, primaryMock, optFns...)
			assert.NoError(t, errCMM)

			for i := 0; i < tt.conf.times; i++ {
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
						assert.Equal(t, tt.want.EncryptionContext(), got.EncryptionContext())
					} else {
						assert.Equal(t, tt.want.SigningKey(), got.SigningKey())
						assert.Equal(t, tt.want.EncryptionContext(), got.EncryptionContext())
					}
				}
			}
		})
	}
}

func TestCachingCryptoMaterialsManager_DecryptMaterials(t *testing.T) {
	type prov struct {
		ID   string
		Kind types.ProviderKind
		dk   model.DataKeyI
	}
	type mockConfig struct {
		primary prov
		times   int
	}

	// provider 1 mock data
	mockKeyMetaProv1Key1 := model.WithKeyMeta("provider1", "key1")
	mockKeyMetaProv1Key2 := model.WithKeyMeta("provider1", "key2")

	mockDataKeyProv1Key1 := model.NewDataKey(mockKeyMetaProv1Key1, []byte("dataKey1"), []byte("encryptedDataKey1"))
	mockDataKeyProv1Key2 := model.NewDataKey(mockKeyMetaProv1Key2, []byte("dataKey2"), []byte("encryptedDataKey2"))

	mockEDKProv1Key1 := model.NewEncryptedDataKey(mockKeyMetaProv1Key1, mockDataKeyProv1Key1.EncryptedDataKey())
	mockEDKProv1Key2 := model.NewEncryptedDataKey(mockKeyMetaProv1Key2, mockDataKeyProv1Key2.EncryptedDataKey())

	type setupParams struct {
		t          *testing.T
		mc         mockConfig
		c          *mocks.MockCache
		defaultCMM *mocks.MockCryptoMaterialsManager
		keyHasher  *mocks.MockCacheHasher
		opts       *[]materials.CachingOptionFunc
	}

	tests := []struct {
		name        string
		setupMocks  func(*setupParams)
		conf        mockConfig
		req         model.DecryptionMaterialsRequest
		want        model.DecryptionMaterial
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Cache miss and cache hit",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return("cacheKey").Times(p.mc.times)

				p.c.EXPECT().GetDecryptionEntry("cacheKey").Return(nil, false).Times(1)

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().DataKey().Return(p.mc.primary.dk).Times(p.mc.times)
				decMaterials.EXPECT().VerificationKey().Return(nil).Times(p.mc.times)

				p.defaultCMM.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).
					Return(decMaterials, nil).Once()

				entry := mocks.NewMockCacheEntry(t)
				entry.EXPECT().Value().Return(decMaterials).Times(p.mc.times)

				p.c.EXPECT().PutDecryptionEntry("cacheKey", decMaterials, mock.Anything).
					Return(entry).Once()

				// cache hit for times minus 1
				if p.mc.times > 1 {
					timesCacheGet := p.mc.times - 1
					p.c.EXPECT().GetDecryptionEntry("cacheKey").Return(entry, true).Times(timesCacheGet)

					// cache entry is not too old, 2 seconds age
					entry.EXPECT().Age().Return(time.Since(time.Now().Add(-2 * time.Second)).Seconds()).Times(timesCacheGet)
					entry.EXPECT().Messages().Return(1).Times(timesCacheGet)
					entry.EXPECT().Bytes().Return(1).Times(timesCacheGet)
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				times:   10,
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
			name: "Cache miss hit invalidate put and return",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
					materials.WithMaxMessages(1),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return("cacheKey").Times(p.mc.times)

				p.c.EXPECT().GetDecryptionEntry("cacheKey").Return(nil, false).Times(1)

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().DataKey().Return(p.mc.primary.dk).Times(p.mc.times)
				decMaterials.EXPECT().VerificationKey().Return(nil).Times(p.mc.times)

				p.defaultCMM.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).
					Return(decMaterials, nil).Times(p.mc.times)

				entry := mocks.NewMockCacheEntry(t)
				entry.EXPECT().Value().Return(decMaterials).Times(p.mc.times)

				p.c.EXPECT().PutDecryptionEntry("cacheKey", decMaterials, mock.Anything).
					Return(entry).Times(p.mc.times)

				// cache hit for times minus 1
				if p.mc.times > 1 {
					timesCacheGet := p.mc.times - 1
					p.c.EXPECT().GetDecryptionEntry("cacheKey").Return(entry, true).Times(timesCacheGet)

					// cache entry is not too old, 2 seconds age
					entry.EXPECT().Age().Return(time.Since(time.Now().Add(-2 * time.Second)).Seconds()).Times(timesCacheGet)
					entry.EXPECT().Messages().Return(2).Times(timesCacheGet)
					entry.EXPECT().Bytes().Return(1).Times(timesCacheGet)

					entry.EXPECT().Invalidate().Times(timesCacheGet)
					p.c.EXPECT().DeleteEntry("cacheKey").Return(true).Times(timesCacheGet)
				}
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				times:   8,
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
			name: "Cache miss error on decrypt from CMM",
			setupMocks: func(p *setupParams) {
				*p.opts = append(*p.opts,
					materials.WithMaterialsManager(p.defaultCMM),
					materials.WithKeyHasher(func() model.CacheHasher { return p.keyHasher }),
				)

				p.keyHasher.EXPECT().Update(mock.Anything)
				p.keyHasher.EXPECT().Compute().Return("cacheKey").Times(p.mc.times)

				p.c.EXPECT().GetDecryptionEntry("cacheKey").Return(nil, false).Times(p.mc.times)

				p.defaultCMM.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).
					Return(nil, materials.ErrCMM).Times(p.mc.times)
			},
			conf: mockConfig{
				primary: prov{ID: "provider1", Kind: types.AwsKms, dk: mockDataKeyProv1Key1},
				times:   10,
			},
			req: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				EncryptedDataKeys: []model.EncryptedDataKeyI{mockEDKProv1Key1, mockEDKProv1Key2},
				EncryptionContext: suite.EncryptionContext{"purpose": "test"},
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "CMM error",
			wantErrType: materials.ErrCMM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Cache
			cacheMock := mocks.NewMockCache(t)

			// Cache Hasher
			keyHasherMock := mocks.NewMockCacheHasher(t)

			// Default CryptoMaterialsManager
			defaultCmmMock := mocks.NewMockCryptoMaterialsManager(t)

			// Primary MasterKeyProvider
			primaryMock := mocks.NewMockMasterKeyProvider(t)

			optFns := make([]materials.CachingOptionFunc, 0)

			tt.setupMocks(&setupParams{
				t:          t,
				mc:         tt.conf,
				c:          cacheMock,
				defaultCMM: defaultCmmMock,
				keyHasher:  keyHasherMock,
				opts:       &optFns,
			})

			dm, errCMM := materials.NewCaching(cacheMock, primaryMock, optFns...)
			assert.NoError(t, errCMM)

			for i := 0; i < tt.conf.times; i++ {
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
			}
		})
	}
}
