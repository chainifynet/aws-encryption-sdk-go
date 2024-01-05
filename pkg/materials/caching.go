// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"time"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

type BaseCache interface {
	PutEncryptionEntry(cacheKey []byte, m model.EncryptionMaterials, n int) (*CacheEntry[model.EncryptionMaterials], error)
	PutDecryptionEntry(cacheKey []byte, m model.DecryptionMaterials) (*CacheEntry[model.DecryptionMaterials], error)
	GetEncryptionEntry(cacheKey []byte, n int) (*CacheEntry[model.EncryptionMaterials], error)
	GetDecryptionEntry(cacheKey []byte) (*CacheEntry[model.DecryptionMaterials], error)
}

type CachingCryptoMaterialsManager struct {
	// TODO probably add DefaultCryptoMaterialsManager
	cache       BaseCache
	maxAge      time.Duration
	maxMessages uint64
	maxBytes    int
}

func NewCaching(cache BaseCache, _ model.MasterKeyProvider, _ ...model.MasterKeyProvider) (*CachingCryptoMaterialsManager, error) {
	return &CachingCryptoMaterialsManager{
		cache:       cache,
		maxAge:      300 * time.Second, //nolint:gomnd
		maxMessages: 1000,              //nolint:gomnd
		maxBytes:    1000000,           //nolint:gomnd
	}, nil
}

// compile checking that CachingCryptoMaterialsManager implements CryptoMaterialsManager interface
var _ model.CryptoMaterialsManager = (*CachingCryptoMaterialsManager)(nil)

func (cm *CachingCryptoMaterialsManager) GetEncryptionMaterials(_ context.Context, _ model.EncryptionMaterialsRequest) (model.EncryptionMaterial, error) {
	return nil, nil
}

func (cm *CachingCryptoMaterialsManager) DecryptMaterials(_ context.Context, _ model.DecryptionMaterialsRequest) (model.DecryptionMaterial, error) {
	return nil, nil
}

func (cm *CachingCryptoMaterialsManager) GetInstance() model.CryptoMaterialsManager {
	return &CachingCryptoMaterialsManager{
		cache:       cm.cache,
		maxAge:      cm.maxAge,
		maxMessages: cm.maxMessages,
		maxBytes:    cm.maxBytes,
	}
}
