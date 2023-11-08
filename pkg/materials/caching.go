// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"time"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
)

type BaseCache interface {
	PutEncryptionEntry(cacheKey []byte, m EncryptionMaterials, n int) (*CacheEntry[EncryptionMaterials], error)
	PutDecryptionEntry(cacheKey []byte, m DecryptionMaterials) (*CacheEntry[DecryptionMaterials], error)
	GetEncryptionEntry(cacheKey []byte, n int) (*CacheEntry[EncryptionMaterials], error)
	GetDecryptionEntry(cacheKey []byte) (*CacheEntry[DecryptionMaterials], error)
}

type CachingCryptoMaterialsManager struct {
	// TODO probably add DefaultCryptoMaterialsManager
	cache       BaseCache
	maxAge      time.Duration //nolint:unused
	maxMessages uint64        //nolint:unused
	maxBytes    int           //nolint:unused
}

func NewCaching(cache BaseCache, _ providers.MasterKeyProvider, _ ...providers.MasterKeyProvider) (*CachingCryptoMaterialsManager, error) {
	_ = &CachingCryptoMaterialsManager{
		cache: cache,
	}
	// TODO implement me
	panic("not implemented yet")
}

// compile checking that CachingCryptoMaterialsManager implements CryptoMaterialsManager interface
var _ CryptoMaterialsManager = (*CachingCryptoMaterialsManager)(nil)

func (c *CachingCryptoMaterialsManager) GetEncryptionMaterials(_ EncryptionMaterialsRequest) (*EncryptionMaterials, error) {
	//TODO implement me
	panic("not implemented yet")
}

func (c *CachingCryptoMaterialsManager) DecryptMaterials(_ DecryptionMaterialsRequest) (*DecryptionMaterials, error) {
	//TODO implement me
	panic("not implemented yet")
}

func (c *CachingCryptoMaterialsManager) GetInstance() CryptoMaterialsManager {
	//TODO implement me
	panic("not implemented yet")
}
