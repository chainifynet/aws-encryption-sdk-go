// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"fmt"
	"sync"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// MemoryCache CachingCryptoMaterialsManager still under development.
type MemoryCache struct {
	cache sync.Map
}

// compile checking that MemoryCache implements BaseCache interface
var _ BaseCache = (*MemoryCache)(nil)

func (mc *MemoryCache) PutEncryptionEntry(key []byte, em model.EncryptionMaterials, _ int) (*CacheEntry[model.EncryptionMaterials], error) {
	entry := NewCacheEntry(key, em, 300) //nolint:mnd
	mc.cache.Store(string(key), entry)
	return entry, nil
}

func (mc *MemoryCache) PutDecryptionEntry(key []byte, dm model.DecryptionMaterials) (*CacheEntry[model.DecryptionMaterials], error) {
	entry := NewCacheEntry(key, dm, 300) //nolint:mnd
	mc.cache.Store(string(key), entry)
	return entry, nil
}

func (mc *MemoryCache) GetEncryptionEntry(key []byte, _ int) (*CacheEntry[model.EncryptionMaterials], error) {
	entry, ok := mc.cache.Load(string(key))
	if !ok {
		return nil, fmt.Errorf("cache entry not found")
	}
	return entry.(*CacheEntry[model.EncryptionMaterials]), nil
}

func (mc *MemoryCache) GetDecryptionEntry(key []byte) (*CacheEntry[model.DecryptionMaterials], error) {
	entry, ok := mc.cache.Load(string(key))
	if !ok {
		return nil, fmt.Errorf("cache entry not found")
	}
	return entry.(*CacheEntry[model.DecryptionMaterials]), nil
}
