// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"sync"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

type MemoryCache struct {
	cache sync.Map //nolint:unused
}

// compile checking that MemoryCache implements BaseCache interface
var _ BaseCache = (*MemoryCache)(nil)

func (mc *MemoryCache) PutEncryptionEntry(_ []byte, _ model.EncryptionMaterials, _ int) (*CacheEntry[model.EncryptionMaterials], error) {
	//entry := NewCacheEntry(key, em, 300) //nolint:gomnd
	//mc.cache.Store(key, entry)
	//return entry, nil
	// TODO implement me
	panic("not implemented yet")
}

func (mc *MemoryCache) PutDecryptionEntry(_ []byte, _ model.DecryptionMaterials) (*CacheEntry[model.DecryptionMaterials], error) {
	//entry := NewCacheEntry(key, dm, 300) //nolint:gomnd
	//mc.cache.Store(key, entry)
	//return entry, nil
	// TODO implement me
	panic("not implemented yet")
}

func (mc *MemoryCache) GetEncryptionEntry(_ []byte, _ int) (*CacheEntry[model.EncryptionMaterials], error) {
	//entry, ok := mc.cache.Load(key)
	//if !ok {
	//	return nil, fmt.Errorf("cache entry not found")
	//}
	//return entry.(*CacheEntry[EncryptionMaterials]), nil
	// TODO implement me
	panic("not implemented yet")
}

func (mc *MemoryCache) GetDecryptionEntry(_ []byte) (*CacheEntry[model.DecryptionMaterials], error) {
	//entry, ok := mc.cache.Load(key)
	//if !ok {
	//	return nil, fmt.Errorf("cache entry not found")
	//}
	//return entry.(*CacheEntry[DecryptionMaterials]), nil
	// TODO implement me
	panic("not implemented yet")
}
