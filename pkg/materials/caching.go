// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/rand"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials/cache"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

const (

	// CacheDefaultMaxAge defines the default lifespan for cached entries.
	// It is used in caching mechanisms to determine when a cache
	// entry should be considered expired.
	CacheDefaultMaxAge = 300 * time.Second

	// CacheDefaultMaxMessages defines the default maximum number of messages
	// that can be encrypted under a single cache entry.
	CacheDefaultMaxMessages uint64 = 10

	// CacheDefaultMaxBytes defines number of bytes that a cache entry may be
	// used to encrypt before it is considered expired.
	CacheDefaultMaxBytes uint64 = 100000
)

// CachingCryptoMaterialsManager is a caching implementation of [model.CryptoMaterialsManager].
// It interacts directly with [DefaultCryptoMaterialsManager] under the hood.
type CachingCryptoMaterialsManager struct {
	// cache is implementation of [model.Cache] interface used to store encryption and decryption materials.
	cache model.Cache

	// maxAge is the duration for which cached items remain in the cache before expiring.
	maxAge time.Duration

	// maxMessages specifies the number of messages that may be encrypted or
	// decrypted under a cache entry before consider it expired.
	maxMessages uint64

	// maxBytes specifies the number of bytes that a cache entry may process before it is considered expired.
	maxBytes uint64

	// partition is a random used to generate unique cache keys.
	partition []byte

	// manager is a backing [model.CryptoMaterialsManager] to back this caching
	// material manager.
	//
	// Either primary [model.MasterKeyProvider] or a custom [model.CryptoMaterialsManager]
	// via [WithMaterialsManager] must be provided.
	//
	// A custom manager takes precedence over the primary provider.
	manager model.CryptoMaterialsManager

	// keyHasherFn is a function used to generate unique cache keys.
	keyHasherFn model.KeyHasherFunc
}

// NewCaching creates a new instance of [CachingCryptoMaterialsManager].
// It initializes the manager with a given cache and a primary [model.MasterKeyProvider].
//
// Default values are used for the following parameters:
//   - maxAge: [CacheDefaultMaxAge]
//   - maxMessages: [CacheDefaultMaxMessages]
//   - maxBytes: [CacheDefaultMaxBytes]
//
// Optional configuration functions can be provided to customize the manager's behavior.
//
// Parameters:
//   - c: The [model.Cache] implementation to be used for storing encryption and decryption materials.
//   - primary: The primary [model.MasterKeyProvider] used for cryptographic operations.
//     It can be nil if a custom [model.CryptoMaterialsManager] is provided via [WithMaterialsManager].
//   - optFns: Optional functions for further configuration of the caching manager.
//
// Returns:
//   - A configured [CachingCryptoMaterialsManager] instance or an error if the configuration is invalid.
//
// Example usage:
//
//	cache, err := cache.NewMemoryCache(10)
//	if err != nil {
//	    // handle error
//	}
//	cachingManager, err := NewCaching(cache, provider)
//
// Advanced usage:
//
//	cache, err := cache.NewMemoryCache(10)
//	if err != nil {
//	    // handle error
//	}
//	cachingManager, err := NewCaching(cache, provider,
//	    WithMaxAge(600 * time.Second),
//	    WithMaxMessages(30),
//	    WithAdditionalProviders(provider1, provider2),
//	)
//	if err != nil {
//	    // handle error
//	}
//
// Advanced usage with provided [model.CryptoMaterialsManager]:
//
//	cmm, err := NewDefault(provider, provider1, provider2)
//	if err != nil {
//	    // handle error
//	}
//
//	cache, err := cache.NewMemoryCache(10)
//	if err != nil {
//	    // handle error
//	}
//
//	cachingManager, err := NewCaching(cache, nil,
//	    WithMaterialsManager(cmm),
//	    WithMaxMessages(10),
//	    WithMaxBytes(32768),
//	)
//	if err != nil {
//	    // handle error
//	}
func NewCaching(c model.Cache, primary model.MasterKeyProvider, optFns ...CachingOptionFunc) (*CachingCryptoMaterialsManager, error) {
	opts := CachingOptions{
		AdditionalProviders: nil,
		Manager:             nil,
		KeyHasherFn:         nil,
		MaxAge:              CacheDefaultMaxAge,
		MaxMessages:         CacheDefaultMaxMessages,
		MaxBytes:            CacheDefaultMaxBytes,
	}

	for _, optFn := range optFns {
		if err := optFn(&opts); err != nil {
			return nil, fmt.Errorf("invalid caching option: %w", errors.Join(ErrInvalidConfig, err))
		}
	}

	if err := validateCachingParams(c, primary, &opts); err != nil {
		return nil, fmt.Errorf("validate caching params: %w", errors.Join(ErrInvalidConfig, err))
	}

	partition, _ := rand.CryptoRandomBytes(16) //nolint:mnd
	if opts.Manager == nil {
		cmm, err := NewDefault(primary, opts.AdditionalProviders...)
		if err != nil {
			return nil, err
		}
		opts.Manager = cmm
	}

	return &CachingCryptoMaterialsManager{
		cache:       c,
		maxAge:      opts.MaxAge,
		maxMessages: opts.MaxMessages,
		maxBytes:    opts.MaxBytes,
		partition:   partition,
		manager:     opts.Manager,
		keyHasherFn: opts.KeyHasherFn,
	}, nil
}

// compile checking that CachingCryptoMaterialsManager implements CryptoMaterialsManager interface
var _ model.CryptoMaterialsManager = (*CachingCryptoMaterialsManager)(nil)

// GetEncryptionMaterials retrieves encryption materials for a given request.
// It first checks if the request should be cached. If not, it delegates the request
// to the underlying manager. If caching is applicable, it attempts to retrieve
// the materials from the cache or generates new materials and stores them in the cache.
func (cm *CachingCryptoMaterialsManager) GetEncryptionMaterials(ctx context.Context, r model.EncryptionMaterialsRequest) (model.EncryptionMaterial, error) {
	if !shouldCacheEncryptionRequest(r) {
		return cm.manager.GetEncryptionMaterials(ctx, r)
	}

	// Inner request strips any information about the plaintext from the actual request.
	// This is done because the resulting encryption materials may be used to encrypt
	// multiple plaintexts.
	innerRequest := model.EncryptionMaterialsRequest{
		EncryptionContext: r.EncryptionContext,
		Algorithm:         r.Algorithm,
	}

	getAndPut := func(key string) (model.EncryptionMaterial, error) {
		encMaterials, err := cm.manager.GetEncryptionMaterials(ctx, innerRequest)
		if err != nil {
			return nil, err
		}

		if uint64(r.PlaintextLength) >= cm.maxBytes {
			return encMaterials, nil
		}

		entry := cm.cache.PutEncryptionEntry(key, encMaterials, r.PlaintextLength, cm.maxAge)
		return entry.Value().(model.EncryptionMaterial), nil
	}

	cacheKey := cache.ComputeEncCacheKey(cm.partition, innerRequest, cm.keyHasherFn)

	cacheEntry, ok := cm.cache.GetEncryptionEntry(cacheKey, r.PlaintextLength)
	if !ok {
		return getAndPut(cacheKey)
	}

	if cm.isEntryOverLimits(cacheEntry) {
		cacheEntry.Invalidate()
		cm.cache.DeleteEntry(cacheKey)
		return getAndPut(cacheKey)
	}

	return cacheEntry.Value().(model.EncryptionMaterial), nil
}

// DecryptMaterials retrieves decryption materials for a given request.
// It delegates the request to the underlying manager, stores the result in the cache, and returns it.
// If the materials are found in the cache but exceed defined limits, it invalidates the cache entry,
// deletes it, and generates new materials.
func (cm *CachingCryptoMaterialsManager) DecryptMaterials(ctx context.Context, r model.DecryptionMaterialsRequest) (model.DecryptionMaterial, error) {
	cacheKey := cache.ComputeDecCacheKey(cm.partition, r, cm.keyHasherFn)

	getAndPut := func(key string) (model.DecryptionMaterial, error) {
		decMaterials, err := cm.manager.DecryptMaterials(ctx, r)
		if err != nil {
			return nil, err
		}
		entry := cm.cache.PutDecryptionEntry(key, decMaterials, cm.maxAge)
		return entry.Value().(model.DecryptionMaterial), nil
	}

	cacheEntry, ok := cm.cache.GetDecryptionEntry(cacheKey)
	if !ok {
		return getAndPut(cacheKey)
	}

	if cm.isEntryOverLimits(cacheEntry) {
		cacheEntry.Invalidate()
		cm.cache.DeleteEntry(cacheKey)
		return getAndPut(cacheKey)
	}

	return cacheEntry.Value().(model.DecryptionMaterial), nil
}

// GetInstance returns a new instance of the crypto materials manager to interact
// within encryption/decryption process.
func (cm *CachingCryptoMaterialsManager) GetInstance() model.CryptoMaterialsManager {
	return &CachingCryptoMaterialsManager{
		cache:       cm.cache,
		maxAge:      cm.maxAge,
		maxMessages: cm.maxMessages,
		maxBytes:    cm.maxBytes,
		partition:   cm.partition,
		manager:     cm.manager,
		keyHasherFn: cm.keyHasherFn,
	}
}

// isEntryOverLimits determines if a cache entry exceeds defined limits.
func (cm *CachingCryptoMaterialsManager) isEntryOverLimits(e model.CacheEntry) bool {
	isTooOld := e.Age() > cm.maxAge.Seconds()
	hasTooManyMessages := e.Messages() > cm.maxMessages
	exceedsMaxBytes := e.Bytes() > cm.maxBytes

	return isTooOld || hasTooManyMessages || exceedsMaxBytes
}

// shouldCacheEncryptionRequest determines if an encryption request should be
// cached based on the request's plaintext length and encryption algorithm.
func shouldCacheEncryptionRequest(r model.EncryptionMaterialsRequest) bool {
	return r.PlaintextLength > 0 && r.Algorithm != nil && r.Algorithm.IsKDFSupported()
}
