// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"
)

// CacheEntry represents a single entry in the cache.
type CacheEntry interface {
	Key() string
	Value() any
	Age() float64
	Messages() uint64
	Bytes() uint64
	IsTooOld() bool
	IsValid() bool
	UpdateMeta(b int)
	Invalidate()
}

// Cache is an interface for managing caching of encryption and decryption
// materials. It allows storing, retrieving, and deleting cache entries.
//
// Custom cache implementations should implement this interface
// to be used with [CryptoMaterialsManager].
type Cache interface {
	PutEncryptionEntry(key string, em EncryptionMaterial, n int, lifetime time.Duration) CacheEntry
	PutDecryptionEntry(key string, dm DecryptionMaterial, lifetime time.Duration) CacheEntry
	GetEncryptionEntry(key string, n int) (CacheEntry, bool)
	GetDecryptionEntry(key string) (CacheEntry, bool)
	DeleteEntry(key string) bool
	Len() int
}

// CacheHasher defines an interface to compute hashes for cache keys.
type CacheHasher interface {

	// Update processes the input byte slice `p` to update the hash state.
	Update(p []byte)

	// Compute finalizes the hash computation and returns the hash as a string.
	// The method should be invoked after providing all input to the hasher using
	// the Update method. The resulting string is typically used as a cache key.
	// After calling, the hasher state is reset and can be reused.
	Compute() string
}

// KeyHasherFunc is a function that returns a new instance of [CacheHasher].
type KeyHasherFunc func() CacheHasher
