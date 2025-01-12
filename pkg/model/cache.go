// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"
)

// CacheEntry represents a single entry in the cache.
type CacheEntry interface {
	// Key returns the key associated with the cache entry.
	Key() string

	// Value returns the value stored in the cache entry.
	Value() any

	// Age returns the age of the cache entry in seconds.
	Age() float64

	// Messages retrieves the number of messages processed by the entry.
	Messages() uint64

	// Bytes returns the size of bytes processed by the entry.
	Bytes() uint64

	// IsTooOld checks if the entry has exceeded its lifetime.
	IsTooOld() bool

	// IsValid checks if the entry is still valid.
	IsValid() bool

	// UpdateMeta updates the metadata of the cache entry
	// with the number of bytes of plaintext to be encrypted.
	UpdateMeta(b int)

	// Invalidate marks the cache entry as invalid.
	Invalidate()
}

// Cache is an interface for managing caching of encryption and decryption
// materials. It allows storing, retrieving, and deleting cache entries.
//
// Custom cache implementations should implement this interface
// to be used with [CryptoMaterialsManager].
type Cache interface {
	// PutEncryptionEntry adds an encryption material to the cache.
	// It accepts a key, encryption material, n is len of bytes to be encrypted, and lifetime.
	// The method returns a CacheEntry object containing the added entry.
	PutEncryptionEntry(key string, em EncryptionMaterial, n int, lifetime time.Duration) CacheEntry

	// PutDecryptionEntry stores a decryption material in the cache with a specified key.
	// The method returns the added or updated cache entry.
	PutDecryptionEntry(key string, dm DecryptionMaterial, lifetime time.Duration) CacheEntry

	// GetEncryptionEntry retrieves an encryption entry from the cache using a specified key.
	// It updates the metadata with the provided number of bytes.
	// Returns the cache entry and a boolean indicating success.
	GetEncryptionEntry(key string, n int) (CacheEntry, bool)

	// GetDecryptionEntry retrieves a decryption entry from the cache using a key.
	// It returns the cache entry and a boolean indicating success.
	GetDecryptionEntry(key string) (CacheEntry, bool)

	// DeleteEntry removes the cache entry associated with the specified key.
	// It returns true if the entry was removed successfully.
	DeleteEntry(key string) bool

	// Len returns the number of entries in the cache.
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
