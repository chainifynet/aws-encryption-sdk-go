// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// MemoryCache is a thread-safe in-memory implementation of [model.Cache] interface.
type MemoryCache struct {
	capacity int
	mu       sync.Mutex
	cache    map[string]*list.Element
	lru      *list.List
}

// compile checking that MemoryCache implements [model.Cache] interface
var _ model.Cache = (*MemoryCache)(nil)

// NewMemoryCache creates a new instance of MemoryCache with the specified capacity.
// It returns an error if the capacity is less than or equal to zero.
func NewMemoryCache(capacity int) (*MemoryCache, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("invalid capacity: %d", capacity)
	}
	return &MemoryCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		lru:      list.New(),
	}, nil
}

// PutEncryptionEntry adds an encryption material to the in-memory cache.
// It accepts a key, encryption material, n is len of bytes to be encrypted, and lifetime.
// The method returns a CacheEntry object containing the added entry.
func (m *MemoryCache) PutEncryptionEntry(key string, em model.EncryptionMaterial, n int, lifetime time.Duration) model.CacheEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ce, ok := m.getCacheEntry(key); ok {
		ce.UpdateMeta(n)
		return ce
	}

	entry := NewCacheEntry(key, em, lifetime)
	entry.UpdateMeta(n)

	return m.storeCacheEntry(key, entry)
}

// PutDecryptionEntry stores a decryption material in the cache with a specified key.
// The method returns the added or updated cache entry.
func (m *MemoryCache) PutDecryptionEntry(key string, dm model.DecryptionMaterial, lifetime time.Duration) model.CacheEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ce, ok := m.getCacheEntry(key); ok {
		ce.UpdateMeta(0)
		return ce
	}

	entry := NewCacheEntry(key, dm, lifetime)
	entry.UpdateMeta(0)

	return m.storeCacheEntry(key, entry)
}

// GetEncryptionEntry retrieves an encryption entry from the cache using a specified key.
// It updates the metadata with the provided number of bytes.
// Returns the cache entry and a boolean indicating success.
func (m *MemoryCache) GetEncryptionEntry(key string, n int) (model.CacheEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.getCacheEntry(key); ok {
		entry.UpdateMeta(n)
		return entry, true
	}

	return nil, false
}

// GetDecryptionEntry retrieves a decryption entry from the cache using a key.
// It returns the cache entry and a boolean indicating success.
func (m *MemoryCache) GetDecryptionEntry(key string) (model.CacheEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.getCacheEntry(key); ok {
		entry.UpdateMeta(0)
		return entry, true
	}

	return nil, false
}

// DeleteEntry removes the cache entry associated with the specified key.
// It returns true if the entry was removed successfully.
func (m *MemoryCache) DeleteEntry(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteEntry(key)
}

// deleteEntry removes the cache entry associated with the specified key.
// It returns true if the entry was removed successfully.
//
// lock must be held before calling this function.
func (m *MemoryCache) deleteEntry(key string) bool {
	if elem, ok := m.cache[key]; ok {
		m.lru.Remove(elem)
		delete(m.cache, key)
		return true
	}
	return false
}

// Len returns the number of entries in the cache.
func (m *MemoryCache) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lru.Len()
}

// getCacheEntry retrieves a cache entry from the cache using a specified key.
// It returns the cache entry and a boolean indicating success.
// It also moves the entry to the front of the LRU list.
// It returns false if the entry is invalid and removes it.
//
// lock must be held before calling this function.
func (m *MemoryCache) getCacheEntry(key string) (model.CacheEntry, bool) {
	// Check if the entry exists and is valid.
	if elem, ok := m.cache[key]; ok && !m.removeIfInvalid(elem) {
		m.lru.MoveToFront(elem)
		return elem.Value.(model.CacheEntry), true
	}
	return nil, false
}

// storeCacheEntry stores a cache entry in the cache.
// New entries are added to the front of the LRU list.
// It also removes the least recently used entry if the cache is full.
// It returns the added or updated cache entry.
//
// lock must be held before calling this function.
func (m *MemoryCache) storeCacheEntry(key string, e model.CacheEntry) model.CacheEntry {
	elem := m.lru.PushFront(e)
	m.cache[key] = elem

	if m.lru.Len() > m.capacity {
		m.removeOldest()
	}

	return elem.Value.(model.CacheEntry)
}

// removeOldest removes the least recently used entry from the cache.
//
// lock must be held before calling this function.
func (m *MemoryCache) removeOldest() {
	elem := m.lru.Back()
	if elem != nil {
		m.lru.Remove(elem)
		delete(m.cache, elem.Value.(model.CacheEntry).Key())
		return
	}
}

// removeIfInvalid removes the cache entry if it is invalid.
// It returns true if the entry was invalid and removed.
//
// lock must be held before calling this function.
func (m *MemoryCache) removeIfInvalid(e *list.Element) bool {
	ce := e.Value.(model.CacheEntry)
	if !ce.IsValid() {
		m.deleteEntry(ce.Key())
		return true
	}
	return false
}
