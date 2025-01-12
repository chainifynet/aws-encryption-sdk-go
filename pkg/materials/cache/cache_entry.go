// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// Entry implements [model.CacheEntry] interface with a key, value, creation time, and metadata.
type Entry[V any] struct {
	key       string
	value     V
	createdAt time.Time
	lifetime  time.Duration
	messages  uint64
	bytes     uint64
	valid     bool
}

var _ model.CacheEntry = (*Entry[model.EncryptionMaterial])(nil)
var _ model.CacheEntry = (*Entry[model.DecryptionMaterial])(nil)

// NewCacheEntry creates a new cache entry with the specified key.
func NewCacheEntry[V any](key string, value V, lifetime time.Duration) *Entry[V] {
	return &Entry[V]{
		key:       key,
		value:     value,
		createdAt: time.Now(),
		lifetime:  lifetime.Abs(),
		messages:  0,
		bytes:     0,
		valid:     true,
	}
}

// Key returns the key associated with the cache entry.
func (ce *Entry[V]) Key() string {
	return ce.key
}

// Value returns the value stored in the cache entry.
func (ce *Entry[V]) Value() any {
	return ce.value
}

// Age returns the age of the cache entry in seconds.
func (ce *Entry[V]) Age() float64 {
	return time.Since(ce.createdAt).Seconds()
}

// Messages retrieves the number of messages processed by the entry.
func (ce *Entry[V]) Messages() uint64 {
	return ce.messages
}

// Bytes returns the size of bytes processed by the entry.
func (ce *Entry[V]) Bytes() uint64 {
	return ce.bytes
}

// IsTooOld checks if the entry has exceeded its lifetime.
func (ce *Entry[V]) IsTooOld() bool {
	return ce.Age() > ce.lifetime.Seconds()
}

// IsValid checks if the entry is still valid.
func (ce *Entry[V]) IsValid() bool {
	return ce.valid
}

// UpdateMeta updates the metadata of the cache entry
// with the number of bytes of plaintext to be encrypted.
func (ce *Entry[V]) UpdateMeta(b int) {
	if b > 0 {
		ce.bytes += uint64(b)
	}
	ce.messages++
}

// Invalidate marks the cache entry as invalid.
func (ce *Entry[V]) Invalidate() {
	ce.valid = false
}
