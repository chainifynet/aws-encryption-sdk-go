// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import "time"

type CacheEntry[V EncryptionMaterials | DecryptionMaterials] struct {
	key       []byte
	value     V
	createdAt time.Time
	lifetime  time.Duration
	messages  uint64 //nolint:unused
	bytes     int    //nolint:unused
	valid     bool
}

func NewCacheEntry[V EncryptionMaterials | DecryptionMaterials](key []byte, value V, lifetime time.Duration) *CacheEntry[V] {
	return &CacheEntry[V]{
		key:       key,
		value:     value,
		createdAt: time.Now(),
		lifetime:  lifetime,
		valid:     true,
	}
}

func (ce *CacheEntry[V]) Key() []byte {
	return ce.key
}

func (ce *CacheEntry[V]) Value() V {
	return ce.value
}

func (ce *CacheEntry[V]) Age() float64 {
	return time.Since(ce.createdAt).Seconds()
	//return time.Now().Sub(ce.createdAt).Seconds()
}

func (ce *CacheEntry[V]) IsTooOld() bool {
	return ce.Age() > ce.lifetime.Seconds()
}

func (ce *CacheEntry[V]) updateMeta(b []byte) { //nolint:unused
	ce.bytes += len(b)
	ce.messages++
}

func (ce *CacheEntry[V]) invalidate() { //nolint:unused
	ce.valid = false
}
