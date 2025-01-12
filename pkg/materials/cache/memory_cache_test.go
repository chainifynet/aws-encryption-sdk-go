// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials/cache"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestMemoryCache_EncryptionConcurrencySafe(t *testing.T) {
	cacheCapacity := 8
	mc, _ := cache.NewMemoryCache(cacheCapacity)
	var wg sync.WaitGroup
	iterations := 10000

	type args struct {
		key      string
		material model.EncryptionMaterial
		n        int
		lifetime time.Duration
	}

	tests := []struct {
		name string
		args args
	}{
		{name: "Test1", args: args{key: "key1", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test2", args: args{key: "key2", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test3", args: args{key: "key3", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test4", args: args{key: "key4", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test5", args: args{key: "key5", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test6", args: args{key: "key6", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test7", args: args{key: "key7", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test8", args: args{key: "key8", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test9", args: args{key: "key9", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
		{name: "Test10", args: args{key: "key10", material: model.EncryptionMaterials{}, n: 1, lifetime: time.Second}},
	}

	wg.Add(len(tests) * iterations * 2)
	for _, tt := range tests {
		tt := tt
		go func() {
			for i := 0; i < iterations; i++ {
				mc.PutEncryptionEntry(tt.args.key, tt.args.material, tt.args.n, tt.args.lifetime)
				wg.Done()
			}
		}()
		go func() {
			for i := 0; i < iterations; i++ {
				mc.GetEncryptionEntry(tt.args.key, tt.args.n)
				wg.Done()
			}
		}()
	}
	wg.Wait()

	// After all operations, ensure entries exist and count matches expected
	for _, tt := range tests {
		entry, ok := mc.GetEncryptionEntry(tt.args.key, 0)
		if ok {
			assert.NotNil(t, entry, "Entry should not be nil when it exists")
			t.Logf("%s: %v msgs; %v bytes\n", tt.name, entry.Messages(), entry.Bytes())
		} else {
			assert.Nil(t, entry, "Entry should be nil when it doesn't exist")
			t.Logf("%s: entity \"%s\" not found\n", tt.name, tt.args.key)
		}
	}

	assert.Equal(t, cacheCapacity, mc.Len())
}

func TestMemoryCache_DecryptionConcurrencySafe(t *testing.T) {
	cacheCapacity := 8
	mc, _ := cache.NewMemoryCache(cacheCapacity)
	var wg sync.WaitGroup
	iterations := 10000

	type args struct {
		key      string
		material model.DecryptionMaterial
		lifetime time.Duration
	}

	tests := []struct {
		name string
		args args
	}{
		{name: "Test1", args: args{key: "key1", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test2", args: args{key: "key2", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test3", args: args{key: "key3", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test4", args: args{key: "key4", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test5", args: args{key: "key5", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test6", args: args{key: "key6", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test7", args: args{key: "key7", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test8", args: args{key: "key8", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test9", args: args{key: "key9", material: model.DecryptionMaterials{}, lifetime: time.Second}},
		{name: "Test10", args: args{key: "key10", material: model.DecryptionMaterials{}, lifetime: time.Second}},
	}

	wg.Add(len(tests) * iterations * 2)
	for _, tt := range tests {
		tt := tt
		go func() {
			for i := 0; i < iterations; i++ {
				mc.PutDecryptionEntry(tt.args.key, tt.args.material, tt.args.lifetime)
				wg.Done()
			}
		}()
		go func() {
			for i := 0; i < iterations; i++ {
				mc.GetDecryptionEntry(tt.args.key)
				wg.Done()
			}
		}()
	}
	wg.Wait()

	// After all operations, ensure entries exist and count matches expected
	for _, tt := range tests {
		entry, ok := mc.GetDecryptionEntry(tt.args.key)
		if ok {
			assert.NotNil(t, entry, "Entry should not be nil when it exists")
			t.Logf("%s: %v msgs\n", tt.name, entry.Messages())
		} else {
			assert.Nil(t, entry, "Entry should be nil when it doesn't exist")
			t.Logf("%s: entity \"%s\" not found\n", tt.name, tt.args.key)
		}
	}

	assert.Equal(t, cacheCapacity, mc.Len())
}

func TestNewMemoryCache(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		wantErr  error
	}{
		{
			name:     "Valid capacity 1",
			capacity: 1,
			wantErr:  nil,
		},
		{
			name:     "Valid capacity 10",
			capacity: 10,
			wantErr:  nil,
		},
		{
			name:     "Valid capacity 100",
			capacity: 100,
			wantErr:  nil,
		},
		{
			name:     "Zero capacity invalid",
			capacity: 0,
			wantErr:  fmt.Errorf("invalid capacity: %d", 0),
		},
		{
			name:     "Negative capacity invalid -1",
			capacity: -1,
			wantErr:  fmt.Errorf("invalid capacity: %d", -1),
		},
		{
			name:     "Negative capacity invalid -10",
			capacity: -10,
			wantErr:  fmt.Errorf("invalid capacity: %d", -10),
		},
		{
			name:     "Large valid capacity 1000",
			capacity: 1000,
			wantErr:  nil,
		},
		{
			name:     "Large invalid negative capacity",
			capacity: -1000,
			wantErr:  fmt.Errorf("invalid capacity: %d", -1000),
		},
		{
			name:     "Small valid capacity 2",
			capacity: 2,
			wantErr:  nil,
		},
		{
			name:     "Borderline invalid negative capacity",
			capacity: -999,
			wantErr:  fmt.Errorf("invalid capacity: %d", -999),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cache.NewMemoryCache(tt.capacity)

			if tt.wantErr != nil {
				assert.Nil(t, got)
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NotNil(t, got)
				assert.NoError(t, err)
			}
		})
	}
}

func TestMemoryCache_DeleteEntry(t *testing.T) {
	tests := []struct {
		name  string
		setup func(c *cache.MemoryCache)
		key   string
		want  bool
	}{
		{
			name: "delete existing key",
			setup: func(c *cache.MemoryCache) {
				c.PutDecryptionEntry("key1", model.DecryptionMaterials{}, time.Second)
			},
			key:  "key1",
			want: true,
		},
		{
			name: "delete non-existing key",
			setup: func(c *cache.MemoryCache) {
				c.PutDecryptionEntry("key1", model.DecryptionMaterials{}, time.Second)
			},
			key:  "key2",
			want: false,
		},
		{
			name: "empty cache delete any key",
			setup: func(c *cache.MemoryCache) {
				// no-op
			},
			key:  "key1",
			want: false,
		},
		{
			name: "delete with multiple keys, key exists",
			setup: func(c *cache.MemoryCache) {
				c.PutEncryptionEntry("key1", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key2", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key3", model.EncryptionMaterials{}, 1, time.Second)
			},
			key:  "key2",
			want: true,
		},
		{
			name: "delete invalid key",
			setup: func(c *cache.MemoryCache) {
				e := c.PutEncryptionEntry("key2", model.EncryptionMaterials{}, 1, time.Second)
				e.Invalidate()
				c.GetDecryptionEntry("key2")
			},
			key:  "key2",
			want: false,
		},
		{
			name: "delete with multiple keys, key does not exist",
			setup: func(c *cache.MemoryCache) {
				c.PutEncryptionEntry("key1", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key3", model.EncryptionMaterials{}, 1, time.Second)
			},
			key:  "key2",
			want: false,
		},
		{
			name: "delete empty string key",
			setup: func(c *cache.MemoryCache) {
				c.PutDecryptionEntry("key1", model.DecryptionMaterials{}, time.Second)
				c.PutDecryptionEntry("", model.DecryptionMaterials{}, time.Second)
			},
			key:  "",
			want: true,
		},
		{
			name: "delete evicted key",
			setup: func(c *cache.MemoryCache) {
				c.PutEncryptionEntry("key1", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key2", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key3", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key4", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key5", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key6", model.EncryptionMaterials{}, 1, time.Second)
			},
			key:  "key1",
			want: false,
		},
		{
			name: "delete last key after first evicted key",
			setup: func(c *cache.MemoryCache) {
				c.PutEncryptionEntry("key1", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key2", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key3", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key4", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key5", model.EncryptionMaterials{}, 1, time.Second)
				c.PutEncryptionEntry("key6", model.EncryptionMaterials{}, 1, time.Second)
			},
			key:  "key6",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := cache.NewMemoryCache(5)
			assert.NoError(t, err)
			assert.NotNil(t, c)
			tt.setup(c)
			got := c.DeleteEntry(tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}
