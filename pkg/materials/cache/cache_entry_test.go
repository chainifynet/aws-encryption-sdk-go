// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestNewCacheEntry(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    interface{}
		lifetime time.Duration
	}{
		{
			name:     "encryption material",
			key:      "key",
			value:    model.EncryptionMaterials{},
			lifetime: 10 * time.Minute,
		},
		{
			name:     "decryption material",
			key:      "anotherKey",
			value:    model.DecryptionMaterials{},
			lifetime: 5 * time.Minute,
		},
		{
			name:     "negative lifetime",
			key:      "negativeKey",
			value:    model.DecryptionMaterials{},
			lifetime: -100 * time.Millisecond,
		},
		{
			name:     "minimal lifetime",
			key:      "yetAnotherKey",
			value:    model.EncryptionMaterials{},
			lifetime: 100 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			switch v := tc.value.(type) {
			case model.EncryptionMaterials:
				entry := NewCacheEntry[model.EncryptionMaterials](tc.key, v, tc.lifetime)
				assert.Equal(t, tc.key, entry.Key())
				assert.Equal(t, v, entry.Value())
				assert.True(t, entry.Age() <= tc.lifetime.Seconds())
				assert.False(t, entry.IsTooOld())
				assert.Equal(t, tc.lifetime.Abs(), entry.lifetime)
				assert.True(t, entry.valid)
				assert.True(t, entry.IsValid())

				entry.UpdateMeta(0)
				assert.Equal(t, uint64(1), entry.Messages())
				assert.Equal(t, uint64(0), entry.Bytes())

				entry.UpdateMeta(-1)
				assert.Equal(t, uint64(2), entry.Messages())
				assert.Equal(t, uint64(0), entry.Bytes())

				entry.UpdateMeta(9)
				assert.Equal(t, uint64(3), entry.Messages())
				assert.Equal(t, uint64(9), entry.Bytes())

				entry.UpdateMeta(5)
				assert.Equal(t, uint64(4), entry.Messages())
				assert.Equal(t, uint64(14), entry.Bytes())

				entry.Invalidate()
				assert.False(t, entry.valid)
				assert.False(t, entry.IsValid())
			case model.DecryptionMaterials:
				entry := NewCacheEntry[model.DecryptionMaterials](tc.key, v, tc.lifetime)
				assert.Equal(t, tc.key, entry.Key())
				assert.Equal(t, v, entry.Value())
				assert.True(t, entry.Age() <= tc.lifetime.Abs().Seconds())
				assert.False(t, entry.IsTooOld())
				assert.Equal(t, tc.lifetime.Abs(), entry.lifetime)
				assert.True(t, entry.valid)
				assert.True(t, entry.IsValid())

				entry.UpdateMeta(0)
				assert.Equal(t, uint64(1), entry.Messages())
				assert.Equal(t, uint64(0), entry.Bytes())

				entry.UpdateMeta(-1)
				assert.Equal(t, uint64(2), entry.Messages())
				assert.Equal(t, uint64(0), entry.Bytes())

				entry.UpdateMeta(10)
				assert.Equal(t, uint64(3), entry.Messages())
				assert.Equal(t, uint64(10), entry.Bytes())

				entry.UpdateMeta(5)
				assert.Equal(t, uint64(4), entry.Messages())
				assert.Equal(t, uint64(15), entry.Bytes())

				entry.Invalidate()
				assert.False(t, entry.valid)
				assert.False(t, entry.IsValid())
			}
		})
	}
}
