// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestNewCacheEntry(t *testing.T) {
	// TODO Write proper tests once CachingCryptoMaterialsManager is implemented.
	tests := []struct {
		name     string
		key      []byte
		value    interface{}
		lifetime time.Duration
	}{
		{
			name:     "encryption material",
			key:      []byte("key"),
			value:    model.EncryptionMaterials{},
			lifetime: 10 * time.Minute,
		},
		{
			name:     "decryption material",
			key:      []byte("anotherKey"),
			value:    model.DecryptionMaterials{},
			lifetime: 5 * time.Minute,
		},
		{
			name:     "minimal lifetime",
			key:      []byte("yetAnotherKey"),
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
				assert.Equal(t, tc.lifetime, entry.lifetime)
				assert.True(t, entry.valid)

				entry.updateMeta([]byte("some_data"))
				assert.Equal(t, uint64(1), entry.messages)
				assert.Equal(t, 9, entry.bytes)

				entry.invalidate()
				assert.False(t, entry.valid)
			case model.DecryptionMaterials:
				entry := NewCacheEntry[model.DecryptionMaterials](tc.key, v, tc.lifetime)
				assert.Equal(t, tc.key, entry.Key())
				assert.Equal(t, v, entry.Value())
				assert.True(t, entry.Age() <= tc.lifetime.Seconds())
				assert.False(t, entry.IsTooOld())
				assert.Equal(t, tc.lifetime, entry.lifetime)
				assert.True(t, entry.valid)

				entry.updateMeta([]byte("some_data"))
				assert.Equal(t, uint64(1), entry.messages)
				assert.Equal(t, 9, entry.bytes)

				entry.invalidate()
				assert.False(t, entry.valid)
			}
		})
	}
}
