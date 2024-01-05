// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestMemoryCache_PutEncryptionEntry(t *testing.T) {
	// TODO Write proper tests once CachingCryptoMaterialsManager is implemented.
	type args struct {
		key []byte
		em  *model.EncryptionMaterials
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				key: []byte("key"),
				em: model.NewEncryptionMaterials(
					model.NewDataKey(model.WithKeyMeta("provider1", "key1"), []byte("dataKey1"), []byte("encryptedDataKey1")),
					nil,
					nil,
					nil,
				),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &MemoryCache{
				cache: sync.Map{},
			}
			got, err := mc.PutEncryptionEntry(tt.args.key, *tt.args.em, 300)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			got2, err := mc.GetEncryptionEntry(tt.args.key, 300)
			assert.NoError(t, err)
			assert.Equal(t, got, got2)

			_, err = mc.GetEncryptionEntry([]byte("key2"), 300)
			assert.Error(t, err)
		})
	}
}

func TestMemoryCache_PutDecryptionEntry(t *testing.T) {
	// TODO Write proper tests once CachingCryptoMaterialsManager is implemented.
	type args struct {
		key []byte
		dm  *model.DecryptionMaterials
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				key: []byte("key"),
				dm: model.NewDecryptionMaterials(
					model.NewDataKey(model.WithKeyMeta("provider1", "key1"), []byte("dataKey1"), []byte("encryptedDataKey1")),
					nil,
				),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &MemoryCache{
				cache: sync.Map{},
			}
			got, err := mc.PutDecryptionEntry(tt.args.key, *tt.args.dm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			got2, err := mc.GetDecryptionEntry(tt.args.key)
			assert.NoError(t, err)
			assert.Equal(t, got, got2)

			_, err = mc.GetDecryptionEntry([]byte("key2"))
			assert.Error(t, err)
		})
	}
}
