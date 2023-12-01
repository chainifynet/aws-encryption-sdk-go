// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestWithStaticKey(t *testing.T) {
	tests := []struct {
		name   string
		inputs []staticKey
	}{
		{
			name: "Add Single Key",
			inputs: []staticKey{
				{keyID: "key1", key: []byte("key-data-1")},
			},
		},
		{
			name: "Add Multiple Keys",
			inputs: []staticKey{
				{keyID: "key1", key: []byte("key-data-1")},
				{keyID: "key2", key: []byte("key-data-2")},
			},
		},
		{
			name: "Add Empty Key",
			inputs: []staticKey{
				{keyID: "key1", key: []byte("key-data-1")},
				{keyID: "key2", key: []byte("key-data-2")},
				{keyID: "", key: []byte("")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			for _, input := range tt.inputs {
				err := WithStaticKey(input.keyID, input.key)(opts)
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.inputs, opts.configKeys)
		})
	}
}

func TestWithKeyFactory(t *testing.T) {
	tests := []struct {
		name       string
		keyFactory model.MasterKeyFactory
	}{
		{
			name:       "With KeyFactory",
			keyFactory: mocks.NewMockMasterKeyFactory(t),
		},
		{
			name:       "With Nil KeyFactory",
			keyFactory: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			err := WithKeyFactory(tt.keyFactory)(opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.keyFactory, opts.keyFactory)
		})
	}
}

func TestWithKeyProvider(t *testing.T) {
	tests := []struct {
		name        string
		keyProvider model.BaseKeyProvider
	}{
		{
			name:        "With KeyProvider",
			keyProvider: mocks.NewMockKeyProvider(t),
		},
		{
			name:        "With Nil KeyProvider",
			keyProvider: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			err := WithKeyProvider(tt.keyProvider)(opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.keyProvider, opts.keyProvider)
		})
	}
}
