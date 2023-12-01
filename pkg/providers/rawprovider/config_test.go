// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
)

func Test_validateConfig(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		opts       *Options
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "Empty ProviderID",
			providerID: "",
			opts:       &Options{},
			wantErr:    true,
			wantErrStr: "providerID must not be empty",
		},
		{
			name:       "Reserved ProviderID",
			providerID: types.KmsProviderID,
			opts:       &Options{},
			wantErr:    true,
			wantErrStr: "providerID is reserved for AWS",
		},
		{
			name:       "Invalid Static Key",
			providerID: "raw",
			opts: &Options{
				configKeys: []staticKey{
					{keyID: "key123", key: []byte("short")},
				},
				staticKeys: make(map[string][]byte),
			},
			wantErr:    true,
			wantErrStr: "static key validation",
		},
		{
			name:       "Duplicate Static Key",
			providerID: "custom-provider",
			opts: &Options{
				configKeys: []staticKey{
					{keyID: "key123", key: make([]byte, _rawMinKeyLength)},
					{keyID: "key123", key: make([]byte, _rawMinKeyLength)},
				},
				staticKeys: make(map[string][]byte),
			},
			wantErr:    true,
			wantErrStr: "static key already exists",
		},
		{
			name:       "Empty Static Keys",
			providerID: "static-provider",
			opts: &Options{
				configKeys: []staticKey{},
				staticKeys: make(map[string][]byte),
			},
			wantErr:    true,
			wantErrStr: "no static keys provided",
		},
		{
			name:       "Invalid keyFactory",
			providerID: "custom-provider",
			opts: &Options{
				keyProvider: mocks.NewMockKeyProvider(t),
				configKeys: []staticKey{
					{keyID: "key123", key: make([]byte, _rawMinKeyLength)},
				},
				staticKeys: make(map[string][]byte),
			},
			wantErr:    true,
			wantErrStr: "keyFactory must not be nil",
		},
		{
			name:       "Invalid keyProvider",
			providerID: "custom-provider",
			opts: &Options{
				keyFactory: mocks.NewMockMasterKeyFactory(t),
				configKeys: []staticKey{
					{keyID: "key123", key: make([]byte, _rawMinKeyLength)},
				},
				staticKeys: make(map[string][]byte),
			},
			wantErr:    true,
			wantErrStr: "keyProvider must not be nil",
		},
		{
			name:       "Valid Options",
			providerID: "custom-provider",
			opts: &Options{
				keyFactory:  mocks.NewMockMasterKeyFactory(t),
				keyProvider: mocks.NewMockKeyProvider(t),
				configKeys: []staticKey{
					{keyID: "key123", key: make([]byte, _rawMinKeyLength)},
				},
				staticKeys: make(map[string][]byte),
			},
			wantErr: false,
		},
		{
			name:       "Valid Multiple Keys",
			providerID: "custom-provider",
			opts: &Options{
				keyFactory:  mocks.NewMockMasterKeyFactory(t),
				keyProvider: mocks.NewMockKeyProvider(t),
				configKeys: []staticKey{
					{keyID: "key123", key: make([]byte, _rawMinKeyLength)},
					{keyID: "key321", key: make([]byte, _rawMinKeyLength)},
				},
				staticKeys: make(map[string][]byte),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.providerID, tt.opts)
			if tt.wantErr {
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.ErrorIs(t, err, providers.ErrConfig)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.opts.configKeys), len(tt.opts.staticKeys))
			}
		})
	}
}

func Test_validateStaticKey(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		key        []byte
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "Empty KeyID",
			keyID:      "",
			key:        []byte("some-key"),
			wantErr:    true,
			wantErrStr: "static keyID must not be empty",
		},
		{
			name:       "Key Too Short",
			keyID:      "key123",
			key:        []byte("short"),
			wantErr:    true,
			wantErrStr: "static key length must be at least",
		},
		{
			name:    "Valid Key",
			keyID:   "key123",
			key:     make([]byte, _rawMinKeyLength),
			wantErr: false,
		},
		{
			name:       "Empty Key",
			keyID:      "key123",
			key:        []byte{},
			wantErr:    true,
			wantErrStr: "static key length must be at least",
		},
		{
			name:       "Nil Key",
			keyID:      "key123",
			key:        nil,
			wantErr:    true,
			wantErrStr: "static key length must be at least",
		},
		{
			name:       "Invalid Length Key",
			keyID:      "key123",
			key:        make([]byte, _rawMinKeyLength-1),
			wantErr:    true,
			wantErrStr: "static key length must be at least",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStaticKey(tt.keyID, tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_resolveKeyProvider(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		opts       *Options
		want       model.BaseKeyProvider
	}{
		{
			name:       "keyProvider not set",
			providerID: "provider1",
			opts:       &Options{},
			want:       keyprovider.NewKeyProvider("provider1", types.Raw, false),
		},
		{
			name:       "keyProvider already set",
			providerID: "provider2",
			opts: &Options{
				keyProvider: keyprovider.NewKeyProvider("existing", types.Raw, true),
			},
			want: keyprovider.NewKeyProvider("existing", types.Raw, true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveKeyProvider(tt.providerID, tt.opts)
			got := tt.opts.keyProvider
			assert.Equal(t, tt.want, got)
		})
	}
}
