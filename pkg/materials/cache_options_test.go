// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestWithAdditionalProviders(t *testing.T) {
	tests := []struct {
		name       string
		providers  []model.MasterKeyProvider
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "nil providers",
			providers:  nil,
			wantErr:    true,
			wantErrStr: "providers must present",
		},
		{
			name:       "no providers",
			providers:  []model.MasterKeyProvider{},
			wantErr:    true,
			wantErrStr: "providers must present",
		},
		{
			name:      "one provider",
			providers: []model.MasterKeyProvider{mocks.NewMockMasterKeyProvider(t)},
			wantErr:   false,
		},
		{
			name:      "multiple providers",
			providers: []model.MasterKeyProvider{mocks.NewMockMasterKeyProvider(t), mocks.NewMockMasterKeyProvider(t)},
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &materials.CachingOptions{}
			err := materials.WithAdditionalProviders(tt.providers...)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.providers, opts.AdditionalProviders)
			}
		})
	}
}

func TestWithMaterialsManager(t *testing.T) {
	tests := []struct {
		name       string
		cmm        model.CryptoMaterialsManager
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "nil cmm",
			cmm:        nil,
			wantErr:    true,
			wantErrStr: "cmm must present",
		},
		{
			name:    "non-nil cmm",
			cmm:     mocks.NewMockCryptoMaterialsManager(t),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &materials.CachingOptions{}
			err := materials.WithMaterialsManager(tt.cmm)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.Nil(t, opts.Manager)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.cmm, opts.Manager)
			}
		})
	}
}

func TestWithKeyHasher(t *testing.T) {
	tests := []struct {
		name        string
		keyHasherFn model.KeyHasherFunc
		wantErr     bool
		wantErrStr  string
	}{
		{
			name:        "nil keyHasher",
			keyHasherFn: nil,
			wantErr:     true,
			wantErrStr:  "keyHasher must present",
		},
		{
			name:        "non-nil keyHasher",
			keyHasherFn: func() model.CacheHasher { return mocks.NewMockCacheHasher(t) },
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &materials.CachingOptions{}
			err := materials.WithKeyHasher(tt.keyHasherFn)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.Nil(t, opts.KeyHasherFn)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, opts.KeyHasherFn)
				assert.Equal(t, tt.keyHasherFn(), opts.KeyHasherFn())
			}
		})
	}
}

func TestWithMaxAge(t *testing.T) {
	tests := []struct {
		name       string
		maxAge     time.Duration
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "negative maxAge",
			maxAge:     -1 * time.Second,
			wantErr:    true,
			wantErrStr: "maxAge cannot be less than or equal to 0",
		},
		{
			name:       "zero maxAge",
			maxAge:     0,
			wantErr:    true,
			wantErrStr: "maxAge cannot be less than or equal to 0",
		},
		{
			name:    "positive maxAge",
			maxAge:  10 * time.Second,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &materials.CachingOptions{}
			err := materials.WithMaxAge(tt.maxAge)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.maxAge, opts.MaxAge)
			}
		})
	}
}

func TestWithMaxMessages(t *testing.T) {
	tests := []struct {
		name        string
		maxMessages uint64
		wantErr     bool
		wantErrStr  string
	}{
		{
			name:        "zero maxMessages",
			maxMessages: 0,
			wantErr:     true,
			wantErrStr:  "maxMessages cannot be less than 1",
		},
		{
			name:        "one maxMessages",
			maxMessages: 1,
			wantErr:     false,
		},
		{
			name:        "multiple maxMessages",
			maxMessages: 100,
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &materials.CachingOptions{}
			err := materials.WithMaxMessages(tt.maxMessages)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.maxMessages, opts.MaxMessages)
			}
		})
	}
}

func TestWithMaxBytes(t *testing.T) {
	tests := []struct {
		name       string
		maxBytes   uint64
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "zero maxBytes",
			maxBytes:   0,
			wantErr:    true,
			wantErrStr: "maxBytes cannot be less than 1",
		},
		{
			name:     "one maxBytes",
			maxBytes: 1,
			wantErr:  false,
		},
		{
			name:     "multiple maxBytes",
			maxBytes: 100,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &materials.CachingOptions{}
			err := materials.WithMaxBytes(tt.maxBytes)(opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.maxBytes, opts.MaxBytes)
			}
		})
	}
}
