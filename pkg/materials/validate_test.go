// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func Test_validateCachingParams(t *testing.T) {
	tests := []struct {
		name    string
		cache   model.Cache
		primary model.MasterKeyProvider
		cmm     model.CryptoMaterialsManager
		wantErr bool
		errStr  string
	}{
		{"nil cache, nil primary, nil cmm", nil, nil, nil, true, "cache is nil"},
		{"nil cache, nil cmm", nil, mocks.NewMockMasterKeyProvider(t), nil, true, "cache is nil"},
		{"nil cache", nil, mocks.NewMockMasterKeyProvider(t), mocks.NewMockCryptoMaterialsManager(t), true, "cache is nil"},
		{"nil primary, nil cmm", mocks.NewMockCache(t), nil, nil, true, "primary MasterKeyProvider nil"},
		{"nil cmm", mocks.NewMockCache(t), mocks.NewMockMasterKeyProvider(t), nil, false, ""},
		{"nil primary", mocks.NewMockCache(t), nil, mocks.NewMockCryptoMaterialsManager(t), false, ""},
		{"valid cache and primary", mocks.NewMockCache(t), mocks.NewMockMasterKeyProvider(t), nil, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CachingOptions{
				Manager: tt.cmm,
			}
			got := validateCachingParams(tt.cache, tt.primary, opts)
			if tt.wantErr {
				assert.Error(t, got)
				assert.ErrorContains(t, got, tt.errStr)
			} else {
				assert.NoError(t, got)
				assert.Nil(t, got)
			}
		})
	}
}
