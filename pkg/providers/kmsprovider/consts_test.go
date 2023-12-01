// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProviderType_String(t *testing.T) {
	tests := []struct {
		name     string
		provider ProviderType
		want     string
	}{
		{
			name:     "Strict KMS Provider",
			provider: StrictKmsProvider,
			want:     "StrictKmsProvider",
		},
		{
			name:     "MRK-Aware Strict KMS Provider",
			provider: MrkAwareStrictKmsProvider,
			want:     "MrkAwareStrictKmsProvider",
		},
		{
			name:     "Discovery KMS Provider",
			provider: DiscoveryKmsProvider,
			want:     "DiscoveryKmsProvider",
		},
		{
			name:     "MRK-Aware Discovery KMS Provider",
			provider: MrkAwareDiscoveryKmsProvider,
			want:     "MrkAwareDiscoveryKmsProvider",
		},
		{
			name:     "Unknown Provider",
			provider: ProviderType(99),
			want:     "UnknownKmsProvider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.provider.String())
		})
	}
}
