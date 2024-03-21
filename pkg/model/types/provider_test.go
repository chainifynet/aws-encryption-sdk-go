// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProviderType_String(t *testing.T) {
	tests := []struct {
		name     string
		provider ProviderKind
		want     string
	}{
		{
			name:     "None Provider",
			provider: _noneProvider,
			want:     "NONE",
		},
		{
			name:     "AWS KMS Provider",
			provider: AwsKms,
			want:     "AWS_KMS",
		},
		{
			name:     "Raw Provider",
			provider: Raw,
			want:     "RAW",
		},
		{
			name:     "Custom Provider",
			provider: Custom,
			want:     "CUSTOM",
		},
		{
			name:     "Unknown Provider",
			provider: ProviderKind(99),
			want:     "NONE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.provider.String())
			assert.Equal(t, tt.want, fmt.Sprintf("%#v", tt.provider))
		})
	}
}
