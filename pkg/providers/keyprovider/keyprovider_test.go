// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
)

func TestNewKeyProvider(t *testing.T) {
	type args struct {
		providerID    string
		providerKind  types.ProviderKind
		vendOnDecrypt bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Raw Key Provider",
			args: args{
				providerID:    "raw",
				providerKind:  types.Raw,
				vendOnDecrypt: false,
			},
		},
		{
			name: "KMS Key Provider without discovery",
			args: args{
				providerID:    types.KmsProviderID,
				providerKind:  types.AwsKms,
				vendOnDecrypt: false,
			},
		},
		{
			name: "KMS Key Provider with discovery",
			args: args{
				providerID:    types.KmsProviderID,
				providerKind:  types.AwsKms,
				vendOnDecrypt: true,
			},
		},
		{
			name: "Custom Key Provider",
			args: args{
				providerID:    "myprovider",
				providerKind:  types.Custom,
				vendOnDecrypt: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewKeyProvider(tt.args.providerID, tt.args.providerKind, tt.args.vendOnDecrypt)
			assert.IsType(t, &keyprovider.KeyProvider{}, got)

			assert.Equal(t, tt.args.providerID, got.ID())
			assert.Equal(t, tt.args.providerKind, got.Kind())
			assert.Equal(t, tt.args.vendOnDecrypt, got.VendOnDecrypt())
		})
	}
}
