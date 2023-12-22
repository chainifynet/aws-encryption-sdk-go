// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
)

type mockProvider struct {
	model.MasterKeyProvider
	ID   string
	Kind types.ProviderKind
}

func (mock *mockProvider) ProviderID() string {
	return mock.ID
}

func (mock *mockProvider) ProviderKind() types.ProviderKind {
	return mock.Kind
}

func TestNewDefault(t *testing.T) {
	tests := []struct {
		name    string
		primary model.MasterKeyProvider
		extra   []model.MasterKeyProvider
		wantErr bool
	}{
		{
			name:    "Test with no extra providers",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra:   []model.MasterKeyProvider{},
			wantErr: false,
		},
		{
			name:    "Test with extra providers with no duplicates",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra: []model.MasterKeyProvider{
				&mockProvider{ID: "provider2", Kind: types.Raw},
				&mockProvider{ID: "provider3", Kind: types.AwsKms},
			},
			wantErr: false,
		},
		{
			name:    "Test with extra Raw type providers having same ID",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra: []model.MasterKeyProvider{
				&mockProvider{ID: "provider2", Kind: types.Raw},
				&mockProvider{ID: "provider2", Kind: types.Raw},
			},
			wantErr: true,
		},
		{
			name:    "Test with primary and extra Raw type providers having same ID",
			primary: &mockProvider{ID: "provider1", Kind: types.AwsKms},
			extra: []model.MasterKeyProvider{
				&mockProvider{ID: "provider1", Kind: types.Raw},
				&mockProvider{ID: "provider2", Kind: types.AwsKms},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := materials.NewDefault(tt.primary, tt.extra...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}
