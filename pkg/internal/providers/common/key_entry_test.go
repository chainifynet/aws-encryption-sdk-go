// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestKeyEntry_GetEntry(t *testing.T) {
	mockMasterKey := mocks.NewMockMasterKey(t)
	tests := []struct {
		name string
		ke   KeyEntry[model.MasterKey]
		want model.MasterKey
	}{
		{
			name: "Get valid entry",
			ke:   KeyEntry[model.MasterKey]{Entry: mockMasterKey},
			want: mockMasterKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ke.GetEntry()
			assert.NotNil(t, got)
			assert.Equal(t, tt.want, got)
			assert.IsType(t, tt.want, got)
			assert.Same(t, tt.want, got)
		})
	}
}

func TestNewKeyEntry(t *testing.T) {
	mockMasterKey := mocks.NewMockMasterKey(t)
	tests := []struct {
		name string
		key  model.MasterKey
		want KeyEntry[model.MasterKey]
	}{
		{
			name: "KeyEntry with valid key",
			key:  mockMasterKey,
			want: KeyEntry[model.MasterKey]{Entry: mockMasterKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ke := NewKeyEntry(tt.key)
			assert.NotNil(t, ke)
			assert.Equal(t, tt.want, ke)
			assert.IsType(t, tt.want, ke)
		})
	}
}

func TestNewKeyEntryPtr(t *testing.T) {
	mockMasterKey := mocks.NewMockMasterKey(t)
	tests := []struct {
		name string
		key  model.MasterKey
		want *KeyEntry[model.MasterKey]
	}{
		{
			name: "pointer KeyEntry",
			key:  mockMasterKey,
			want: &KeyEntry[model.MasterKey]{Entry: mockMasterKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kePtr := NewKeyEntryPtr(tt.key)
			assert.NotNil(t, kePtr)
			assert.Equal(t, tt.want, kePtr)
			assert.IsType(t, tt.want, kePtr)
			assert.NotSame(t, tt.want, kePtr)
		})
	}
}
