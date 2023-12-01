// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func Test_masterKey_KeyID(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"key1", fields{model.KeyMeta{KeyID: "key1"}}, "key1"},
		{"key2", fields{model.KeyMeta{KeyID: "key2"}}, "key2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mk := &BaseKey{
				metadata: tt.fields.metadata,
			}
			assert.Equalf(t, tt.want, mk.KeyID(), "KeyID()")
		})
	}
}

func Test_masterKey_Metadata(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	tests := []struct {
		name   string
		fields fields
		want   model.KeyMeta
	}{
		{
			name:   "key1",
			fields: fields{model.KeyMeta{KeyID: "key1"}},
			want:   model.KeyMeta{KeyID: "key1"},
		},
		{
			name:   "key2",
			fields: fields{model.KeyMeta{ProviderID: "aws-kms", KeyID: "key2"}},
			want:   model.KeyMeta{ProviderID: "aws-kms", KeyID: "key2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mk := &BaseKey{
				metadata: tt.fields.metadata,
			}
			assert.Equalf(t, tt.want, mk.Metadata(), "Metadata()")
		})
	}
}

func Test_masterKey_OwnsDataKey(t *testing.T) {
	type fields struct {
		metadata model.KeyMeta
	}
	tests := []struct {
		name      string
		fields    fields
		mockKeyID string
		want      bool
	}{

		{"dk_key1", fields{model.KeyMeta{KeyID: "key1"}}, "key1", true},
		{"dk_key2", fields{model.KeyMeta{KeyID: "key2"}}, "key2", true},
		{"dk_key3", fields{model.KeyMeta{KeyID: "key3"}}, "key100", false},
		{"edk_1", fields{model.KeyMeta{KeyID: "edk1"}}, "edk1", true},
		{"edk_2", fields{model.KeyMeta{KeyID: "edk2"}}, "edk2", true},
		{"edk_3", fields{model.KeyMeta{KeyID: "edk3"}}, "edk200", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKey := mocks.NewMockKey(t)
			mockKey.EXPECT().KeyID().Return(tt.mockKeyID).Once()
			mk := &BaseKey{
				metadata: tt.fields.metadata,
			}
			assert.Equalf(t, tt.want, mk.OwnsDataKey(mockKey), "OwnsDataKey(%v)", mockKey)
		})
	}
}

func TestNewBaseKey(t *testing.T) {
	tests := []struct {
		name     string
		metadata model.KeyMeta
		want     BaseKey
	}{
		{
			name:     "Empty metadata",
			metadata: model.KeyMeta{},
			want:     NewBaseKey(model.KeyMeta{}),
		},
		{
			name: "Non-empty metadata with ProviderID and KeyID",
			metadata: model.KeyMeta{
				ProviderID: "Provider1",
				KeyID:      "Key1",
			},
			want: NewBaseKey(model.KeyMeta{
				ProviderID: "Provider1",
				KeyID:      "Key1",
			}),
		},
		{
			name: "Non-empty metadata with only ProviderID",
			metadata: model.KeyMeta{
				ProviderID: "Provider2",
			},
			want: NewBaseKey(model.KeyMeta{
				ProviderID: "Provider2",
			}),
		},
		{
			name: "Non-empty metadata with only KeyID",
			metadata: model.KeyMeta{
				KeyID: "Key2",
			},
			want: NewBaseKey(model.KeyMeta{
				KeyID: "Key2",
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBaseKey(tt.metadata)
			assert.Equal(t, tt.want, got)
		})
	}
}
