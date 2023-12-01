// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDataKey_KeyProvider(t *testing.T) {
	tests := []struct {
		name string
		dk   DataKey
		want KeyMeta
	}{
		{
			name: "Empty KeyMeta",
			dk:   DataKey{},
			want: KeyMeta{},
		},
		{
			name: "Valid KeyMeta",
			dk:   DataKey{provider: KeyMeta{ProviderID: "aws", KeyID: "key123"}},
			want: KeyMeta{ProviderID: "aws", KeyID: "key123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.KeyProvider()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDataKey_KeyID(t *testing.T) {
	tests := []struct {
		name string
		dk   DataKey
		want string
	}{
		{
			name: "Empty KeyID",
			dk:   DataKey{},
			want: "",
		},
		{
			name: "Valid KeyID",
			dk:   DataKey{provider: KeyMeta{KeyID: "key123"}},
			want: "key123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.KeyID()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDataKey_EncryptedDataKey(t *testing.T) {
	tests := []struct {
		name string
		dk   DataKey
		want []byte
	}{
		{
			name: "Empty EncryptedDataKey",
			dk:   DataKey{},
			want: nil,
		},
		{
			name: "Non-Empty EncryptedDataKey",
			dk:   DataKey{encryptedDataKey: []byte{0x1, 0x2, 0x3}},
			want: []byte{0x1, 0x2, 0x3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.EncryptedDataKey()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDataKey_DataKey(t *testing.T) {
	tests := []struct {
		name string
		dk   DataKey
		want []byte
	}{
		{
			name: "Empty DataKey",
			dk:   DataKey{},
			want: nil,
		},
		{
			name: "Non-Empty DataKey",
			dk:   DataKey{dataKey: []byte{0x1, 0x2, 0x3}},
			want: []byte{0x1, 0x2, 0x3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.DataKey()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewEncryptedDataKey(t *testing.T) {
	type args struct {
		provider         KeyMeta
		encryptedDataKey []byte
	}
	tests := []struct {
		name string
		args args
		want *EncryptedDataKey
	}{
		{
			name: "Empty DataKey",
			args: args{
				provider:         KeyMeta{},
				encryptedDataKey: []byte{},
			},
			want: &EncryptedDataKey{
				provider:         KeyMeta{},
				encryptedDataKey: []byte{},
			},
		},
		{
			name: "Empty DataKey nil EDK",
			args: args{
				provider:         KeyMeta{},
				encryptedDataKey: nil,
			},
			want: &EncryptedDataKey{
				provider:         KeyMeta{},
				encryptedDataKey: nil,
			},
		},
		{
			name: "Valid DataKey",
			args: args{
				provider:         KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
				encryptedDataKey: []byte{1, 2, 3},
			},
			want: &EncryptedDataKey{
				provider:         KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
				encryptedDataKey: []byte{1, 2, 3},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewEncryptedDataKey(tt.args.provider, tt.args.encryptedDataKey), "NewEncryptedDataKey(%v, %v)", tt.args.provider, tt.args.encryptedDataKey)
		})
	}
}

func TestNewDataKey(t *testing.T) {
	type args struct {
		provider         KeyMeta
		dataKey          []byte
		encryptedDataKey []byte
	}
	tests := []struct {
		name string
		args args
		want *DataKey
	}{
		{
			name: "Empty DataKey",
			args: args{
				provider:         KeyMeta{},
				encryptedDataKey: []byte{},
				dataKey:          []byte{},
			},
			want: &DataKey{
				provider:         KeyMeta{},
				encryptedDataKey: []byte{},
				dataKey:          []byte{},
			},
		},
		{
			name: "Empty DataKey nil EDK",
			args: args{
				provider:         KeyMeta{},
				encryptedDataKey: nil,
				dataKey:          nil,
			},
			want: &DataKey{
				provider:         KeyMeta{},
				encryptedDataKey: nil,
				dataKey:          nil,
			},
		},
		{
			name: "Valid DataKey",
			args: args{
				provider:         KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
				encryptedDataKey: []byte{1, 2, 3},
				dataKey:          []byte{1, 2, 3},
			},
			want: &DataKey{
				provider:         KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
				encryptedDataKey: []byte{1, 2, 3},
				dataKey:          []byte{1, 2, 3},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewDataKey(tt.args.provider, tt.args.dataKey, tt.args.encryptedDataKey), "NewDataKey(%v, %v, %v)", tt.args.provider, tt.args.dataKey, tt.args.encryptedDataKey)
		})
	}
}

func TestEncryptedDataKey_KeyProvider(t *testing.T) {
	tests := []struct {
		name string
		dk   EncryptedDataKey
		want KeyMeta
	}{
		{
			name: "Empty KeyMeta",
			dk:   EncryptedDataKey{},
			want: KeyMeta{},
		},
		{
			name: "Valid KeyMeta",
			dk:   EncryptedDataKey{provider: KeyMeta{ProviderID: "aws", KeyID: "key123"}},
			want: KeyMeta{ProviderID: "aws", KeyID: "key123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.KeyProvider()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEncryptedDataKey_KeyID(t *testing.T) {
	tests := []struct {
		name string
		dk   EncryptedDataKey
		want string
	}{
		{
			name: "Empty KeyID",
			dk:   EncryptedDataKey{},
			want: "",
		},
		{
			name: "Valid KeyID",
			dk:   EncryptedDataKey{provider: KeyMeta{KeyID: "key123"}},
			want: "key123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.KeyID()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEncryptedDataKey_EncryptedDataKey(t *testing.T) {
	tests := []struct {
		name string
		dk   EncryptedDataKey
		want []byte
	}{
		{
			name: "Empty EncryptedDataKey",
			dk:   EncryptedDataKey{},
			want: nil,
		},
		{
			name: "Non-Empty EncryptedDataKey",
			dk:   EncryptedDataKey{encryptedDataKey: []byte{0x1, 0x2, 0x3}},
			want: []byte{0x1, 0x2, 0x3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dk.EncryptedDataKey()
			assert.Equal(t, tt.want, got)
		})
	}
}
