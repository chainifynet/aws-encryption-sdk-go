// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyMeta_Equal(t *testing.T) {
	tests := []struct {
		name string
		km   KeyMeta
		arg  KeyMeta
		want bool
	}{
		{
			name: "Equal KeyMetas",
			km:   KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
			arg:  KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
			want: true,
		},
		{
			name: "Different ProviderID",
			km:   KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
			arg:  KeyMeta{ProviderID: "azure", KeyID: "key123"},
			want: false,
		},
		{
			name: "Different KeyID",
			km:   KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
			arg:  KeyMeta{ProviderID: "aws-kms", KeyID: "key456"},
			want: false,
		},
		{
			name: "Both Fields Different",
			km:   KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
			arg:  KeyMeta{ProviderID: "azure", KeyID: "key456"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.km.Equal(tt.arg), "KeyMeta.Equal(%v, %v)", tt.km, tt.arg)
		})
	}
}

func TestKeyMeta_String(t *testing.T) {
	tests := []struct {
		name string
		km   KeyMeta
		want string
	}{
		{
			name: "Non-Empty KeyMeta",
			km:   KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
			want: "aws-kms__key123",
		},
		{
			name: "Empty KeyMeta",
			km:   KeyMeta{},
			want: "__",
		},
		{
			name: "Empty ProviderID",
			km:   KeyMeta{KeyID: "key123"},
			want: "__key123",
		},
		{
			name: "Empty KeyID",
			km:   KeyMeta{ProviderID: "aws-kms"},
			want: "aws-kms__",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.km.String(), "KeyMeta.String(%v)", tt.km)
		})
	}
}

func TestWithKeyMeta(t *testing.T) {
	tests := []struct {
		name        string
		providerID  string
		keyID       string
		wantKeyMeta KeyMeta
	}{
		{
			name:        "Both fields provided",
			providerID:  "aws-kms",
			keyID:       "key123",
			wantKeyMeta: KeyMeta{ProviderID: "aws-kms", KeyID: "key123"},
		},
		{
			name:        "Empty ProviderID",
			providerID:  "",
			keyID:       "key123",
			wantKeyMeta: KeyMeta{ProviderID: "", KeyID: "key123"},
		},
		{
			name:        "Empty KeyID",
			providerID:  "aws-kms",
			keyID:       "",
			wantKeyMeta: KeyMeta{ProviderID: "aws-kms", KeyID: ""},
		},
		{
			name:        "Both fields empty",
			providerID:  "",
			keyID:       "",
			wantKeyMeta: KeyMeta{ProviderID: "", KeyID: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKeyMeta := WithKeyMeta(tt.providerID, tt.keyID)
			assert.Equalf(t, tt.wantKeyMeta, gotKeyMeta, "WithKeyMeta(%q, %q)", tt.providerID, tt.keyID)
		})
	}
}
