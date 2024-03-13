// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package wrappingkey_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/serialization/wrappingkey"
)

func TestWrappingKey_SerializeEncryptedDataKey(t *testing.T) {
	var tests = []struct {
		name         string
		encryptedKey []byte
		tag          []byte
		iv           []byte
		want         []byte
	}{
		{
			name:         "empty slices",
			encryptedKey: []byte{},
			tag:          []byte{},
			iv:           []byte{},
			want:         []byte{},
		},
		{
			name:         "non-empty slices",
			encryptedKey: []byte{0x01, 0x02},
			tag:          []byte{0x03},
			iv:           []byte{0x04, 0x05},
			want:         []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name:         "realistic lengths",
			encryptedKey: []byte("encrypted_key_here_encrypted_key"),
			tag:          []byte("tag_here_tag_tag"),
			iv:           []byte("iv_here_here"),
			want:         append(append([]byte("encrypted_key_here_encrypted_key"), []byte("tag_here_tag_tag")...), []byte("iv_here_here")...),
		},
		{
			name:         "uneven lengths",
			encryptedKey: []byte{0x01, 0x02, 0x03},
			tag:          []byte{0x04},
			iv:           []byte{0x05, 0x06, 0x07, 0x08},
			want:         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wk := wrappingkey.WrappingKey{}
			got := wk.SerializeEncryptedDataKey(tt.encryptedKey, tt.tag, tt.iv)
			assert.Equal(t, tt.want, got, "Serialized output should match the wanted output")
		})
	}
}

func TestWrappingKey_DeserializeEncryptedDataKey(t *testing.T) {
	var tests = []struct {
		name    string
		input   []byte
		iVLen   int
		wantKey []byte
		wantIV  []byte
	}{
		{
			name:    "empty slice",
			input:   []byte{},
			iVLen:   0,
			wantKey: []byte{},
			wantIV:  []byte{},
		},
		{
			name:    "non-empty slice",
			input:   []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			iVLen:   2,
			wantKey: []byte{0x01, 0x02, 0x03},
			wantIV:  []byte{0x04, 0x05},
		},
		{
			name:    "realistic lengths",
			input:   append(append([]byte("encrypted_key_here_encrypted_key"), []byte("tag_here_tag_tag")...), []byte("iv_here_here")...),
			iVLen:   12,
			wantKey: []byte("encrypted_key_here_encrypted_keytag_here_tag_tag"),
			wantIV:  []byte("iv_here_here"),
		},
		{
			name:    "all zeros",
			input:   make([]byte, 100), // 100-byte slice initialized to zeroes
			iVLen:   16,
			wantKey: make([]byte, 84), // 84-byte slice of zeroes
			wantIV:  make([]byte, 16), // 16-byte slice of zeroes
		},
		{
			name:    "realistic zeros",
			input:   make([]byte, 60), // 60-byte slice initialized to zeroes
			iVLen:   12,
			wantKey: make([]byte, 48), // 48-byte slice of zeroes
			wantIV:  make([]byte, 12), // 12-byte slice of zeroes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wk := wrappingkey.WrappingKey{}
			gotKey, gotIV := wk.DeserializeEncryptedDataKey(tt.input, tt.iVLen)
			assert.Equal(t, tt.wantKey, gotKey, "Decrypted key should match the wanted key")
			assert.Equal(t, tt.wantIV, gotIV, "IV should match the wanted IV")
		})
	}
}

func TestWrappingKey_SerializeKeyInfoPrefix(t *testing.T) {
	type args struct {
		keyID string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"empty keyID", args{""}, []byte{0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0c}},
		{"rawMK1", args{"rawMK1"}, []byte{0x72, 0x61, 0x77, 0x4d, 0x4b, 0x31, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0c}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wk := wrappingkey.WrappingKey{}
			assert.Equalf(t, tt.want, wk.SerializeKeyInfoPrefix(tt.args.keyID), "SerializeKeyInfoPrefix(%v)", tt.args.keyID)
		})
	}
}
