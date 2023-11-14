// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	b64 "encoding/base64"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto/hasher"
)

func TestNewECCVerifier(t *testing.T) {
	mockNilHash := func() hash.Hash { return nil }
	type args struct {
		hashFn func() hash.Hash
		c      elliptic.Curve
	}
	tests := []struct {
		name string
		args args
		want *ECCVerifier
	}{
		{"nil", args{mockNilHash, nil}, &ECCVerifier{hasher.NewECCHasher(mockNilHash, nil), nil}},
		{"nil_P256", args{mockNilHash, elliptic.P256()}, &ECCVerifier{hasher.NewECCHasher(mockNilHash, elliptic.P256()), nil}},
		{"nil_P384", args{mockNilHash, elliptic.P384()}, &ECCVerifier{hasher.NewECCHasher(mockNilHash, elliptic.P384()), nil}},
		{"sha512_384_P384", args{sha512.New384, elliptic.P384()}, &ECCVerifier{hasher.NewECCHasher(sha512.New384, elliptic.P384()), nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewECCVerifier(tt.args.hashFn, tt.args.c), "NewECCVerifier(%v, %v)", tt.args.hashFn(), tt.args.c)
		})
	}
}

func TestECCVerifier_LoadECCKey(t *testing.T) {
	mockP384Key, _ := b64.StdEncoding.DecodeString("Az94dQ1SfEDGjWafOC49z7LnoI5qB/k6yr7Bdk1CTJe3WXTAcSLfBl+DWTr76/gatA==")
	mockNilHash := func() hash.Hash { return nil }
	type fields struct {
		Hasher hasher.Hasher
		key    *ecdsa.PublicKey
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		wantErrStr string
		wantPanic  bool
	}{
		{"nil", fields{hasher.NewECCHasher(mockNilHash, nil), nil}, args{nil}, true, "verification key is empty", false},
		{"key_exists", fields{hasher.NewECCHasher(mockNilHash, nil), &ecdsa.PublicKey{}}, args{[]byte("key")}, true, "key already exists", false},
		{"nil_curve", fields{hasher.NewECCHasher(mockNilHash, nil), nil}, args{[]byte("key")}, false, "", true},
		{"invalid_P384_key", fields{hasher.NewECCHasher(mockNilHash, elliptic.P384()), nil}, args{[]byte("key")}, true, "key not on the curve", false},
		{"valid_P384_key", fields{hasher.NewECCHasher(mockNilHash, elliptic.P384()), nil}, args{mockP384Key}, false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &ECCVerifier{
				Hasher: tt.fields.Hasher,
				key:    tt.fields.key,
			}
			if tt.wantPanic {
				assert.Panics(t, func() { _ = v.LoadECCKey(tt.args.data) })
				return
			}
			err := v.LoadECCKey(tt.args.data)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrSignVerification)
				assert.ErrorContains(t, err, tt.wantErrStr)
				require.Error(t, err)
				return
			}
			assert.NoError(t, err)
			x, y := elliptic.UnmarshalCompressed(v.Curve(), tt.args.data)
			wantKey := &ecdsa.PublicKey{
				Curve: v.Curve(),
				X:     x,
				Y:     y,
			}
			assert.Equal(t, wantKey, v.key)
		})
	}
}
