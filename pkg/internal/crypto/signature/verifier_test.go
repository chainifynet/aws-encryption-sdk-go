// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	randpkg "crypto/rand"
	"crypto/sha512"
	b64 "encoding/base64"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hashermocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/internal_/crypto/hasher"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/hasher"
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

func TestECCVerifier_Verify(t *testing.T) {
	type mocksParams struct {
		hasher *hashermocks.MockHasher
		priv   *ecdsa.PrivateKey
	}
	tests := []struct {
		name        string
		setupMocks  func(t *testing.T, m mocksParams) []byte
		curve       elliptic.Curve
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Valid P384",
			setupMocks: func(t *testing.T, m mocksParams) []byte {
				m.hasher.EXPECT().Sum().Return([]byte{0x01}).Twice()
				sig, err := ecdsa.SignASN1(randpkg.Reader, m.priv, m.hasher.Sum())
				require.NoError(t, err)
				return sig
			},
			curve:   elliptic.P384(),
			wantErr: false,
		},
		{
			name: "Valid P256",
			setupMocks: func(t *testing.T, m mocksParams) []byte {
				m.hasher.EXPECT().Sum().Return([]byte{0x02}).Twice()
				sig, err := ecdsa.SignASN1(randpkg.Reader, m.priv, m.hasher.Sum())
				require.NoError(t, err)
				return sig
			},
			curve:   elliptic.P256(),
			wantErr: false,
		},
		{
			name: "Invalid Signature",
			setupMocks: func(t *testing.T, m mocksParams) []byte {
				m.hasher.EXPECT().Sum().Return([]byte{0x03}).Once()
				return []byte("invalid signature")
			},
			curve:       elliptic.P256(),
			wantErr:     true,
			wantErrStr:  "signature not valid",
			wantErrType: ErrSignVerification,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := hashermocks.NewMockHasher(t)

			privKey, err := ecdsa.GenerateKey(tt.curve, randpkg.Reader)
			require.NoError(t, err)

			sign := tt.setupMocks(t, mocksParams{
				hasher: h,
				priv:   privKey,
			})

			v := &ECCVerifier{
				Hasher: h,
				key:    &privKey.PublicKey,
			}

			err = v.Verify(sign)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.ErrorIs(t, err, tt.wantErrType)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
