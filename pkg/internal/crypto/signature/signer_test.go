// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	randpkg "crypto/rand"
	"hash"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	hashermocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/internal_/crypto/hasher"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/hasher"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

func TestNewECCSigner(t *testing.T) {
	mockNilHash := func() hash.Hash { return nil }
	type args struct {
		hashFn  func() hash.Hash
		c       elliptic.Curve
		signLen int
		key     *ecdsa.PrivateKey
	}
	tests := []struct {
		name string
		args args
		want *ECCSigner
	}{
		{"nil", args{mockNilHash, nil, 0, nil}, &ECCSigner{hasher.NewECCHasher(mockNilHash, nil), 0, nil}},
		{"nil_P256", args{mockNilHash, elliptic.P256(), 71, nil}, &ECCSigner{hasher.NewECCHasher(mockNilHash, elliptic.P256()), 71, nil}},
		{"nil_P384", args{mockNilHash, elliptic.P384(), 103, nil}, &ECCSigner{hasher.NewECCHasher(mockNilHash, elliptic.P384()), 103, nil}},
		{"P384", args{mockNilHash, elliptic.P384(), 103, &ecdsa.PrivateKey{}}, &ECCSigner{hasher.NewECCHasher(mockNilHash, elliptic.P384()), 103, &ecdsa.PrivateKey{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewECCSigner(tt.args.hashFn, tt.args.c, tt.args.signLen, tt.args.key), "NewECCSigner(%v, %v, %v, %v)", tt.args.hashFn, tt.args.c, tt.args.signLen, tt.args.key)
		})
	}
}

type errorReader struct{}

func (r errorReader) Read(_ []byte) (n int, err error) {
	return 0, assert.AnError
}

func TestECCSigner_Sign(t *testing.T) {
	type mocksParams struct {
		hasher *hashermocks.MockHasher
	}
	tests := []struct {
		name        string
		setupMocks  func(t *testing.T, m mocksParams)
		curve       elliptic.Curve
		reader      io.Reader
		signLen     int
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Valid",
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hasher.EXPECT().Sum().Return([]byte{0x01})
				m.hasher.EXPECT().Sum().Return([]byte{0x02})
			},
			curve:   elliptic.P384(),
			reader:  randpkg.Reader,
			signLen: 104,
		},
		{
			name: "Valid",
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hasher.EXPECT().Sum().Return([]byte{0x01})
				m.hasher.EXPECT().Sum().Return([]byte{0x02})
			},
			curve:   elliptic.P256(),
			reader:  randpkg.Reader,
			signLen: 71,
		},
		{
			name: "Sign Error",
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hasher.EXPECT().Sum().Return([]byte{0x01}).Once()
			},
			curve:       elliptic.P384(),
			reader:      errorReader{},
			signLen:     0,
			wantErr:     true,
			wantErrStr:  "signASN1",
			wantErrType: ErrSigning,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				rand.Reader = randpkg.Reader
			}()
			rand.Reader = tt.reader

			h := hashermocks.NewMockHasher(t)

			priv, _ := ecdsa.GenerateKey(tt.curve, randpkg.Reader)

			tt.setupMocks(t, mocksParams{
				hasher: h,
			})
			s := &ECCSigner{
				Hasher:  h,
				signLen: tt.signLen,
				key:     priv,
			}
			got, err := s.Sign()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Len(t, got, tt.signLen)

				got2, err2 := s.Sign()
				assert.NoError(t, err2)
				assert.Len(t, got2, tt.signLen)
				// make sure that two signatures are different
				assert.NotEqual(t, got, got2)
			}
		})
	}
}
