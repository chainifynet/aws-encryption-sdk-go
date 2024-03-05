// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"

	hashmocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/hash"
)

func TestNewECCHasher(t *testing.T) {
	type args struct {
		hashFn func() hash.Hash
		c      elliptic.Curve
	}
	tests := []struct {
		name string
		args args
		want *ECCHasher
	}{
		{"nil", args{func() hash.Hash { return nil }, nil}, &ECCHasher{nil, nil}},
		{"nil_P256", args{func() hash.Hash { return nil }, elliptic.P256()}, &ECCHasher{nil, elliptic.P256()}},
		{"nil_P384", args{func() hash.Hash { return nil }, elliptic.P384()}, &ECCHasher{nil, elliptic.P384()}},
		{"sha256_P256", args{sha256.New, elliptic.P256()}, &ECCHasher{sha256.New(), elliptic.P256()}},
		{"sha512_384_P384", args{sha512.New384, elliptic.P384()}, &ECCHasher{sha512.New384(), elliptic.P384()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewECCHasher(tt.args.hashFn, tt.args.c), "NewECCHasher(%v, %v)", tt.args.hashFn(), tt.args.c)
		})
	}
}

func TestECCHasher_Curve(t *testing.T) {
	type fields struct {
		curve elliptic.Curve
	}
	tests := []struct {
		name   string
		fields fields
		want   elliptic.Curve
	}{
		{"nil", fields{nil}, nil},
		{"P256", fields{elliptic.P256()}, elliptic.P256()},
		{"P384", fields{elliptic.P384()}, elliptic.P384()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &ECCHasher{
				curve: tt.fields.curve,
			}
			assert.Equalf(t, tt.want, h.Curve(), "Curve()")
		})
	}
}

func TestECCHasher_Sum(t *testing.T) {
	type mocksParams struct {
		hash *hashmocks.MockHash
	}
	tests := []struct {
		name       string
		setupMocks func(t *testing.T, m mocksParams)
		want       []byte
	}{
		{
			name: "nil hash",
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hash.EXPECT().Sum([]byte(nil)).Return([]byte(nil)).Once()
			},
			want: []byte(nil),
		},
		{
			name: "valid hash",
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hash.EXPECT().Sum([]byte(nil)).Return([]byte("some hash")).Once()
			},
			want: []byte("some hash"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashMock := hashmocks.NewMockHash(t)
			tt.setupMocks(t, mocksParams{hash: hashMock})

			h := &ECCHasher{
				hasher: hashMock,
			}
			assert.Equal(t, tt.want, h.Sum())
		})
	}
}

func TestECCHasher_Write(t *testing.T) {
	type mocksParams struct {
		hash *hashmocks.MockHash
	}
	tests := []struct {
		name        string
		input       []byte
		setupMocks  func(t *testing.T, m mocksParams)
		want        int
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name:  "Success Hash Write",
			input: []byte("some data"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hash.EXPECT().Write([]byte("some data")).Return(9, nil).Once()
			},
			want:    9,
			wantErr: false,
		},
		{
			name:  "Hash Write Error",
			input: []byte("other data"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.hash.EXPECT().Write([]byte("other data")).
					Return(0, assert.AnError).Once()
			},
			want:        0,
			wantErr:     true,
			wantErrStr:  "hasher write",
			wantErrType: assert.AnError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashMock := hashmocks.NewMockHash(t)
			tt.setupMocks(t, mocksParams{hash: hashMock})

			h := &ECCHasher{
				hasher: hashMock,
			}

			got, err := h.Write(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.ErrorIs(t, err, tt.wantErrType)
				assert.Equal(t, tt.want, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
