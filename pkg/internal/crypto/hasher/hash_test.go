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
