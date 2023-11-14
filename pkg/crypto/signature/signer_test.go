// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto/hasher"
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
