// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"hash"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/hasher"
)

var (
	ErrSignVerification = errors.New("verification error")
)

type Verifier interface {
	hasher.Hasher
	Verify(sig []byte) error
	LoadECCKey(data []byte) error
}

type ECCVerifier struct {
	hasher.Hasher
	key *ecdsa.PublicKey
}

var _ Verifier = (*ECCVerifier)(nil)

type VerifierFunc func(hashFn func() hash.Hash, c elliptic.Curve) Verifier

func NewECCVerifier(hashFn func() hash.Hash, c elliptic.Curve) Verifier {
	return &ECCVerifier{
		Hasher: hasher.NewECCHasher(hashFn, c),
	}
}

func (v *ECCVerifier) Verify(sig []byte) error {
	if ok := ecdsa.VerifyASN1(v.key, v.Sum(), sig); !ok {
		return fmt.Errorf("signature not valid: %w", ErrSignVerification)
	}
	return nil
}

func (v *ECCVerifier) LoadECCKey(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("verification key is empty: %w", ErrSignVerification)
	}
	if v.key != nil {
		return fmt.Errorf("key already exists: %w", ErrSignVerification)
	}
	x, y := elliptic.UnmarshalCompressed(v.Curve(), data)
	if x == nil {
		return fmt.Errorf("X is nil: key not on the curve: %w", ErrSignVerification)
	}
	v.key = &ecdsa.PublicKey{
		Curve: v.Curve(),
		X:     x,
		Y:     y,
	}
	return nil
}
