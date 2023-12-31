// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"hash"

	"github.com/rs/zerolog/log"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto/hasher"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

var (
	ErrSigning = errors.New("sign error")
)

type Signer interface {
	hasher.Hasher
	Sign() ([]byte, error)
}

type ECCSigner struct {
	hasher.Hasher
	signLen int
	key     *ecdsa.PrivateKey
}

var _ Signer = (*ECCSigner)(nil)

func NewECCSigner(hashFn func() hash.Hash, c elliptic.Curve, signLen int, key *ecdsa.PrivateKey) *ECCSigner {
	return &ECCSigner{
		Hasher:  hasher.NewECCHasher(hashFn, c),
		signLen: signLen,
		key:     key,
	}
}

func (s *ECCSigner) Sign() ([]byte, error) {
	var signature []byte
	for {
		// can be replaced with:
		// sig, err := cs.key.Sign(rand.Reader, finalHash, nil)
		sig, err := ecdsa.SignASN1(rand.Reader, s.key, s.Sum())
		if err != nil {
			return nil, fmt.Errorf("signASN1: %w", errors.Join(ErrSigning, err))
		}
		if len(sig) == s.signLen {
			signature = sig
			break
		}
		log.Trace().Int("expectedLen", s.signLen).
			Int("actualLen", len(sig)).
			Msg("sign is not desired length. recalculating")
		continue
	}
	return signature, nil
}
