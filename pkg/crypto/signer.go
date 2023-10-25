// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"hash"

	"github.com/pkg/errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

var (
	signingErr = errors.New("sign error")
)

type signer struct {
	hasher  hash.Hash
	curve   elliptic.Curve
	signLen int
	key     *ecdsa.PrivateKey
}

func newSigner(algorithm *suite.AlgorithmSuite, signingKey *ecdsa.PrivateKey) *signer {
	return &signer{
		hasher:  algorithm.Authentication.HashFunc(),
		curve:   algorithm.Authentication.Algorithm,
		signLen: algorithm.Authentication.SignatureLen,
		key:     signingKey,
	}
}

func (cs *signer) update(b []byte) {
	if n, err := cs.hasher.Write(b); err != nil {
		log.Error().Err(err).Msg("Signer update error")
	} else {
		log.Trace().Int("written", n).Msg("Signer update")
	}
}

func (cs *signer) sign() ([]byte, error) {
	var signature []byte
	for {
		log.Trace().Msg("sign attempt")
		finalHash := cs.hasher.Sum([]byte(nil))
		sign, err := ecdsa.SignASN1(rand.Reader, cs.key, finalHash)
		if err != nil {
			return nil, fmt.Errorf("signASN1 %v, %w", err, signingErr)
		}
		if len(sign) == cs.signLen {
			signature = sign
			break
		} else {
			log.Debug().Int("expectedLen", cs.signLen).
				Int("actualLen", len(sign)).
				Msg("sign is not desired length. recalculating")
			continue
		}
	}

	log.Trace().
		Int("len", len(signature)).
		Str("bytes", logger.FmtBytes(signature)).
		Msg("generated signature")

	return signature, nil
}
