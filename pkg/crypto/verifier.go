// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"hash"

	"github.com/pkg/errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var (
	VerificationErr = errors.New("verification error")
)

type verifier struct {
	hasher hash.Hash
	curve  elliptic.Curve
	key    *ecdsa.PublicKey
}

func newVerifier(algorithm *suite.AlgorithmSuite) *verifier {
	return &verifier{
		hasher: algorithm.Authentication.HashFunc(),
		curve:  algorithm.Authentication.Algorithm,
	}
}

func (cv *verifier) loadECCVerificationKey(verificationKey []byte) error {
	if cv.key != nil {
		return errors.Wrap(VerificationErr, "key already exists")
	}

	x, y := elliptic.UnmarshalCompressed(cv.curve, verificationKey)
	if x == nil {
		return errors.Wrap(VerificationErr, "X or Y is nil")
	}

	// We are using only P384 curve in suite.AlgorithmSuite
	//goland:noinspection GoDeprecation
	if ok := cv.curve.IsOnCurve(x, y); !ok {
		return errors.Wrap(VerificationErr, "X or Y not on Curve")
	}
	cv.key = &ecdsa.PublicKey{
		Curve: cv.curve,
		X:     x,
		Y:     y,
	}
	return nil
}

func (cv *verifier) update(b []byte) {
	if n, err := cv.hasher.Write(b); err != nil {
		log.Error().Err(err).Msg("Hasher update error")
	} else {
		log.Trace().Int("written", n).Msg("Hasher update")
	}
}

func (cv *verifier) verify(signature []byte) error {
	finalHash := cv.hasher.Sum([]byte(nil))
	if ok := ecdsa.VerifyASN1(cv.key, finalHash, signature); !ok {
		log.Error().Err(errors.Wrap(VerificationErr, "signature not valid")).Msg("verifier")
		return errors.Wrap(VerificationErr, "signature not valid")
	}
	return nil
}
