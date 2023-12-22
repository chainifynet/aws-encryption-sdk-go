// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keyderivation

import (
	"errors"
	"fmt"
	"io"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

var errKeyDerivation = errors.New("key derivation error")

const (
	deriveKeyLabel         = "DERIVEKEY" // label to calculate the derived key
	commitLabel            = "COMMITKEY" // label to calculate the commitment key
	deriveKeyKdfInfoV1Size = 18          // 2 bytes AlgorithmID(uint16) + 16 bytes messageID used in V1
	deriveKeyKdfInfoV2Size = 11          // 2 bytes AlgorithmID(uint16) + 9 bytes deriveKeyLabel label
	commitKdfInfoSize      = 9           // 9 bytes commitLabel
	lengthCommit           = 32          // used in serialization to calculate the commitment key length
)

func DeriveDataEncryptionKey(dataKey []byte, alg *suite.AlgorithmSuite, messageID []byte) ([]byte, error) {
	if err := validateInputs(dataKey, alg); err != nil {
		return nil, fmt.Errorf("validate error: %v: %w", err.Error(), errKeyDerivation)
	}

	// for algorithms that do not support KDF, the data key is the derived key
	if !alg.IsKDFSupported() {
		key := make([]byte, len(dataKey))
		copy(key, dataKey)
		return key, nil
	}

	var buf []byte
	var kdf io.Reader
	if alg.IsCommitting() {
		buf = make([]byte, 0, deriveKeyKdfInfoV2Size) // 2 bytes AlgorithmID + 9 bytes label
		buf = append(buf, conv.FromInt.UUint16BigEndian(alg.AlgorithmID)...)
		buf = append(buf, []byte(deriveKeyLabel)...)

		// hashFn, secret, salt, info
		kdf = alg.KDFSuite.KDFFunc(alg.KDFSuite.HashFunc, dataKey, messageID, buf)
	} else {
		buf = make([]byte, 0, deriveKeyKdfInfoV1Size) // 2 bytes AlgorithmID(uint16) + 16 bytes messageID
		buf = append(buf, conv.FromInt.UUint16BigEndian(alg.AlgorithmID)...)
		buf = append(buf, messageID...)

		// hashFn, secret, salt, info
		kdf = alg.KDFSuite.KDFFunc(alg.KDFSuite.HashFunc, dataKey, nil, buf)
	}

	derivedKey := make([]byte, alg.EncryptionSuite.DataKeyLen)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("derive data encryption key: %v: %w", err.Error(), errKeyDerivation)
	}
	return derivedKey, nil
}

func CalculateCommitmentKey(dataKey []byte, alg *suite.AlgorithmSuite, messageID []byte) ([]byte, error) {
	if err := validateInputs(dataKey, alg); err != nil {
		return nil, fmt.Errorf("validate error: %v: %w", err.Error(), errKeyDerivation)
	}
	var buf []byte
	buf = make([]byte, 0, commitKdfInfoSize) // 9 bytes commitLabel
	buf = append(buf, []byte(commitLabel)...)

	kdf := alg.KDFSuite.KDFFunc(alg.KDFSuite.HashFunc, dataKey, messageID, buf)

	commitmentKey := make([]byte, lengthCommit)
	if _, err := io.ReadFull(kdf, commitmentKey); err != nil {
		return nil, fmt.Errorf("calculate commitment key: %v: %w", err.Error(), errKeyDerivation)
	}
	return commitmentKey, nil
}

func validateInputs(dataKey []byte, alg *suite.AlgorithmSuite) error {
	if len(dataKey) == 0 {
		return fmt.Errorf("data key is empty")
	}
	if alg == nil {
		return fmt.Errorf("algorithm suite is nil")
	}
	if alg.IsKDFSupported() {
		if alg.KDFSuite.HashFunc == nil {
			return fmt.Errorf("hash func is nil")
		}
	}
	if alg.EncryptionSuite.DataKeyLen == 0 {
		return fmt.Errorf("data key length is invalid")
	}
	return nil
}
