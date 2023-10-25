// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"io"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

const (
	deriveKeyLabel = "DERIVEKEY"
	commitLabel    = "COMMITKEY"
	lengthCommit   = 32
)

func deriveDataEncryptionKey(dk keys.DataKeyI, alg *suite.AlgorithmSuite, messageID []byte) ([]byte, error) {
	var buf []byte
	buf = make([]byte, 0, 11) // 2 bytes AlgorithmID + 9 bytes label
	buf = append(buf, conv.FromInt.UUint16BigEndian(alg.AlgorithmID)...)
	buf = append(buf, []byte(deriveKeyLabel)...)

	kdf := alg.KDFSuite.KDFFunc(alg.KDFSuite.HashFunc, dk.DataKey(), messageID, buf)

	derivedKey := make([]byte, alg.EncryptionSuite.DataKeyLen)
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, err
	}
	return derivedKey, nil
}

func calculateCommitmentKey(dk keys.DataKeyI, alg *suite.AlgorithmSuite, messageID []byte) ([]byte, error) {
	var buf []byte
	buf = make([]byte, 0, 9) // 9 bytes commitLabel
	buf = append(buf, []byte(commitLabel)...)

	kdf := alg.KDFSuite.KDFFunc(alg.KDFSuite.HashFunc, dk.DataKey(), messageID, buf)

	commitmentKey := make([]byte, lengthCommit)
	if _, err := io.ReadFull(kdf, commitmentKey); err != nil {
		return nil, err
	}
	return commitmentKey, nil
}
