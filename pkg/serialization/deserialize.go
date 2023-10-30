// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

//goland:noinspection GoExportedFuncWithUnexportedType
func DeserializeHeader(buf *bytes.Buffer, maxEncryptedDataKeys int) (*MessageHeader, *headerAuth, error) { //nolint:revive
	header, err := EncryptedMessageHeader.fromBuffer(buf)
	if err != nil {
		return nil, nil, err
	}

	if errEdk := EDK.validateMinMaxEDKs(header.EncryptedDataKeyCount, maxEncryptedDataKeys); errEdk != nil {
		return nil, nil, errEdk
	}

	authData, err := MessageHeaderAuth.Deserialize(buf)
	if err != nil {
		return nil, nil, err
	}

	return header, authData, nil
}

//goland:noinspection GoExportedFuncWithUnexportedType
func DeserializeBody(buf *bytes.Buffer, algorithm *suite.AlgorithmSuite, frameLen int) (*body, error) { //nolint:revive
	if buf.Len() < frameFieldBytes {
		return nil, errors.New("malformed message")
	}
	deserializedBody, err := MessageBody.fromBuffer(algorithm, frameLen, buf)
	if err != nil {
		return nil, err
	}

	// TODO andrew move this into footer deserialize
	if algorithm.IsSigning() && buf.Len() > (lenFieldBytes+algorithm.Authentication.SignatureLen) {
		return nil, errors.New("malformed large message")
	}

	return deserializedBody, nil
}
