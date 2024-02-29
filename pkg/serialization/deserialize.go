// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type Deserializer struct{}

func NewDeserializer() format.Deserializer {
	return &Deserializer{}
}

func (d *Deserializer) DeserializeHeader(buf *bytes.Buffer, maxEncryptedDataKeys int) (format.MessageHeader, format.MessageHeaderAuth, error) {
	header, err := deserializeHeader(buf)
	if err != nil {
		return nil, nil, err
	}

	if errEdk := EDK.validateMinMaxEDKs(header.EncryptedDataKeyCount(), maxEncryptedDataKeys); errEdk != nil {
		return nil, nil, errEdk
	}

	authData, err := deserializeHeaderAuth(header.Version(), buf)
	if err != nil {
		return nil, nil, err
	}

	return header, authData, nil
}

func (d *Deserializer) DeserializeBody(buf *bytes.Buffer, algorithm *suite.AlgorithmSuite, frameLen int) (format.MessageBody, error) {
	return deserializeBody(algorithm, frameLen, buf)
}

func (d *Deserializer) DeserializeFooter(alg *suite.AlgorithmSuite, buf *bytes.Buffer) (format.MessageFooter, error) {
	return deserializeFooter(alg, buf)
}
