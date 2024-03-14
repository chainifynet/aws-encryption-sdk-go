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

func (d *Deserializer) DeserializeHeader(buf *bytes.Buffer, maxEDK int) (format.MessageHeader, format.MessageHeaderAuth, error) {
	header, err := deserializeHeader(buf)
	if err != nil {
		return nil, nil, err
	}

	if errEdk := EDK.validateMinMaxEDKs(header.EncryptedDataKeyCount(), maxEDK); errEdk != nil {
		return nil, nil, errEdk
	}

	authData, err := deserializeHeaderAuth(header.Version(), buf)
	if err != nil {
		return nil, nil, err
	}

	return header, authData, nil
}

func (d *Deserializer) DeserializeBody(buf *bytes.Buffer, alg *suite.AlgorithmSuite, frameLen int) (format.MessageBody, error) {
	return deserializeBody(alg, frameLen, buf)
}

func (d *Deserializer) DeserializeFooter(buf *bytes.Buffer, alg *suite.AlgorithmSuite) (format.MessageFooter, error) {
	return deserializeFooter(alg, buf)
}
