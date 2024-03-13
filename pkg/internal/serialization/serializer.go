// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type Serializer struct{}

func NewSerializer() format.Serializer {
	return &Serializer{}
}

func (s *Serializer) SerializeHeader(p format.HeaderParams) (format.MessageHeader, error) {
	return newHeader(p)
}

func (s *Serializer) SerializeHeaderAuth(v suite.MessageFormatVersion, iv, authData []byte) (format.MessageHeaderAuth, error) {
	return newHeaderAuth(v, iv, authData)
}

func (s *Serializer) SerializeBody(alg *suite.AlgorithmSuite, frameLength int) (format.MessageBody, error) {
	return newBody(alg, frameLength)
}

func (s *Serializer) SerializeFooter(alg *suite.AlgorithmSuite, signature []byte) (format.MessageFooter, error) {
	return newFooter(alg, signature)
}
