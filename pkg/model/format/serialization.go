// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"bytes"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type Deserializer interface {
	DeserializeHeader(buf *bytes.Buffer, maxEncryptedDataKeys int) (MessageHeader, MessageHeaderAuth, error)
	DeserializeBody(buf *bytes.Buffer, algorithm *suite.AlgorithmSuite, frameLen int) (MessageBody, error)
	DeserializeFooter(alg *suite.AlgorithmSuite, buf *bytes.Buffer) (MessageFooter, error)
}

type Serializer interface {
	SerializeHeader(p HeaderParams) (MessageHeader, error)
	SerializeHeaderAuth(v suite.MessageFormatVersion, iv, authData []byte) (MessageHeaderAuth, error)
	SerializeBody(alg *suite.AlgorithmSuite, frameLength int) (MessageBody, error)
	SerializeFooter(alg *suite.AlgorithmSuite, signature []byte) (MessageFooter, error)
}
