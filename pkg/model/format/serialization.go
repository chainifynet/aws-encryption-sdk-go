// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"bytes"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// Deserializer defines methods for deserializing encrypted message components.
type Deserializer interface {
	// DeserializeHeader deserializes a message header from a buffer.
	// It takes a buffer and a maximum number of encrypted data keys as input.
	// It returns a MessageHeader, MessageHeaderAuth, and an error if any.
	DeserializeHeader(buf *bytes.Buffer, maxEncryptedDataKeys int) (MessageHeader, MessageHeaderAuth, error)

	// DeserializeBody deserializes a message body from a buffer.
	// It takes a buffer, an algorithm suite, and a frame length as input.
	// It returns a MessageBody and an error if any.
	DeserializeBody(buf *bytes.Buffer, alg *suite.AlgorithmSuite, frameLen int) (MessageBody, error)

	// DeserializeFooter deserializes a message footer from a buffer.
	// It takes a buffer and an algorithm suite as input.
	// It returns a MessageFooter and an error if any.
	DeserializeFooter(buf *bytes.Buffer, alg *suite.AlgorithmSuite) (MessageFooter, error)
}

// Serializer defines methods for serializing encrypted message components.
type Serializer interface {
	// SerializeHeader serializes a message header.
	// It takes header parameters as input and returns a MessageHeader and an error if any.
	SerializeHeader(p HeaderParams) (MessageHeader, error)

	// SerializeHeaderAuth serializes a message header authentication data.
	// It takes a message format version, an initialization vector, and authentication data as input.
	// It returns a MessageHeaderAuth and an error if any.
	SerializeHeaderAuth(v suite.MessageFormatVersion, iv, authData []byte) (MessageHeaderAuth, error)

	// SerializeBody serializes a message body.
	// It takes an algorithm suite and a frame length as input.
	// It returns a MessageBody and an error if any.
	SerializeBody(alg *suite.AlgorithmSuite, frameLength int) (MessageBody, error)

	// SerializeFooter serializes a message footer.
	// It takes an algorithm suite and a signature as input.
	// It returns a MessageFooter and an error if any.
	SerializeFooter(alg *suite.AlgorithmSuite, signature []byte) (MessageFooter, error)
}
