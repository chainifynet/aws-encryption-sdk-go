// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type Serializable interface {
	Len() int
	Bytes() []byte
}

type messageHeaderBase interface {
	Version() suite.MessageFormatVersion
	AlgorithmSuite() *suite.AlgorithmSuite
	MessageID() []byte
	AADLength() int
	AADData() MessageAAD
	EncryptedDataKeyCount() int
	EncryptedDataKeys() []MessageEDK
	ContentType() suite.ContentType
	FrameLength() int
}

type MessageHeader interface {
	Serializable
	messageHeaderBase
	Type() suite.MessageType    // present only in V1
	Reserved() []byte           // present only in V1
	IVLength() int              // present only in V1
	AlgorithmSuiteData() []byte // present only in V2
}

type MessageEDK interface {
	Serializable
	ProviderID() string
	ProviderInfo() string
	EncryptedDataKey() []byte
}

type MessageAAD interface {
	Serializable
	EncryptionContext() suite.EncryptionContext
}

type MessageHeaderAuth interface {
	Serializable
	AuthData() []byte
	IV() []byte // present only in V1
}

type HeaderParams struct {
	AlgorithmSuite     *suite.AlgorithmSuite
	MessageID          []byte
	EncryptionContext  suite.EncryptionContext
	EncryptedDataKeys  []MessageEDK
	ContentType        suite.ContentType
	FrameLength        int
	AlgorithmSuiteData []byte
}
