// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// Serializable is an interface for objects that can be serialized to bytes.
type Serializable interface {
	// Len returns the length of the serialized object.
	Len() int
	// Bytes returns the serialized object.
	Bytes() []byte
}

// MessageHeaderBase is the common interface for the message header.
type MessageHeaderBase interface {
	// Version returns the message format version.
	Version() suite.MessageFormatVersion

	// AlgorithmSuite returns the algorithm suite used with the message.
	AlgorithmSuite() *suite.AlgorithmSuite

	// MessageID returns the message ID.
	MessageID() []byte

	// AADLength returns the length of the additional authenticated data.
	AADLength() int

	// AADData returns the additional authenticated data.
	AADData() MessageAAD

	// EncryptedDataKeyCount returns the number of encrypted data keys.
	EncryptedDataKeyCount() int

	// EncryptedDataKeys returns the encrypted data keys.
	EncryptedDataKeys() []MessageEDK

	// ContentType returns the content type.
	ContentType() suite.ContentType

	// FrameLength returns the frame length.
	FrameLength() int
}

// MessageHeader contains information about the message header.
type MessageHeader interface {
	Serializable
	MessageHeaderBase

	// Type returns the message type. Present only in V1.
	Type() MessageType

	// Reserved returns the reserved bytes. Present only in V1.
	Reserved() []byte

	// IVLength returns the length of the IV. Present only in V1.
	IVLength() int

	// AlgorithmSuiteData returns the algorithm suite data. Present only in V2.
	AlgorithmSuiteData() []byte
}

// MessageEDK contains information about the encrypted data key.
type MessageEDK interface {
	Serializable

	// ProviderID returns the provider ID.
	ProviderID() string

	// ProviderInfo returns the provider info.
	ProviderInfo() string

	// EncryptedDataKey returns the encrypted data key.
	EncryptedDataKey() []byte
}

// MessageAAD contains information about the additional authenticated data.
type MessageAAD interface {
	Serializable

	// EncryptionContext returns the encryption context.
	EncryptionContext() suite.EncryptionContext
}

// MessageHeaderAuth contains information about the message header authentication.
type MessageHeaderAuth interface {
	Serializable

	// AuthData returns the authentication data.
	AuthData() []byte

	// IV returns the IV. Present only in V1.
	IV() []byte
}

// HeaderParams contains the parameters to be used to create [MessageHeader].
type HeaderParams struct {
	AlgorithmSuite     *suite.AlgorithmSuite
	MessageID          []byte
	EncryptionContext  suite.EncryptionContext
	EncryptedDataKeys  []MessageEDK
	ContentType        suite.ContentType
	FrameLength        int
	AlgorithmSuiteData []byte
}
