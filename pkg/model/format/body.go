// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

type BodyFrame interface {
	Serializable
	IsFinal() bool
	SequenceNumber() int
	IV() []byte
	EncryptedContent() []byte
	AuthenticationTag() []byte
}

type MessageBody interface {
	Serializable
	Frames() []BodyFrame
	AddFrame(final bool, seqNum int, IV []byte, contentLength int, ciphertext, authTag []byte) error
}
