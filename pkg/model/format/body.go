// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

// BodyFrame contains information about the body frame.
type BodyFrame interface {
	Serializable

	// IsFinal indicates true if the frame is final.
	IsFinal() bool

	// SequenceNumber returns the frame sequence number.
	SequenceNumber() int

	// IV returns the frame IV.
	IV() []byte

	// EncryptedContent returns the frame encrypted content.
	EncryptedContent() []byte

	// AuthenticationTag returns the frame authentication tag.
	AuthenticationTag() []byte
}

// MessageBody contains information about the message body.
type MessageBody interface {
	Serializable

	// Frames returns the body frames.
	Frames() []BodyFrame

	// AddFrame adds new BodyFrame to the body.
	AddFrame(final bool, seqNum int, IV []byte, contentLength int, ciphertext, authTag []byte) error
}
