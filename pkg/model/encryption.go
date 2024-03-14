// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"io"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// DecryptionHandler is an interface for decryption handler implementations.
type DecryptionHandler interface {
	// Decrypt decrypts ciphertext encrypted message and returns the decrypted
	// plaintext and associated message header.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, format.MessageHeader, error)
}

// EncryptionHandler is an interface for encryption handler implementations.
type EncryptionHandler interface {
	// Encrypt encrypts the plaintext and returns the encrypted ciphertext and
	// associated message header.
	Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, format.MessageHeader, error)
}

// EncryptionBuffer is an interface to be used as a buffer for encryption. See
// [bytes.Buffer] for more details on Bytes, Len and Reset methods.
type EncryptionBuffer interface {
	io.ReadWriter

	// Bytes returns a slice of buffer length holding the unread portion of the
	// buffer.
	Bytes() []byte

	// Len returns the number of bytes of the unread portion of the buffer.
	Len() int

	// Reset resets the buffer to be empty.
	Reset()
}
