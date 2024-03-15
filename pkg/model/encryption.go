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

// GcmEncrypter is an interface for GCM encryption implementations.
type GcmEncrypter interface {
	// Encrypt is a method for encrypting data. It returns three values: the
	// encrypted ciphertext, the authentication tag, and an error if any occurred
	// during the encryption process.
	Encrypt(key, iv, plaintext, aadData []byte) ([]byte, []byte, error)
}

// GcmDecrypter is an interface for GCM decryption implementations.
type GcmDecrypter interface {
	// Decrypt is a method for decrypting data. It returns the decrypted plaintext,
	// and an error if any occurred.
	Decrypt(key, iv, ciphertext, tag, aadData []byte) ([]byte, error)
}

// GcmCrypter is a combined interface for GCM encryption and decryption.
type GcmCrypter interface {
	GcmEncrypter
	GcmDecrypter
}

// AEADEncrypter is an interface for AEAD encryption implementations.
type AEADEncrypter interface {
	GcmEncrypter

	// GenerateHeaderAuth generates the header authentication tag and returns the
	// authentication tag, iv, and an error if any occurred.
	GenerateHeaderAuth(derivedDataKey, headerBytes []byte) ([]byte, []byte, error)

	// ConstructIV constructs the IV from the sequence number.
	ConstructIV(seqNum int) []byte
}

// AEADDecrypter is an interface for AEAD decryption implementations.
type AEADDecrypter interface {
	GcmDecrypter

	// ValidateHeaderAuth validates that the header authentication tag against the
	// message header, and returns an error if any occurred.
	ValidateHeaderAuth(derivedDataKey, headerAuthTag, headerBytes []byte) error
}
