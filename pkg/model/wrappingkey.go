// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

// Wrapper is an interface for wrapping key implementations.
type Wrapper interface {
	// SerializeEncryptedDataKey serializes the encrypted data key and returns the
	// serialized form.
	SerializeEncryptedDataKey(encryptedKey, tag, iv []byte) []byte

	// DeserializeEncryptedDataKey deserializes the encrypted data key and returns
	// the encrypted data key, tag and IV.
	DeserializeEncryptedDataKey(b []byte, iVLen int) (encryptedData, iv []byte)

	// SerializeKeyInfoPrefix serializes the key ID and returns the serialized form.
	SerializeKeyInfoPrefix(keyID string) []byte
}
