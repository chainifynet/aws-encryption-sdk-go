// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package wrappingkey

type Wrapper interface {
	SerializeEncryptedDataKey(encryptedKey, tag, iv []byte) []byte
	DeserializeEncryptedDataKey(b []byte, iVLen int) (encryptedData, iv []byte)
}

type WrappingKey struct{}

// SerializeEncryptedDataKey takes three separate byte slices that represent
// the encrypted key, the authentication tag, and the initialization vector (IV),
// and concatenates them into a single byte slice.
//
// Parameters:
//
//	encryptedKey []byte: A byte slice representing the encrypted data key.
//	tag          []byte: A byte slice representing the authentication tag
//	                     used to verify the integrity of the encrypted data.
//	iv           []byte: A byte slice representing the initialization vector
//	                     used during the encryption process.
//
// Returns:
//
//	[]byte: A concatenated byte slice that includes the encrypted key, followed
//	        by the authentication tag, and ending with the IV.
func (wk WrappingKey) SerializeEncryptedDataKey(encryptedKey, tag, iv []byte) []byte {
	buf := make([]byte, len(encryptedKey)+len(tag)+len(iv))

	offset := 0
	copy(buf[offset:], encryptedKey)
	offset += len(encryptedKey)
	copy(buf[offset:], tag)
	offset += len(tag)
	copy(buf[offset:], iv)

	return buf
}

// DeserializeEncryptedDataKey reverses the process of SerializeEncryptedDataKey.
// It takes a single byte slice containing the serialized encrypted data key,
// tag, and IV and extracts the original components. This is typically used to
// retrieve the encrypted key and IV for decryption purposes.
//
// Parameters:
//
//	b      []byte: A byte slice that contains the serialized encrypted data key,
//	                authentication tag, and IV.
//	iVLen  int:    The length of the IV, which dictates how many bytes to extract
//	                from the end of the byte slice for the IV.
//
// Returns:
//
//	encryptedData []byte: The portion of the byte slice 'b' that represents the
//	                      encrypted data key (and potentially the authentication
//	                      tag if it is included with the encrypted data).
//	iv            []byte: The extracted initialization vector that was originally
//	                      used for encryption.
func (wk WrappingKey) DeserializeEncryptedDataKey(b []byte, iVLen int) (encryptedData, iv []byte) {
	iv = make([]byte, iVLen)
	copy(iv, b[len(b)-iVLen:])

	// encryptedData is ciphertext + tag, im too lazy to extract it
	encryptedData = make([]byte, len(b)-iVLen)
	copy(encryptedData, b[:len(b)-iVLen])
	return
}
