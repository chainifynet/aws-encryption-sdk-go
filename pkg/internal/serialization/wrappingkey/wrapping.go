// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package wrappingkey

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"

const (
	tagLen             = 16
	ivLen              = 12
	oneByte            = 8 // bits
	uint32BigEndianLen = 4 // bytes
)

type WrappingKey struct{}

// SerializeKeyInfoPrefix is a method of the WrappingKey struct.
// It takes a keyID string as input and returns a byte slice.
//
// The method first creates a byte slice, keyInfoPrefix, with a length equal to
// the length of the keyID string plus twice the length of a uint32 in big
// endian format.
// It then copies the keyID string into the start of the keyInfoPrefix byte
// slice.
// Next, it converts the tag length (tagLen) multiplied by the size of a byte
// (oneByte) into a uint32 in big endian format and copies this into
// the keyInfoPrefix byte slice, starting at the position after the keyID.
// Finally, it converts the initialization vector length (ivLen) into a uint32
// in big endian format and copies this into the keyInfoPrefix byte slice,
// starting at the position after the keyID and the tag length.
//
// Parameters:
//
//	keyID string: A string representing the key ID.
//
// Returns:
//
//	[]byte: A byte slice that includes the key ID, followed by the tag length
//	        and the initialization vector length, all in big endian format.
func (wk WrappingKey) SerializeKeyInfoPrefix(keyID string) []byte {
	keyInfoPrefix := make([]byte, len(keyID)+uint32BigEndianLen+uint32BigEndianLen)
	copy(keyInfoPrefix, keyID)
	copy(keyInfoPrefix[len(keyID):], conv.FromInt.Uint32BigEndian(tagLen*oneByte))
	copy(keyInfoPrefix[len(keyID)+uint32BigEndianLen:], conv.FromInt.Uint32BigEndian(ivLen))
	return keyInfoPrefix
}

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
