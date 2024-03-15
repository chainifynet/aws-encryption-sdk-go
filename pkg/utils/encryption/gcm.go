// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
)

const (
	aesGCMTagSize = 16
	IVLen         = 12
)

var (
	ErrGcmDecrypt = errors.New("gcm decrypt error")
	ErrGcmEncrypt = errors.New("gcm encrypt error")
)

type Encrypter interface {
	Encrypt(key, iv, plaintext, aadData []byte) ([]byte, []byte, error)
}

type Decrypter interface {
	Decrypt(key, iv, ciphertext, tag, aadData []byte) ([]byte, error)
}

type GcmBase interface {
	Encrypter
	Decrypter
}

type AEADEncrypter interface {
	Encrypter
	GenerateHeaderAuth(derivedDataKey, headerBytes []byte) ([]byte, []byte, error)
	ConstructIV(seqNum int) []byte
}

type AEADDecrypter interface {
	Decrypter
	ValidateHeaderAuth(derivedDataKey, headerAuthTag, headerBytes []byte) error
}

type Gcm struct{}

// Decrypt data with AES-GCM AEAD, IV is nonce
//
// For decryption of the Header only
//
//	Specification: https://github.com/awslabs/aws-encryption-sdk-specification/blob/6124516bb8a58d21d61b4bc6dd7d33561fdf2cae/client-apis/decrypt.md#verify-the-header
//	key: derivedDataKey (32 bytes) per AlgorithmSuite.EncryptionSuite.DataKeyLen
//	iv: 64-bits (8 bytes of 0x00) value of 0 + 32-bits (4 bytes of 0x00) value of 0 = 12 bytes
//	ciphertext: []byte(nil) (empty slice of 0 bytes)
//	tag: header.HeaderAuthentication
//	aadData - header.SerializeBytes(), all header bytes not including header.HeaderAuthentication
//
// For Header returns if success:
//
//	[]byte: []byte(nil)
//	error: not nil
func (ge Gcm) Decrypt(key, iv, ciphertext, tag, aadData []byte) ([]byte, error) {
	// TODO validations

	// concat raw_ciphertext + auth_tag
	ciphertextWithTag := append(ciphertext, tag...) //nolint:gocritic

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher error: %v: %w", err.Error(), ErrGcmDecrypt)
	}

	aesGCM, err := cipher.NewGCMWithNonceSize(c, len(iv))
	if err != nil {
		return nil, fmt.Errorf("AEAD error: %v: %w", err.Error(), ErrGcmDecrypt)
	}

	// nil, IV/nonce, (raw_ciphertext + auth_tag), aadData
	plaintext, err := aesGCM.Open(nil, iv, ciphertextWithTag, aadData)
	if err != nil {
		return nil, fmt.Errorf("AES error: %v: %w", err.Error(), ErrGcmDecrypt)
	}
	return plaintext, nil
}

func (ge Gcm) Encrypt(key, iv, plaintext, aadData []byte) ([]byte, []byte, error) {
	// TODO andrew add validations

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher error: %v: %w", err.Error(), ErrGcmEncrypt)
	}

	// error is always nil can be ignored due to the constant aesGCMTagSize fixed size
	aesGCM, _ := cipher.NewGCMWithTagSize(c, aesGCMTagSize)

	// ciphertext[:ciphertext len - tagSize], tag[:ciphertext len - tagSize]
	//	= nil, IV/nonce, plaintext, aadData
	ciphertext := aesGCM.Seal(nil, iv, plaintext, aadData)

	tag := ciphertext[len(ciphertext)-aesGCMTagSize:]

	ciphertext = ciphertext[:len(ciphertext)-aesGCMTagSize]

	return ciphertext, tag, nil
}

// ValidateHeaderAuth validates header authorization
// constructs IV per https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/IV-reference.html
// For decryption of the Header only
//
// Specification: https://github.com/awslabs/aws-encryption-sdk-specification/blob/6124516bb8a58d21d61b4bc6dd7d33561fdf2cae/client-apis/decrypt.md#verify-the-header
//
//	derivedDataKey: derivedDataKey (32 bytes) per AlgorithmSuite.EncryptionSuite.DataKeyLen
//	headerAuthTag: header.HeaderAuthentication
//	headerBytes: header.SerializeBytes(), all header bytes not including header.HeaderAuthentication
func (ge Gcm) ValidateHeaderAuth(derivedDataKey, headerAuthTag, headerBytes []byte) error {
	// decrypted plaintext always have a length of 0 due to the empty ciphertext input, so it can be ignored
	_, err := ge.Decrypt(derivedDataKey, ge.ConstructIV(0), []byte(nil), headerAuthTag, headerBytes)
	if err != nil {
		return fmt.Errorf("invalid header auth: %w", err)
	}
	return nil
}

func (ge Gcm) GenerateHeaderAuth(derivedDataKey, headerBytes []byte) ([]byte, []byte, error) {
	iv := ge.ConstructIV(0)
	_, headerAuth, err := ge.Encrypt(derivedDataKey, iv, []byte(nil), headerBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid header auth: %w", err)
	}

	return headerAuth, iv, nil
}

// ConstructIV constructs IV
// Each 96-bit (12-byte) IV is constructed from two big-endian
// byte arrays concatenated in the following order:
//
//  1. 64 bits: 0 (reserved for future use)
//  2. 32 bits: Frame sequence number
//
// For the header authentication tag, this value is all zeroes. seqNum will be 0
func (ge Gcm) ConstructIV(seqNum int) []byte {
	var bs []byte
	bs = make([]byte, 0, IVLen)                                                 // IV is 12 bytes
	bs = append(bs, []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...) // 64 bits or 8 bytes: 0 (reserved for future use)
	bs = append(bs, conv.FromInt.Uint32BigEndian(seqNum)...)                    // 32 bits or 4 bytes: Frame sequence number.
	return bs
}
