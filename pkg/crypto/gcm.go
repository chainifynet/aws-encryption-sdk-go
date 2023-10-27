// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/pkg/errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

// Each 96-bit (12-byte) IV is constructed from two big-endian
// byte arrays concatenated in the following order:
//
// 64 bits: 0 (reserved for future use)
// 32 bits: Frame sequence number. For the header authentication tag, this value is all zeroes.

const aesGCMTagSize = 16

type gcmDecrypter struct{}

type gcmEncryptor struct{}

// decrypt data with AES-GCM AEAD, IV is nonce
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
func (gd gcmDecrypter) decrypt(key []byte, iv []byte, ciphertext []byte, tag []byte, aadData []byte) ([]byte, error) {
	// TODO validations

	// concat raw_ciphertext + auth_tag
	ciphertextWithTag := append(ciphertext, tag...)

	log.Trace().
		Str("key", logger.FmtBytes(key)).
		Str("iv", logger.FmtBytes(iv)).
		Str("ciphertext", logger.FmtBytes(ciphertext)).
		Str("tag", logger.FmtBytes(tag)).
		Str("aadData", logger.FmtBytes(aadData)).
		Str("ciphertextWithTag", logger.FmtBytes(ciphertextWithTag)).
		Msg("AES decrypt params")

	//log.Trace().MsgFunc(logger.FmtHex("AES ciphertext", ciphertext))
	//log.Trace().MsgFunc(logger.FmtHex("AES tag", tag))
	//log.Trace().MsgFunc(logger.FmtHex("AES IV", iv))
	//log.Trace().MsgFunc(logger.FmtHex("AES aadData", aadData))
	//log.Trace().MsgFunc(logger.FmtHex("AES ciphertextWithTag", ciphertextWithTag))

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCMWithNonceSize(c, len(iv))
	if err != nil {
		return nil, err
	}

	// nil, IV/nonce, (raw_ciphertext + auth_tag), aadData
	plaintext, err := aesGCM.Open(nil, iv, ciphertextWithTag, aadData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (ge gcmEncryptor) encrypt(key, iv, plaintext, aadData []byte) ([]byte, []byte, error) {
	// TODO andrew add validations
	log.Trace().
		Str("key", logger.FmtBytes(key)).
		Str("iv", logger.FmtBytes(iv)).
		Str("plaintext", logger.FmtBytes(plaintext)).
		Str("aadData", logger.FmtBytes(aadData)).
		Msg("AES encrypt params")

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCMWithTagSize(c, aesGCMTagSize)
	if err != nil {
		return nil, nil, err
	}

	// ciphertext[:ciphertext len - tagSize], tag[:ciphertext len - tagSize]
	//	= nil, IV/nonce, plaintext, aadData
	ciphertext := aesGCM.Seal(nil, iv, plaintext, aadData)
	//log.Trace().MsgFunc(logger.FmtHex("AES ciphertext", ciphertext))

	tag := ciphertext[len(ciphertext)-aesGCMTagSize:]
	//log.Trace().MsgFunc(logger.FmtHex("AES tag", tag))

	ciphertext = ciphertext[:len(ciphertext)-aesGCMTagSize]
	//log.Trace().MsgFunc(logger.FmtHex("AES ciphertext, no tag", ciphertext))

	log.Trace().
		Str("key", logger.FmtBytes(key)).
		Str("iv", logger.FmtBytes(iv)).
		Str("ciphertext", logger.FmtBytes(ciphertext)).
		Str("tag", logger.FmtBytes(tag)).
		Str("plaintext", logger.FmtBytes(plaintext)).
		Str("aadData", logger.FmtBytes(aadData)).
		Msg("AES encrypt result")

	return ciphertext, tag, nil
}

// validateHeaderAuth validates header authorization
// constructs IV per https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/IV-reference.html
// For decryption of the Header only
//
//	Specification: https://github.com/awslabs/aws-encryption-sdk-specification/blob/6124516bb8a58d21d61b4bc6dd7d33561fdf2cae/client-apis/decrypt.md#verify-the-header
//	derivedDataKey: derivedDataKey (32 bytes) per AlgorithmSuite.EncryptionSuite.DataKeyLen
//	headerAuthTag: header.HeaderAuthentication
//	headerBytes - header.SerializeBytes(), all header bytes not including header.HeaderAuthentication
func (gd gcmDecrypter) validateHeaderAuth(derivedDataKey, headerAuthTag, headerBytes []byte) error {
	out, err := gd.decrypt(derivedDataKey, constructIV(0), []byte(nil), headerAuthTag, headerBytes)
	if err != nil {
		// TODO deprecate pkg/errors, introduce GCM errors
		return errors.Wrap(DecryptionErr, "header authorization failed")
	}
	if len(out) != 0 {
		// TODO deprecate pkg/errors, introduce GCM errors
		return errors.Wrap(DecryptionErr, "header authorization output validation failed")
	}
	return nil
}

func (ge gcmEncryptor) generateHeaderAuth(derivedDataKey, headerBytes []byte) ([]byte, error) {
	_, headerAuth, err := ge.encrypt(derivedDataKey, constructIV(0), []byte(nil), headerBytes)
	if err != nil {
		// TODO deprecate pkg/errors, introduce GCM errors
		return nil, fmt.Errorf("%w: header auth error", err)
	}

	return headerAuth, nil
}

// constructIV constructs IV
// Each 96-bit (12-byte) IV is constructed from two big-endian
// byte arrays concatenated in the following order:
//
// 64 bits: 0 (reserved for future use)
// 32 bits: Frame sequence number
// For the header authentication tag, this value is all zeroes. seqNum will be 0
func constructIV(seqNum int) []byte {
	var bs []byte
	bs = make([]byte, 0, 12)                                                    // IV is 12 bytes
	bs = append(bs, []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...) // 64 bits or 8 bytes: 0 (reserved for future use)
	bs = append(bs, conv.FromInt.Uint32BigEndian(seqNum)...)                    // 32 bits or 4 bytes: Frame sequence number.
	return bs
}
