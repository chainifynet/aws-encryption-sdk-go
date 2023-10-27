// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var (
	log = logger.L().Level(zerolog.DebugLevel)
)

var (
	InvalidMessage = errors.New("invalid message format")
	DecryptionErr  = errors.New("decryption error")
	EncryptionErr  = errors.New("encryption error")
)

// SdkDecrypter will take
//
//	ciphertext - copy to buffer
//	cmm - is a pointer
//	source len ?
//	commitment_policy
//
// must return:
//
//	plaintext []byte
//	header as object
//	error nil or specific error think about error handling, not just return fmt errorf...
//	TODO might be try to provide client config here
type SdkDecrypter interface {
	decrypt(ciphertext []byte) ([]byte, error)
}

type decrypter struct {
	cmm             materials.CryptoMaterialsManager
	config          clientconfig.ClientConfig
	aeadDecrypter   gcmDecrypter
	header          *serialization.MessageHeader
	verifier        *verifier
	_derivedDataKey []byte
}

func Decrypt(config clientconfig.ClientConfig, ciphertext []byte, cmm materials.CryptoMaterialsManager) ([]byte, error) {
	log.Trace().
		Str("config", fmt.Sprintf("%+v", config)).
		Msg("Decrypt")
	// TODO not sure needs to be tested properly

	dec := decrypter{
		cmm:           cmm.GetInstance(),
		config:        config,
		aeadDecrypter: gcmDecrypter{},
	}

	b, err := dec.decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("SDK error: %w", errors.Join(DecryptionErr, err))
	}
	// TODO andrew return header on decryption
	//  https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/__init__.py#L190
	//  :returns: Tuple containing the decrypted plaintext and the message header object
	return b, nil
}

var _ SdkDecrypter = (*decrypter)(nil)

// SdkEncryptor will take a lot more, later
type SdkEncryptor interface {
	encrypt(source []byte, ec suite.EncryptionContext) ([]byte, *serialization.MessageHeader, error)
}

type encryptor struct {
	cmm             materials.CryptoMaterialsManager
	config          clientconfig.ClientConfig
	algorithm       *suite.AlgorithmSuite
	frameLength     int
	aeadEncryptor   gcmEncryptor
	header          *serialization.MessageHeader
	_derivedDataKey []byte
	signer          *signer
	ciphertextBuf   *bytes.Buffer
}

func Encrypt(config clientconfig.ClientConfig, source []byte, ec suite.EncryptionContext, cmm materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	return EncryptWithOpts(config, source, ec, cmm, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, 1024)
}

func EncryptWithOpts(config clientconfig.ClientConfig, source []byte, ec suite.EncryptionContext, cmm materials.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error) {
	enc := encryptor{
		cmm:           cmm.GetInstance(),
		config:        config,
		algorithm:     algorithm,
		frameLength:   frameLength,
		aeadEncryptor: gcmEncryptor{},
		ciphertextBuf: new(bytes.Buffer),
	}
	ciphertext, header, err := enc.encrypt(source, ec)
	if err != nil {
		// TODO andrew clean up derived data key
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(EncryptionErr, err))
	}
	return ciphertext, header, nil
}

var _ SdkEncryptor = (*encryptor)(nil)
