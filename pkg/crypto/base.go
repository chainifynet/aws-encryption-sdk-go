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
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
)

var (
	log = logger.L().Level(zerolog.DebugLevel) //nolint:gochecknoglobals
)

var (
	ErrInvalidMessage = errors.New("invalid message format")
	ErrDecryption     = errors.New("decryption error")
	ErrEncryption     = errors.New("encryption error")
)

const (
	firstByteEncryptedMessage = byte(0x02)
	defaultClientEncryptFrame = int(1024)
)

type SdkDecrypter interface {
	decrypt(ciphertext []byte) ([]byte, *serialization.MessageHeader, error)
}

type decrypter struct {
	cmm             materials.CryptoMaterialsManager
	config          clientconfig.ClientConfig
	aeadDecrypter   encryption.AEADDecrypter
	header          *serialization.MessageHeader
	verifier        *verifier
	_derivedDataKey []byte
}

func Decrypt(config clientconfig.ClientConfig, ciphertext []byte, cmm materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	log.Trace().
		Str("config", fmt.Sprintf("%+v", config)).
		Msg("Decrypt")
	// TODO not sure needs to be tested properly

	dec := decrypter{
		cmm:           cmm.GetInstance(),
		config:        config,
		aeadDecrypter: encryption.Gcm{},
	}

	b, header, err := dec.decrypt(ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(ErrDecryption, err))
	}
	return b, header, nil
}

var _ SdkDecrypter = (*decrypter)(nil)

type SdkEncrypter interface {
	encrypt(source []byte, ec suite.EncryptionContext) ([]byte, *serialization.MessageHeader, error)
}

type encrypter struct {
	cmm             materials.CryptoMaterialsManager
	config          clientconfig.ClientConfig
	algorithm       *suite.AlgorithmSuite
	frameLength     int
	aeadEncrypter   encryption.AEADEncrypter
	header          *serialization.MessageHeader
	_derivedDataKey []byte
	signer          *signer
	ciphertextBuf   *bytes.Buffer
}

func Encrypt(config clientconfig.ClientConfig, source []byte, ec suite.EncryptionContext, cmm materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	return EncryptWithOpts(config, source, ec, cmm, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, defaultClientEncryptFrame)
}

func EncryptWithOpts(config clientconfig.ClientConfig, source []byte, ec suite.EncryptionContext, cmm materials.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error) {
	enc := encrypter{
		cmm:           cmm.GetInstance(),
		config:        config,
		algorithm:     algorithm,
		frameLength:   frameLength,
		aeadEncrypter: encryption.Gcm{},
		ciphertextBuf: new(bytes.Buffer),
	}
	ciphertext, header, err := enc.encrypt(source, ec)
	if err != nil {
		// TODO andrew clean up derived data key
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(ErrEncryption, err))
	}
	return ciphertext, header, nil
}

var _ SdkEncrypter = (*encrypter)(nil)
