// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto/signature"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
)

var (
	ErrInvalidMessage = errors.New("invalid message format")
	ErrDecryption     = errors.New("decryption error")
	ErrEncryption     = errors.New("encryption error")
)

const (
	firstByteEncryptedMessage = byte(0x02)
)

type SdkDecrypter interface {
	decrypt(ctx context.Context, ciphertext []byte) ([]byte, *serialization.MessageHeader, error)
}

type decrypter struct {
	cmm             model.CryptoMaterialsManager
	config          clientconfig.ClientConfig
	aeadDecrypter   encryption.AEADDecrypter
	header          *serialization.MessageHeader
	verifier        signature.Verifier
	_derivedDataKey []byte
}

func Decrypt(ctx context.Context, config clientconfig.ClientConfig, ciphertext []byte, cmm model.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	dec := decrypter{
		cmm:           cmm.GetInstance(),
		config:        config,
		aeadDecrypter: encryption.Gcm{},
	}

	b, header, err := dec.decrypt(ctx, ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(ErrDecryption, err))
	}
	return b, header, nil
}

var _ SdkDecrypter = (*decrypter)(nil)

type SdkEncrypter interface {
	encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, *serialization.MessageHeader, error)
}

type encrypter struct {
	cmm             model.CryptoMaterialsManager
	config          clientconfig.ClientConfig
	algorithm       *suite.AlgorithmSuite
	frameLength     int
	aeadEncrypter   encryption.AEADEncrypter
	header          *serialization.MessageHeader
	_derivedDataKey []byte
	signer          signature.Signer
	ciphertextBuf   *bytes.Buffer
}

func Encrypt(ctx context.Context, config clientconfig.ClientConfig, source []byte, ec suite.EncryptionContext, cmm model.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error) {
	enc := encrypter{
		cmm:           cmm.GetInstance(),
		config:        config,
		algorithm:     algorithm,
		frameLength:   frameLength,
		aeadEncrypter: encryption.Gcm{},
		ciphertextBuf: new(bytes.Buffer),
	}
	ciphertext, header, err := enc.encrypt(ctx, source, ec)
	if err != nil {
		// TODO andrew clean up derived data key
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(ErrEncryption, err))
	}
	return ciphertext, header, nil
}

var _ SdkEncrypter = (*encrypter)(nil)
