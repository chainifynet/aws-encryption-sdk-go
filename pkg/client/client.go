// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const (
	defaultClientFrameLength = 4096
)

// NewClient returns a new client with default clientconfig.ClientConfig config
func NewClient() *Client {
	cfg, _ := clientconfig.NewConfig()
	return NewClientWithConfig(cfg)
}

// NewClientWithConfig returns a new client with cfg clientconfig.ClientConfig
func NewClientWithConfig(cfg *clientconfig.ClientConfig) *Client {
	return &Client{
		config: *cfg,
	}
}

type BaseClient interface {
	clientConfig() clientconfig.ClientConfig
	Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error)
	EncryptWithOpts(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error)
	Decrypt(ctx context.Context, ciphertext []byte, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error)
}

var _ BaseClient = (*Client)(nil)

type Client struct {
	config clientconfig.ClientConfig
}

func (c *Client) clientConfig() clientconfig.ClientConfig {
	return c.config
}

// EncryptWithOpts is similar to Encrypt but allows specifying additional options such as
// the algorithm suite and frame length.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - source []byte: The data to encrypt.
//   - ec suite.EncryptionContext: The encryption context.
//   - materialsManager materials.CryptoMaterialsManager: The manager that provides the cryptographic materials.
//   - algorithm suite.AlgorithmSuite: The algorithm suite to use for encryption.
//   - frameLength int: The frame length for encryption.
//
// Returns:
//   - []byte: The encrypted data.
//   - serialization.MessageHeader: The header of the encrypted message.
//   - error: An error if encryption fails.
func (c *Client) EncryptWithOpts(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error) {
	ciphertext, header, err := crypto.Encrypt(ctx, c.clientConfig(), source, ec, materialsManager, algorithm, frameLength)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, header, nil
}

// Encrypt encrypts the given source data using the provided materials manager and encryption context.
// Uses the default algorithm suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 and frame length 4096.
// It returns the encrypted data and the message header.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - source []byte: The data to encrypt.
//   - ec suite.EncryptionContext: The encryption context, a set of key-value pairs
//     that are cryptographically bound to the encrypted data.
//     materialsManager materials.CryptoMaterialsManager: The manager that provides the cryptographic materials.
//
// Returns:
//   - []byte: The encrypted data.
//   - serialization.MessageHeader: The header of the encrypted message.
//   - error: An error if encryption fails.
func (c *Client) Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	return c.EncryptWithOpts(ctx, source, ec, materialsManager, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, defaultClientFrameLength)
}

// Decrypt decrypts the given ciphertext using the provided materials manager.
// It returns the decrypted plaintext and the message header.
//
// Parameters:
//
//   - ctx: context.Context.
//   - ciphertext []byte: The data to decrypt.
//   - materialsManager materials.CryptoMaterialsManager: The manager that provides the cryptographic materials.
//
// Returns:
//
//   - []byte: The decrypted data.
//   - serialization.MessageHeader: The header of the encrypted message.
//   - error: An error if decryption fails.
func (c *Client) Decrypt(ctx context.Context, ciphertext []byte, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	b, header, err := crypto.Decrypt(ctx, c.clientConfig(), ciphertext, materialsManager)
	if err != nil {
		return nil, nil, err
	}
	return b, header, nil
}
