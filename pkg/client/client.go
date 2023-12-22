// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// NewClient returns a new client with default [clientconfig.ClientConfig] config
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
	Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager model.CryptoMaterialsManager, optFns ...EncryptOptionFunc) ([]byte, format.MessageHeader, error)
	EncryptWithParams(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager model.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, format.MessageHeader, error)
	Decrypt(ctx context.Context, ciphertext []byte, materialsManager model.CryptoMaterialsManager) ([]byte, format.MessageHeader, error)
}

var _ BaseClient = (*Client)(nil)

type Client struct {
	config clientconfig.ClientConfig
}

func (c *Client) clientConfig() clientconfig.ClientConfig {
	return c.config
}

// EncryptWithParams is similar to Encrypt but allows specifying additional options such as
// the algorithm suite and frame length as arguments instead of functional EncryptOptionFunc options.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - source []byte: The data to encrypt.
//   - ec [suite.EncryptionContext]: The encryption context.
//   - materialsManager [model.CryptoMaterialsManager]: The manager that provides the cryptographic materials.
//   - algorithm [suite.AlgorithmSuite]: The algorithm suite to use for encryption.
//   - frameLength int: The frame length for encryption.
//
// Returns:
//   - []byte: The encrypted data.
//   - [format.MessageHeader]: The header of the encrypted message.
//   - error: An error if encryption fails.
func (c *Client) EncryptWithParams(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager model.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, format.MessageHeader, error) {
	return c.Encrypt(ctx, source, ec, materialsManager, WithAlgorithm(algorithm), WithFrameLength(frameLength))
}

// Encrypt encrypts the given source data using the provided materials manager and encryption context.
// By default, it uses the algorithm [suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384] and a frame length of 4096.
//
// This behavior can be modified by passing in optional functional arguments using EncryptOptionFunc.
// It returns the ciphertext data along with the message header.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - source []byte: The data to encrypt.
//   - ec [suite.EncryptionContext]: The encryption context, a set of key-value pairs
//     that are cryptographically bound to the encrypted data.
//   - materialsManager [model.CryptoMaterialsManager]: The manager that provides the cryptographic materials.
//   - optFns EncryptOptionFunc: A variadic set of optional functions for configuring encryption options such as
//     custom algorithm or frame length.
//
// Returns:
//   - []byte: The encrypted data.
//   - [format.MessageHeader]: The header of the encrypted message.
//   - error: An error if encryption fails.
//
// Example usage:
//
//	ciphertext, header, err := client.Encrypt(context.TODO(), plaintext, encryptionContext, materialsManager,
//	    WithAlgorithm(customAlgorithm),
//	    WithFrameLength(1024))
//	if err != nil {
//	    // handle error
//	}
//
// Notes:
//
//  1. The Encrypt function allows customization of the encryption process through its optional parameters.
//  2. The WithAlgorithm and WithFrameLength functions can be used to specify an encryption algorithm and frame length,
//     respectively. If these functions are not used, default values are applied.
func (c *Client) Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext, materialsManager model.CryptoMaterialsManager, optFns ...EncryptOptionFunc) ([]byte, format.MessageHeader, error) {
	opts := EncryptOptions{
		Algorithm:   suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		FrameLength: DefaultFrameLength,
	}
	for _, optFn := range optFns {
		if err := optFn(&opts); err != nil {
			return nil, nil, fmt.Errorf("invalid encrypt option: %w", errors.Join(crypto.ErrEncryption, err))
		}
	}
	ciphertext, header, err := crypto.Encrypt(ctx, c.clientConfig(), source, ec, materialsManager, opts.Algorithm, opts.FrameLength)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, header, nil
}

// Decrypt decrypts the given ciphertext using the provided materials manager.
// It returns the decrypted plaintext and the message header.
//
// Parameters:
//
//   - ctx: context.Context.
//   - ciphertext []byte: The data to decrypt.
//   - materialsManager [model.CryptoMaterialsManager]: The manager that provides the cryptographic materials.
//
// Returns:
//
//   - []byte: The decrypted data.
//   - [format.MessageHeader]: The header of the encrypted message.
//   - error: An error if decryption fails.
func (c *Client) Decrypt(ctx context.Context, ciphertext []byte, materialsManager model.CryptoMaterialsManager) ([]byte, format.MessageHeader, error) {
	b, header, err := crypto.Decrypt(ctx, c.clientConfig(), ciphertext, materialsManager)
	if err != nil {
		return nil, nil, err
	}
	return b, header, nil
}
