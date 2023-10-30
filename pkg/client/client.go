// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var MaterialsManager materialsManager //nolint:gochecknoglobals

type materialsManager struct{}

func (materialsManager) NewCMM(keyProvider providers.MasterKeyProvider) materials.CryptoMaterialsManager {
	return materials.CMM.NewDefault(keyProvider)
}

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
	Decrypt(ciphertext []byte, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error)
	Encrypt(source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error)
	EncryptWithOpts(source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error)
}

var _ BaseClient = (*Client)(nil)

type Client struct {
	config clientconfig.ClientConfig
}

func (c *Client) clientConfig() clientconfig.ClientConfig {
	return c.config
}

func (c *Client) EncryptWithOpts(source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager, algorithm *suite.AlgorithmSuite, frameLength int) ([]byte, *serialization.MessageHeader, error) {
	ciphertext, header, err := crypto.EncryptWithOpts(c.clientConfig(), source, ec, materialsManager, algorithm, frameLength)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, header, nil
}

func (c *Client) Encrypt(source []byte, ec suite.EncryptionContext, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	ciphertext, header, err := crypto.Encrypt(c.clientConfig(), source, ec, materialsManager)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, header, nil
}

func (c *Client) Decrypt(ciphertext []byte, materialsManager materials.CryptoMaterialsManager) ([]byte, *serialization.MessageHeader, error) {
	b, header, err := crypto.Decrypt(c.clientConfig(), ciphertext, materialsManager)
	if err != nil {
		return nil, nil, err
	}
	return b, header, nil
}
