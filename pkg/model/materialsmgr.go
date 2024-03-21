// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"crypto/ecdsa"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// CryptoMaterialsManager is an interface for crypto materials manager implementations.
type CryptoMaterialsManager interface {
	// GetEncryptionMaterials returns the encryption materials for the given request.
	// Used during encryption process to get the encryption materials from registered
	// master key providers.
	GetEncryptionMaterials(ctx context.Context, request EncryptionMaterialsRequest) (EncryptionMaterial, error)

	// DecryptMaterials returns the decryption materials for the given request. Used
	// during decryption process to get the decryption materials from registered
	// master key providers.
	DecryptMaterials(ctx context.Context, request DecryptionMaterialsRequest) (DecryptionMaterial, error)

	// GetInstance returns a new instance of the crypto materials manager to interact
	// within encryption/decryption process.
	GetInstance() CryptoMaterialsManager
}

// DecryptionMaterial is an interface for decryption material.
type DecryptionMaterial interface {
	// DataKey returns the data key used for decryption.
	DataKey() DataKeyI

	// VerificationKey returns a verification key used to verify footer signature. It
	// returns nil if non-signing algorithm is used.
	VerificationKey() []byte
}

// EncryptionMaterial is an interface for encryption material.
type EncryptionMaterial interface {
	// DataEncryptionKey returns the data encryption key to be used for encryption.
	DataEncryptionKey() DataKeyI

	// EncryptedDataKeys returns the encrypted data keys encrypted with primary
	// master key provider data key.
	EncryptedDataKeys() []EncryptedDataKeyI

	// EncryptionContext returns the encryption context associated with the encryption.
	EncryptionContext() suite.EncryptionContext

	// SigningKey returns the signing key used to sign the footer. It returns nil if
	// non-signing algorithm is used.
	SigningKey() *ecdsa.PrivateKey
}
