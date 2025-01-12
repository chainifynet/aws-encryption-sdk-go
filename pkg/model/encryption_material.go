// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"crypto/ecdsa"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// EncryptionMaterialsRequest is a request to get [EncryptionMaterial] from a [CryptoMaterialsManager].
type EncryptionMaterialsRequest struct {
	// EncryptionContext is a map of key-value pairs that will be used to generate
	// primary data key, and encrypt other data keys.
	EncryptionContext suite.EncryptionContext

	// Algorithm is the algorithm to be used for encryption.
	Algorithm *suite.AlgorithmSuite

	// PlaintextLength is the length of the plaintext to be encrypted.
	PlaintextLength int
}

// EncryptionMaterials contains the encryption materials produced by a [CryptoMaterialsManager].
type EncryptionMaterials struct {
	dataEncryptionKey DataKeyI
	encryptedDataKeys []EncryptedDataKeyI
	encryptionContext suite.EncryptionContext
	signingKey        *ecdsa.PrivateKey
}

// NewEncryptionMaterials returns a new instance of [EncryptionMaterials].
func NewEncryptionMaterials(dataEncryptionKey DataKeyI, encryptedDataKeys []EncryptedDataKeyI, ec suite.EncryptionContext, signingKey *ecdsa.PrivateKey) EncryptionMaterial {
	return &EncryptionMaterials{dataEncryptionKey: dataEncryptionKey, encryptedDataKeys: encryptedDataKeys, encryptionContext: ec, signingKey: signingKey}
}

// DataEncryptionKey returns the data encryption key to be used for encryption.
func (e EncryptionMaterials) DataEncryptionKey() DataKeyI {
	return e.dataEncryptionKey
}

// EncryptedDataKeys returns the encrypted data keys encrypted with primary master key provider data key.
func (e EncryptionMaterials) EncryptedDataKeys() []EncryptedDataKeyI {
	return e.encryptedDataKeys
}

// EncryptionContext returns the encryption context associated with the encryption.
func (e EncryptionMaterials) EncryptionContext() suite.EncryptionContext {
	return e.encryptionContext
}

// SigningKey returns the signing key used to sign the footer. It returns nil if
// non-signing algorithm is used.
func (e EncryptionMaterials) SigningKey() *ecdsa.PrivateKey {
	return e.signingKey
}

// DecryptionMaterialsRequest is a request to get [DecryptionMaterial] from a [CryptoMaterialsManager].
type DecryptionMaterialsRequest struct {
	// Algorithm is the algorithm to be used for decryption.
	Algorithm *suite.AlgorithmSuite

	// EncryptedDataKeys is a list of encrypted data keys to decrypt data key.
	EncryptedDataKeys []EncryptedDataKeyI

	// EncryptionContext is a map of key-value pairs that will be used to decrypt data keys.
	EncryptionContext suite.EncryptionContext
}

// DecryptionMaterials contains the decryption materials produced by a [CryptoMaterialsManager].
type DecryptionMaterials struct {
	dataKey         DataKeyI
	verificationKey []byte
}

// NewDecryptionMaterials returns a new instance of [DecryptionMaterials].
func NewDecryptionMaterials(dataKey DataKeyI, verificationKey []byte) DecryptionMaterial {
	return &DecryptionMaterials{dataKey: dataKey, verificationKey: verificationKey}
}

// DataKey returns the data encryption key to be used for decryption.
func (d DecryptionMaterials) DataKey() DataKeyI {
	return d.dataKey
}

// VerificationKey returns a verification key used to verify footer signature. It
// returns nil if non-signing algorithm is used.
func (d DecryptionMaterials) VerificationKey() []byte {
	return d.verificationKey
}
