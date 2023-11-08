// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"crypto/ecdsa"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// EncryptionMaterialsRequest Request struct to provide to CryptoMaterialsManager.GetEncryptionMaterials method
// TODO might replace with interface to achieve compatibility in CryptoMaterialsManager interface
type EncryptionMaterialsRequest struct {
	EncryptionContext suite.EncryptionContext
	FrameLength       int    // TODO andrew remove unused
	PlaintextRoStream []byte // TODO andrew remove unused
	Algorithm         *suite.AlgorithmSuite
	PlaintextLength   int
	CommitmentPolicy  suite.CommitmentPolicy // TODO andrew remove unused
}

// EncryptionMaterials Encryption materials returned by CryptoMaterialsManager.GetEncryptionMaterials method
type EncryptionMaterials struct {
	algorithm         *suite.AlgorithmSuite // TODO andrew remove unused
	dataEncryptionKey keys.DataKeyI
	encryptedDataKeys []keys.EncryptedDataKeyI
	encryptionContext suite.EncryptionContext
	signingKey        *ecdsa.PrivateKey
}

// Algorithm
//
// Deprecated: TODO andrew remove unused
func (e EncryptionMaterials) Algorithm() *suite.AlgorithmSuite {
	return e.algorithm
}

func (e EncryptionMaterials) DataEncryptionKey() keys.DataKeyI {
	return e.dataEncryptionKey
}

func (e EncryptionMaterials) EncryptedDataKeys() []keys.EncryptedDataKeyI {
	return e.encryptedDataKeys
}

func (e EncryptionMaterials) EncryptionContext() suite.EncryptionContext {
	return e.encryptionContext
}

func (e EncryptionMaterials) SigningKey() *ecdsa.PrivateKey {
	return e.signingKey
}

// DecryptionMaterialsRequest Request struct to provide to CryptoMaterialsManager.DecryptMaterials method
type DecryptionMaterialsRequest struct {
	Algorithm         *suite.AlgorithmSuite
	EncryptedDataKeys []keys.EncryptedDataKeyI
	EncryptionContext suite.EncryptionContext
	CommitmentPolicy  suite.CommitmentPolicy // TODO andrew remove unused
}

// DecryptionMaterials Decryption materials returned by CryptoMaterialsManager.DecryptMaterials method
type DecryptionMaterials struct {
	dataKey         keys.DataKeyI
	verificationKey []byte
}

func (d DecryptionMaterials) DataKey() keys.DataKeyI {
	return d.dataKey
}

func (d DecryptionMaterials) VerificationKey() []byte {
	return d.verificationKey
}
