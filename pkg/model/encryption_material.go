// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"crypto/ecdsa"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type EncryptionMaterialsRequest struct {
	EncryptionContext suite.EncryptionContext
	Algorithm         *suite.AlgorithmSuite
	PlaintextLength   int
}

type EncryptionMaterials struct {
	dataEncryptionKey DataKeyI
	encryptedDataKeys []EncryptedDataKeyI
	encryptionContext suite.EncryptionContext
	signingKey        *ecdsa.PrivateKey
}

func NewEncryptionMaterials(dataEncryptionKey DataKeyI, encryptedDataKeys []EncryptedDataKeyI, ec suite.EncryptionContext, signingKey *ecdsa.PrivateKey) *EncryptionMaterials {
	return &EncryptionMaterials{dataEncryptionKey: dataEncryptionKey, encryptedDataKeys: encryptedDataKeys, encryptionContext: ec, signingKey: signingKey}
}

func (e EncryptionMaterials) DataEncryptionKey() DataKeyI {
	return e.dataEncryptionKey
}

func (e EncryptionMaterials) EncryptedDataKeys() []EncryptedDataKeyI {
	return e.encryptedDataKeys
}

func (e EncryptionMaterials) EncryptionContext() suite.EncryptionContext {
	return e.encryptionContext
}

func (e EncryptionMaterials) SigningKey() *ecdsa.PrivateKey {
	return e.signingKey
}

type DecryptionMaterialsRequest struct {
	Algorithm         *suite.AlgorithmSuite
	EncryptedDataKeys []EncryptedDataKeyI
	EncryptionContext suite.EncryptionContext
}

type DecryptionMaterials struct {
	dataKey         DataKeyI
	verificationKey []byte
}

func NewDecryptionMaterials(dataKey DataKeyI, verificationKey []byte) *DecryptionMaterials {
	return &DecryptionMaterials{dataKey: dataKey, verificationKey: verificationKey}
}

func (d DecryptionMaterials) DataKey() DataKeyI {
	return d.dataKey
}

func (d DecryptionMaterials) VerificationKey() []byte {
	return d.verificationKey
}
