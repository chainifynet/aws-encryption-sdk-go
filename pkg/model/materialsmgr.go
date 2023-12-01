// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"crypto/ecdsa"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type CryptoMaterialsManager interface {
	GetEncryptionMaterials(ctx context.Context, request EncryptionMaterialsRequest) (EncryptionMaterial, error)
	DecryptMaterials(ctx context.Context, request DecryptionMaterialsRequest) (DecryptionMaterial, error)
	GetInstance() CryptoMaterialsManager // TODO research and test
}

type DecryptionMaterial interface {
	DataKey() DataKeyI
	VerificationKey() []byte
}

type EncryptionMaterial interface {
	DataEncryptionKey() DataKeyI
	EncryptedDataKeys() []EncryptedDataKeyI
	EncryptionContext() suite.EncryptionContext
	SigningKey() *ecdsa.PrivateKey
}
