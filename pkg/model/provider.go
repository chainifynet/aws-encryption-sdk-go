// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type BaseKeyProvider interface {
	ID() string
	Kind() types.ProviderKind
	VendOnDecrypt() bool
	DecryptDataKey(ctx context.Context, MKP MasterKeyProvider, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
	DecryptDataKeyFromList(ctx context.Context, MKP MasterKeyProvider, encryptedDataKeys []EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
}

type ProviderBase interface {
	ProviderKind() types.ProviderKind
	ProviderID() string
	ValidateProviderID(otherID string) error
}

type MasterKeyProvider interface {
	ProviderBase

	AddMasterKey(keyID string) (MasterKey, error)
	NewMasterKey(ctx context.Context, keyID string) (MasterKey, error)
	MasterKeysForEncryption(ctx context.Context, ec suite.EncryptionContext) (MasterKey, []MasterKey, error)
	MasterKeyForDecrypt(ctx context.Context, metadata KeyMeta) (MasterKey, error)
	DecryptDataKey(ctx context.Context, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
	DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
	ValidateMasterKey(keyID string) error
	MasterKeysForDecryption() []MasterKey
}
