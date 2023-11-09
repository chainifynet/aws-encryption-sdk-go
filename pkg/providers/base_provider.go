// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var (
	ErrMasterKeyProvider             = errors.New("MKP error")
	ErrMasterKeyProviderDecrypt      = errors.New("MKP decrypt error")
	ErrMasterKeyProviderEncrypt      = errors.New("MKP encrypt error")
	ErrMasterKeyProviderNoPrimaryKey = errors.New("MKP no primary key")
)

type ProviderBase interface {
	Provider() *KeyProvider
	ValidateProviderID(otherID string) error
}

type MasterKeyProvider interface {
	ProviderBase

	addMasterKey(keyID string) (keys.MasterKeyBase, error)
	newMasterKey(ctx context.Context, keyID string) (keys.MasterKeyBase, error)
	MasterKeysForEncryption(ctx context.Context, ec suite.EncryptionContext, plaintextRoStream []byte, plaintextLength int) (keys.MasterKeyBase, []keys.MasterKeyBase, error)
	MasterKeyForDecrypt(ctx context.Context, metadata keys.KeyMeta) (keys.MasterKeyBase, error)
	DecryptDataKey(ctx context.Context, encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error)
	DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error)
	validateMasterKey(keyID string) error
	masterKeysForDecryption() []keys.MasterKeyBase
}
