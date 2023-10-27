// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors

type ProviderBase interface {
	ProviderID() string
	ValidateProviderID(otherID string) error
}

type MasterKeyProvider interface {
	ProviderBase

	// addMasterKey adds master key
	addMasterKey(keyID string) (keys.MasterKeyBase, error)
	newMasterKey(keyID string) (keys.MasterKeyBase, error)
	MasterKeysForEncryption(ec suite.EncryptionContext, plaintextRoStream []byte, plaintextLength int) (keys.MasterKeyBase, []keys.MasterKeyBase, error)
	// Deprecated: TODO andrew remove unused
	MasterKeyForEncrypt(keyID string) (keys.MasterKeyBase, error) // TODO andrew remove unused
	// Deprecated: TODO andrew remove unused
	MasterKeyForEncryptByKeyMetadata(metadata keys.KeyMeta) (keys.MasterKeyBase, error) // TODO andrew remove unused
	MasterKeyForDecrypt(metadata keys.KeyMeta) (keys.MasterKeyBase, error)
	DecryptDataKey(encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error)
	DecryptDataKeyFromList(encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error)
	validateMasterKey(keyID string) error
}
