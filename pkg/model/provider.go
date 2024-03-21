// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// BaseKeyProvider is the base interface for key provider. It responsible for a
// logic of decrypting encrypted data keys for an abstract [MasterKeyProvider].
type BaseKeyProvider interface {
	// ID returns the ID of the key provider.
	ID() string

	// Kind returns the kind of the key provider.
	Kind() types.ProviderKind

	// VendOnDecrypt returns true if the key provider indicates that it can decrypt
	// encrypted data keys that is not registered with master key provider.
	VendOnDecrypt() bool

	// DecryptDataKey attempts to decrypt the encrypted data key and returns the data
	// key.
	DecryptDataKey(ctx context.Context, MKP MasterKeyProvider, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)

	// DecryptDataKeyFromList attempts to decrypt the encrypted data keys and returns
	// the data key.
	DecryptDataKeyFromList(ctx context.Context, MKP MasterKeyProvider, encryptedDataKeys []EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
}

// MasterKeyProvider is an interface for master key provider implementations.
type MasterKeyProvider interface { //nolint:interfacebloat
	// ProviderKind returns the kind of the master key provider.
	ProviderKind() types.ProviderKind

	// ProviderID returns the ID of the master key provider.
	ProviderID() string

	// ValidateProviderID validates master key provider ID matches the given provider ID.
	ValidateProviderID(otherID string) error

	// AddMasterKey creates a new master key and adds it to the master key provider.
	AddMasterKey(keyID string) (MasterKey, error)

	// NewMasterKey returns a new instance of master key.
	NewMasterKey(ctx context.Context, keyID string) (MasterKey, error)

	// MasterKeysForEncryption returns the primary master key and a list of master
	// keys for encryption.
	MasterKeysForEncryption(ctx context.Context, ec suite.EncryptionContext) (MasterKey, []MasterKey, error)

	// MasterKeyForDecrypt returns the master key for the given metadata.
	MasterKeyForDecrypt(ctx context.Context, metadata KeyMeta) (MasterKey, error)

	// DecryptDataKey attempts to decrypt the encrypted data key with a KeyProvider.
	DecryptDataKey(ctx context.Context, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)

	// DecryptDataKeyFromList attempts to decrypt the encrypted data keys with a
	// KeyProvider.
	DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)

	// ValidateMasterKey validates the master key with the given key ID.
	ValidateMasterKey(keyID string) error

	// MasterKeysForDecryption returns the list of master keys for decryption.
	MasterKeysForDecryption() []MasterKey
}
