// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package myprovider provides a custom [model.MasterKeyProvider] implementation.
//
// # Don't use this implementation in production
//
// [MyProvider] and [mykey.MyKey] implementation using base64 encoding for
// demonstration purposes only.
package myprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go-tests/example/customKeyProvider/mykey"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// MyProvider is a custom [model.MasterKeyProvider] implementation.
//
// # Don't use this implementation in production
//
// [MyProvider] and [mykey.MyKey] implementations using base64 encoding for
// demonstration purposes only.
type MyProvider struct {
	// keyProvider is a [keyprovider.KeyProvider] instance.
	keyProvider model.BaseKeyProvider

	// keyFactory is a [model.MasterKeyFactory] instance of [mykey.KeyFactory].
	keyFactory model.MasterKeyFactory

	// primaryMasterKey is a primary [model.MasterKey] instance.
	primaryMasterKey model.MasterKey

	// keyRegistry is a map of [model.MasterKey] instances.
	keyRegistry map[string]model.MasterKey
}

var _ model.MasterKeyProvider = (*MyProvider)(nil)

// NewMyProvider creates a new [MyProvider] with the given providerID and keyIDs.
//
// It uses [mykey.KeyFactory] factory to create [model.MasterKey] keys.
func NewMyProvider(providerID string, keyIDs ...string) (*MyProvider, error) {
	if len(keyIDs) == 0 {
		return nil, fmt.Errorf("no keyIDs provided: %w", providers.ErrConfig)
	}

	// create MyProvider
	p := &MyProvider{
		// assign keyProvider with types.Custom kind.
		keyProvider: keyprovider.NewKeyProvider(providerID, types.Custom, false),

		// use mykey.KeyFactory that will be used to create model.MasterKey keys.
		keyFactory: &mykey.KeyFactory{},

		// initialize keyRegistry map.
		keyRegistry: make(map[string]model.MasterKey, len(keyIDs)),
	}

	// register each keyID with the provider
	for _, keyID := range keyIDs {
		if _, err := p.AddMasterKey(keyID); err != nil {
			return nil, fmt.Errorf("add MasterKey error: %w", errors.Join(providers.ErrMasterKeyProvider, err))
		}
	}

	return p, nil
}

// ProviderKind returns the provider kind.
func (mp *MyProvider) ProviderKind() types.ProviderKind {
	return mp.keyProvider.Kind()
}

// ProviderID returns the provider ID.
func (mp *MyProvider) ProviderID() string {
	return mp.keyProvider.ID()
}

// ValidateProviderID validates the provider ID.
func (mp *MyProvider) ValidateProviderID(otherID string) error {
	if mp.keyProvider.ID() != otherID {
		return fmt.Errorf("%q providerID doesnt match to with MasterKeyProvider ID %q", otherID, mp.keyProvider.ID())
	}
	return nil
}

// AddMasterKey adds a new [model.MasterKey] with the given keyID to the provider.
func (mp *MyProvider) AddMasterKey(keyID string) (model.MasterKey, error) {
	if err := mp.ValidateMasterKey(keyID); err != nil {
		return nil, err
	}
	if _, exists := mp.keyRegistry[keyID]; !exists {
		key, err := mp.NewMasterKey(context.Background(), keyID)
		if err != nil {
			return nil, err
		}

		if mp.primaryMasterKey == nil {
			mp.primaryMasterKey = key
		}

		mp.keyRegistry[key.KeyID()] = key
	}
	return mp.keyRegistry[keyID], nil
}

// NewMasterKey creates a new [model.MasterKey] with the given keyID via [mykey.KeyFactory].
func (mp *MyProvider) NewMasterKey(_ context.Context, keyID string) (model.MasterKey, error) {
	key, err := mp.keyFactory.NewMasterKey(mp.keyProvider.ID(), keyID)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// MasterKeysForEncryption returns the primary master key and a list of master
// keys for encryption.
func (mp *MyProvider) MasterKeysForEncryption(context.Context, suite.EncryptionContext) (model.MasterKey, []model.MasterKey, error) {
	if mp.primaryMasterKey == nil {
		return nil, nil, fmt.Errorf("no primary key: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderEncrypt, providers.ErrMasterKeyProviderNoPrimaryKey))
	}
	members := make([]model.MasterKey, 0, len(mp.keyRegistry))

	for _, k := range mp.keyRegistry {
		members = append(members, k)
	}

	if len(members) > 0 {
		return mp.primaryMasterKey, members, nil
	}

	return mp.primaryMasterKey, nil, nil
}

// MasterKeyForDecrypt always returns an error because [MyProvider] doesn't
// support vend data keys for decryption.
func (mp *MyProvider) MasterKeyForDecrypt(context.Context, model.KeyMeta) (model.MasterKey, error) {
	// should be never requested because VendOnDecrypt is false for Non-AWS providers
	return nil, fmt.Errorf("MasterKeyForDecrypt not allowed: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecrypt))
}

// DecryptDataKey attempts to decrypt the encrypted data key with a KeyProvider.
func (mp *MyProvider) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, err := mp.keyProvider.DecryptDataKey(ctx, mp, encryptedDataKey, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

// DecryptDataKeyFromList attempts to decrypt data key from the encrypted data
// keys with a KeyProvider.
func (mp *MyProvider) DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, err := mp.keyProvider.DecryptDataKeyFromList(ctx, mp, encryptedDataKeys, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

// ValidateMasterKey validates the given keyID are registered in the provider.
//
// Validation is done by checking the length of the keyID for demonstration
// purposes only.
func (mp *MyProvider) ValidateMasterKey(keyID string) error {
	if len(keyID) <= 3 {
		return fmt.Errorf("invalid keyID %q", keyID)
	}
	return nil
}

// MasterKeysForDecryption returns the list of master keys registered for
// decryption with the [MyProvider].
//
// This method is used by keyprovider.KeyProvider.
func (mp *MyProvider) MasterKeysForDecryption() []model.MasterKey {
	members := make([]model.MasterKey, 0, len(mp.keyRegistry))
	for _, k := range mp.keyRegistry {
		members = append(members, k)
	}
	return members
}
