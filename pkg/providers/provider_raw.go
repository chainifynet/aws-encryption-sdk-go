// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func NewRawKeyProviderWithOpts(providerID string, optFns ...func(options *RawProviderOptions) error) (*RawKeyProvider[keys.RawMasterKeyI], error) {
	if providerID == "" {
		return nil, fmt.Errorf("providerID must not be empty: %w", ErrMasterKeyProvider)
	}
	if providerID == _kmsProviderID {
		return nil, fmt.Errorf("providerID %q is reserved for AWS: %w", providerID, ErrMasterKeyProvider)
	}
	var options RawProviderOptions
	for _, optFn := range optFns {
		if err := optFn(&options); err != nil {
			return nil, fmt.Errorf("provider option error: %w", errors.Join(ErrMasterKeyProvider, err))
		}
	}
	p := newRawKeyProvider(providerID, &options)
	p.staticKeys = options.staticKeys
	for keyID := range p.staticKeys {
		if _, err := p.addMasterKey(keyID); err != nil {
			return nil, fmt.Errorf("add MasterKey error: %w", errors.Join(ErrMasterKeyProvider, err))
		}
	}
	return p, nil
}

func newRawKeyProvider(providerID string, options *RawProviderOptions) *RawKeyProvider[keys.RawMasterKeyI] {
	return &RawKeyProvider[keys.RawMasterKeyI]{
		keyProvider:          newKeyProvider(providerID, Raw),
		staticKeys:           make(map[string][]byte, 5), // increase if needed
		options:              *options,
		keyEntriesForEncrypt: make(map[string]*keys.KeyEntry[keys.RawMasterKeyI], 5), // increase if needed
		keyEntriesForDecrypt: make(map[string]*keys.KeyEntry[keys.RawMasterKeyI], 5), // increase if needed
	}
}

type RawKeyProviderI interface {
	MasterKeyProvider
	getStaticKey(keyID string) ([]byte, error)
}

type RawKeyProvider[KT keys.RawMasterKeyI] struct {
	keyProvider      *KeyProvider
	primaryMasterKey *keys.KeyEntry[KT]

	staticKeys map[string][]byte

	options RawProviderOptions

	keyEntriesForEncrypt map[string]*keys.KeyEntry[KT]
	keyEntriesForDecrypt map[string]*keys.KeyEntry[KT]
}

func (rawKP *RawKeyProvider[KT]) Provider() *KeyProvider {
	return rawKP.keyProvider
}

func (rawKP *RawKeyProvider[KT]) ValidateProviderID(otherID string) error {
	if rawKP.keyProvider.providerID != otherID {
		return fmt.Errorf("providerID %q doesnt match to with MasterKeyProvider ID %q", otherID, rawKP.keyProvider.providerID)
	}
	return nil
}

func (rawKP *RawKeyProvider[KT]) validateMasterKey(keyID string) error {
	// TODO implement validation
	if keyID == "" {
		return fmt.Errorf("invalid keyID")
	}
	return nil
}

func (rawKP *RawKeyProvider[KT]) addMasterKey(keyID string) (keys.MasterKeyBase, error) {
	if err := rawKP.validateMasterKey(keyID); err != nil {
		return nil, err
	}
	if _, exists := rawKP.keyEntriesForEncrypt[keyID]; !exists {
		key, err := rawKP.newMasterKey(context.Background(), keyID)
		if err != nil {
			// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
			return nil, err
		}

		castKey := key.(KT)

		kmsKeyEntry := keys.NewKeyEntryPtr(castKey)

		if rawKP.primaryMasterKey == nil {
			rawKP.primaryMasterKey = kmsKeyEntry
		}

		rawKP.keyEntriesForEncrypt[key.KeyID()] = kmsKeyEntry
	}

	// TODO andrew cover with tests, the issue will appear
	if rawKP.primaryMasterKey == nil {
		rawKP.primaryMasterKey = keys.NewKeyEntryPtr(rawKP.keyEntriesForEncrypt[keyID].GetEntry())
	}

	return rawKP.keyEntriesForEncrypt[keyID].GetEntry(), nil
}

func (rawKP *RawKeyProvider[KT]) getStaticKey(keyID string) ([]byte, error) {
	if !structs.MapContains(rawKP.staticKeys, keyID) {
		return nil, fmt.Errorf("staticKey %v doesnt exists", keyID)
	}
	return rawKP.staticKeys[keyID], nil
}

func (rawKP *RawKeyProvider[KT]) newMasterKey(_ context.Context, keyID string) (keys.MasterKeyBase, error) {
	staticKey, err := rawKP.getStaticKey(keyID)
	if err != nil {
		return nil, err
	}
	key, err := keys.NewRawMasterKey(rawKP.keyProvider.providerID, keyID, staticKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (rawKP *RawKeyProvider[KT]) MasterKeysForEncryption(_ context.Context, _ suite.EncryptionContext, _ []byte, _ int) (keys.MasterKeyBase, []keys.MasterKeyBase, error) {
	if rawKP.primaryMasterKey == nil {
		return nil, nil, fmt.Errorf("RawKeyProvider no primary key: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderEncrypt, ErrMasterKeyProviderNoPrimaryKey))
	}
	members := make([]keys.MasterKeyBase, 0, len(rawKP.keyEntriesForEncrypt))
	for _, k := range rawKP.keyEntriesForEncrypt {
		memberMasterKey := k.GetEntry()
		members = append(members, memberMasterKey)
	}

	if len(members) > 0 {
		return rawKP.primaryMasterKey.GetEntry(), members, nil
	}

	return rawKP.primaryMasterKey.GetEntry(), nil, nil
}

func (rawKP *RawKeyProvider[KT]) MasterKeyForDecrypt(ctx context.Context, metadata keys.KeyMeta) (keys.MasterKeyBase, error) {
	if err := rawKP.ValidateProviderID(metadata.ProviderID); err != nil {
		return nil, fmt.Errorf("MasterKeyForDecrypt: %w", errors.Join(ErrMasterKeyProvider, err))
	}
	if err := rawKP.validateMasterKey(metadata.KeyID); err != nil {
		return nil, fmt.Errorf("MasterKeyForDecrypt error: %w", errors.Join(ErrMasterKeyProvider, err))
	}
	if mkForEncrypt, ok := rawKP.keyEntriesForEncrypt[metadata.KeyID]; ok {
		return mkForEncrypt.GetEntry(), nil
	}

	if mkForDecrypt, ok := rawKP.keyEntriesForDecrypt[metadata.KeyID]; ok {
		return mkForDecrypt.GetEntry(), nil
	}

	decryptMasterKey, err := rawKP.newMasterKey(ctx, metadata.KeyID)
	if err != nil {
		return nil, fmt.Errorf("MasterKeyForDecrypt error: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderDecrypt, err))
	}

	rawKP.keyEntriesForDecrypt[metadata.KeyID] = keys.NewKeyEntryPtr(decryptMasterKey.(KT))

	return decryptMasterKey, nil
}

func (rawKP *RawKeyProvider[KT]) DecryptDataKey(ctx context.Context, encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	dataKey, err := rawKP.keyProvider.decryptDataKey(ctx, rawKP, encryptedDataKey, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

func (rawKP *RawKeyProvider[KT]) DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	dataKey, err := rawKP.keyProvider.decryptDataKeyFromList(ctx, rawKP, encryptedDataKeys, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

func (rawKP *RawKeyProvider[KT]) masterKeysForDecryption() []keys.MasterKeyBase {
	var allMembers []keys.MasterKeyBase
	var allMemberKeys []string

	for keyID, entry := range rawKP.keyEntriesForDecrypt {
		if !structs.Contains(allMemberKeys, keyID) {
			allMembers = append(allMembers, entry.GetEntry())
			allMemberKeys = append(allMemberKeys, keyID)
		}
	}

	for keyID, entry := range rawKP.keyEntriesForEncrypt {
		if !structs.Contains(allMemberKeys, keyID) {
			allMembers = append(allMembers, entry.GetEntry())
			allMemberKeys = append(allMemberKeys, keyID)
		}
	}

	return allMembers
}
