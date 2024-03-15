// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/common"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys/raw"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func NewWithOpts(providerID string, optFns ...func(options *Options) error) (*RawKeyProvider[model.MasterKey], error) {
	options := Options{
		staticKeys: make(map[string][]byte, 5), // increase if needed
		configKeys: make([]staticKey, 0, 5),    // increase if needed
		keyFactory: &raw.KeyFactory{},
	}
	for _, optFn := range optFns {
		if err := optFn(&options); err != nil {
			return nil, fmt.Errorf("provider option error: %w", errors.Join(providers.ErrConfig, err))
		}
	}

	resolveKeyProvider(providerID, &options)

	if err := validateConfig(providerID, &options); err != nil {
		return nil, err
	}

	p := newRawProvider(&options)
	for keyID := range options.staticKeys {
		if _, err := p.AddMasterKey(keyID); err != nil {
			return nil, fmt.Errorf("add MasterKey error: %w", errors.Join(providers.ErrMasterKeyProvider, err))
		}
	}
	return p, nil
}

func newRawProvider(options *Options) *RawKeyProvider[model.MasterKey] {
	return &RawKeyProvider[model.MasterKey]{
		keyProvider:          options.keyProvider,
		options:              *options,
		keyEntriesForEncrypt: make(map[string]*common.KeyEntry[model.MasterKey], 5), // increase if needed
	}
}

type RawProvider interface {
	model.MasterKeyProvider
	getStaticKey(keyID string) ([]byte, error)
}

type RawKeyProvider[KT model.MasterKey] struct {
	keyProvider      model.BaseKeyProvider
	primaryMasterKey *common.KeyEntry[KT]

	options Options

	keyEntriesForEncrypt map[string]*common.KeyEntry[KT]
}

func (rawKP *RawKeyProvider[KT]) ProviderID() string {
	return rawKP.keyProvider.ID()
}

func (rawKP *RawKeyProvider[KT]) ProviderKind() types.ProviderKind {
	return rawKP.keyProvider.Kind()
}

func (rawKP *RawKeyProvider[KT]) ValidateProviderID(otherID string) error {
	if rawKP.keyProvider.ID() != otherID {
		return fmt.Errorf("%q providerID doesnt match to with MasterKeyProvider ID %q", otherID, rawKP.keyProvider.ID())
	}
	return nil
}

func (rawKP *RawKeyProvider[KT]) ValidateMasterKey(keyID string) error {
	sk, err := rawKP.getStaticKey(keyID)
	if err != nil {
		return err
	}
	return validateStaticKey(keyID, sk)
}

func (rawKP *RawKeyProvider[KT]) AddMasterKey(keyID string) (model.MasterKey, error) {
	if err := rawKP.ValidateMasterKey(keyID); err != nil {
		return nil, err
	}
	if _, exists := rawKP.keyEntriesForEncrypt[keyID]; !exists {
		key, err := rawKP.NewMasterKey(context.Background(), keyID)
		if err != nil {
			// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
			return nil, err
		}

		castKey := key.(KT)

		kmsKeyEntry := common.NewKeyEntryPtr(castKey)

		if rawKP.primaryMasterKey == nil {
			rawKP.primaryMasterKey = kmsKeyEntry
		}

		rawKP.keyEntriesForEncrypt[key.KeyID()] = kmsKeyEntry
	}

	return rawKP.keyEntriesForEncrypt[keyID].GetEntry(), nil
}

func (rawKP *RawKeyProvider[KT]) getStaticKey(keyID string) ([]byte, error) {
	if !structs.MapContains(rawKP.options.staticKeys, keyID) {
		return nil, fmt.Errorf("%q staticKey doesnt exists", keyID)
	}
	return rawKP.options.staticKeys[keyID], nil
}

func (rawKP *RawKeyProvider[KT]) NewMasterKey(_ context.Context, keyID string) (model.MasterKey, error) {
	sk, err := rawKP.getStaticKey(keyID)
	if err != nil {
		return nil, err
	}
	key, err := rawKP.options.keyFactory.NewMasterKey(rawKP.keyProvider.ID(), keyID, sk)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (rawKP *RawKeyProvider[KT]) MasterKeysForEncryption(_ context.Context, _ suite.EncryptionContext) (model.MasterKey, []model.MasterKey, error) {
	if rawKP.primaryMasterKey == nil {
		return nil, nil, fmt.Errorf("no primary key: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderEncrypt, providers.ErrMasterKeyProviderNoPrimaryKey))
	}
	members := make([]model.MasterKey, 0, len(rawKP.keyEntriesForEncrypt))
	for _, k := range rawKP.keyEntriesForEncrypt {
		memberMasterKey := k.GetEntry()
		members = append(members, memberMasterKey)
	}

	if len(members) > 0 {
		return rawKP.primaryMasterKey.GetEntry(), members, nil
	}

	return rawKP.primaryMasterKey.GetEntry(), nil, nil
}

func (rawKP *RawKeyProvider[KT]) MasterKeyForDecrypt(_ context.Context, _ model.KeyMeta) (model.MasterKey, error) {
	// should be never requested because VendOnDecrypt is false for RawKeyProvider
	return nil, fmt.Errorf("MasterKeyForDecrypt not allowed for RawKeyProvider: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecrypt))
}

func (rawKP *RawKeyProvider[KT]) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, err := rawKP.keyProvider.DecryptDataKey(ctx, rawKP, encryptedDataKey, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

func (rawKP *RawKeyProvider[KT]) DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, err := rawKP.keyProvider.DecryptDataKeyFromList(ctx, rawKP, encryptedDataKeys, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

func (rawKP *RawKeyProvider[KT]) MasterKeysForDecryption() []model.MasterKey {
	var allMembers []model.MasterKey
	var allMemberKeys []string

	for keyID, entry := range rawKP.keyEntriesForEncrypt {
		if !structs.Contains(allMemberKeys, keyID) {
			allMembers = append(allMembers, entry.GetEntry())
			allMemberKeys = append(allMemberKeys, keyID)
		}
	}

	return allMembers
}

// checking that RawKeyProvider implements both model.MasterKeyProvider and RawProvider interfaces.
var _ model.MasterKeyProvider = (*RawKeyProvider[raw.KeyHandler])(nil)
var _ model.MasterKeyProvider = (*RawKeyProvider[model.MasterKey])(nil)

var _ RawProvider = (*RawKeyProvider[model.MasterKey])(nil)
var _ RawProvider = (*RawKeyProvider[raw.KeyHandler])(nil)
