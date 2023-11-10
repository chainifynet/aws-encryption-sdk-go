// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/rs/zerolog"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/arn"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var (
	log = logger.L().Level(zerolog.DebugLevel) //nolint:gochecknoglobals
)

type KmsKeyProviderI interface {
	MasterKeyProvider
	getClient(ctx context.Context, keyID string) (*kms.Client, error)
}

func NewKmsKeyProviderWithOpts(keyIDs []string, optFns ...func(options *KmsProviderOptions) error) (*KmsKeyProvider[keys.KmsMasterKeyI], error) {
	var options KmsProviderOptions
	for _, optFn := range optFns {
		if err := optFn(&options); err != nil {
			return nil, fmt.Errorf("provider config error: %w", errors.Join(ErrMasterKeyProvider, err))
		}
	}

	p := newKmsKeyProvider(&options)
	if len(keyIDs) > 0 {
		for _, keyID := range keyIDs {
			if _, err := p.addMasterKey(keyID); err != nil {
				return nil, fmt.Errorf("add MasterKey error: %w", errors.Join(ErrMasterKeyProvider, err))
			}
		}
	}
	return p, nil
}

func NewKmsKeyProvider(keyIDs ...string) (*KmsKeyProvider[keys.KmsMasterKeyI], error) {
	return NewKmsKeyProviderWithOpts(keyIDs)
}

func newKmsKeyProvider(options *KmsProviderOptions) *KmsKeyProvider[keys.KmsMasterKeyI] {
	return &KmsKeyProvider[keys.KmsMasterKeyI]{
		keyProvider:          newKeyProvider(_kmsProviderID, AwsKms),
		options:              *options,
		regionalClients:      make(map[string]*kms.Client, 5),                       // increase if needed
		keyEntriesForEncrypt: make(map[string]keys.KeyEntry[keys.KmsMasterKeyI], 5), // increase if needed
		keyEntriesForDecrypt: make(map[string]keys.KeyEntry[keys.KmsMasterKeyI], 5), // increase if needed
	}
}

type KmsKeyProvider[KT keys.KmsMasterKeyI] struct {
	keyProvider      *KeyProvider
	primaryMasterKey *keys.KeyEntry[KT]

	options KmsProviderOptions

	regionalClients map[string]*kms.Client

	// keyEntriesForEncrypt where keys.KeyEntry not a pointer
	keyEntriesForEncrypt map[string]keys.KeyEntry[KT]
	keyEntriesForDecrypt map[string]keys.KeyEntry[KT] // keyEntriesForDecrypt where keys.KeyEntry not a pointer
}

func (kmsKP *KmsKeyProvider[KT]) Provider() *KeyProvider {
	return kmsKP.keyProvider
}

func (kmsKP *KmsKeyProvider[KT]) ValidateProviderID(otherID string) error {
	if kmsKP.keyProvider.providerID != otherID {
		return fmt.Errorf("providerID %q doesnt match to with MasterKeyProvider ID %q", otherID, kmsKP.keyProvider.providerID)
	}
	return nil
}

func (kmsKP *KmsKeyProvider[KT]) validateMasterKey(keyID string) error {
	if err := arn.ValidateKeyArn(keyID); err != nil {
		return fmt.Errorf("invalid keyID %q: %w", keyID, err)
	}
	if kmsKP.options.discovery && kmsKP.options.discoveryFilter != nil {
		if !kmsKP.options.discoveryFilter.IsAllowed(keyID) {
			return fmt.Errorf("keyID %q is not allowed by discovery filter", keyID)
		}
	}
	return nil
}

func (kmsKP *KmsKeyProvider[KT]) addMasterKey(keyID string) (keys.MasterKeyBase, error) {
	if err := kmsKP.validateMasterKey(keyID); err != nil {
		return nil, err
	}
	if _, exists := kmsKP.keyEntriesForEncrypt[keyID]; !exists {
		// TODO fix context at the some point
		key, err := kmsKP.newMasterKey(context.Background(), keyID)
		if err != nil {
			// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
			return nil, err
		}

		castKey := key.(KT)

		kmsKeyEntry := keys.NewKeyEntryPtr(castKey)

		if kmsKP.primaryMasterKey == nil {
			kmsKP.primaryMasterKey = kmsKeyEntry
		}

		// kmsKeyEntry2 := keys.NewKmsKeyEntry[keys.KmsMasterKeyI](act)
		// kmsKeyEntry := keys.NewKeyEntryPtr(castKey)
		// kmsKP.KeyEntriesIFaceGene[key.KeyID()] = kmsKeyEntry

		kmsKeyEntry2 := keys.NewKeyEntry(castKey)
		kmsKP.keyEntriesForEncrypt[key.KeyID()] = kmsKeyEntry2
	}

	// TODO andrew cover with tests, the issue will appear
	if kmsKP.primaryMasterKey == nil {
		kmsKP.primaryMasterKey = keys.NewKeyEntryPtr(kmsKP.keyEntriesForEncrypt[keyID].GetEntry())
	}

	return kmsKP.keyEntriesForEncrypt[keyID].GetEntry(), nil
}

func (kmsKP *KmsKeyProvider[KT]) newMasterKey(ctx context.Context, keyID string) (keys.MasterKeyBase, error) {
	client, err := kmsKP.getClient(ctx, keyID)
	if err != nil {
		return nil, err
	}
	key := keys.NewKmsMasterKey(client, keyID)
	return key, nil
}

func (kmsKP *KmsKeyProvider[KT]) getClient(ctx context.Context, keyID string) (*kms.Client, error) {
	// TODO add configurable default region
	regionName, err := regionForKeyID(keyID, "")
	if err != nil {
		return nil, fmt.Errorf("KMS client error: %w", err)
	}
	kmsKP.addRegionalClient(ctx, regionName)
	log.Trace().
		Str("region", regionName).
		Str("keyID", keyID).
		Msg("GET regional KMS client")
	return kmsKP.regionalClients[regionName], nil
}

func (kmsKP *KmsKeyProvider[KT]) addRegionalClient(ctx context.Context, region string) {
	// do nothing if requested KMS client already registered for a region
	if structs.MapContains(kmsKP.regionalClients, region) {
		return
	}

	opts := append(kmsKP.options.awsLoadOptions, config.WithRegion(region)) //nolint:gocritic

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		log.Error().Err(err).Msg("unable to load Custom SDK config")
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		// TODO andrew refactor return error
	}
	log.Trace().
		Str("region", region).
		Msg("Register new regional KMS client")
	kmsClient := kms.NewFromConfig(cfg)
	kmsKP.regionalClients[region] = kmsClient
}

func (kmsKP *KmsKeyProvider[KT]) MasterKeysForEncryption(_ context.Context, _ suite.EncryptionContext, _ []byte, _ int) (keys.MasterKeyBase, []keys.MasterKeyBase, error) {
	if kmsKP.primaryMasterKey == nil {
		return nil, nil, fmt.Errorf("KmsKeyProvider no primary key: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderEncrypt, ErrMasterKeyProviderNoPrimaryKey))
	}
	members := make([]keys.MasterKeyBase, 0, len(kmsKP.keyEntriesForEncrypt))
	for _, k := range kmsKP.keyEntriesForEncrypt {
		memberMasterKey := k.GetEntry()
		members = append(members, memberMasterKey)
	}

	if len(members) > 0 {
		return kmsKP.primaryMasterKey.GetEntry(), members, nil
	}

	return kmsKP.primaryMasterKey.GetEntry(), nil, nil
}

func (kmsKP *KmsKeyProvider[KT]) MasterKeyForDecrypt(ctx context.Context, metadata keys.KeyMeta) (keys.MasterKeyBase, error) {
	if err := kmsKP.ValidateProviderID(metadata.ProviderID); err != nil {
		return nil, fmt.Errorf("MasterKeyForDecrypt: %w", errors.Join(ErrMasterKeyProvider, err))
	}
	if err := kmsKP.validateMasterKey(metadata.KeyID); err != nil {
		return nil, fmt.Errorf("MasterKeyForDecrypt: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderDecryptForbidden, err))
	}

	// first check available keys for Encrypt
	if mkForEncrypt, ok := kmsKP.keyEntriesForEncrypt[metadata.KeyID]; ok {
		return mkForEncrypt.GetEntry(), nil
	}

	if !kmsKP.options.discovery {
		return nil, fmt.Errorf("MasterKeyForDecrypt: discovery not enabled: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderDecryptForbidden))
	}

	// then check available keys for Decrypt
	if mkForDecrypt, ok := kmsKP.keyEntriesForDecrypt[metadata.KeyID]; ok {
		return mkForDecrypt.GetEntry(), nil
	}

	decryptMasterKey, err := kmsKP.newMasterKey(ctx, metadata.KeyID)
	if err != nil {
		return nil, fmt.Errorf("MasterKeyForDecrypt error: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderDecrypt, err))
	}

	kmsKP.keyEntriesForDecrypt[metadata.KeyID] = keys.NewKeyEntry(decryptMasterKey.(KT))

	return decryptMasterKey, nil
}

func (kmsKP *KmsKeyProvider[KT]) masterKeysForDecryption() []keys.MasterKeyBase {
	var allMembers []keys.MasterKeyBase
	var allMemberKeys []string

	// only if discovery filter is set
	if kmsKP.options.discovery && kmsKP.options.discoveryFilter != nil {
		for keyID, entry := range kmsKP.keyEntriesForDecrypt {
			if !structs.Contains(allMemberKeys, keyID) {
				allMembers = append(allMembers, entry.GetEntry())
				allMemberKeys = append(allMemberKeys, keyID)
			}
		}
	}

	for keyID, entry := range kmsKP.keyEntriesForEncrypt {
		if !structs.Contains(allMemberKeys, keyID) {
			allMembers = append(allMembers, entry.GetEntry())
			allMemberKeys = append(allMemberKeys, keyID)
		}
	}

	return allMembers
}

func (kmsKP *KmsKeyProvider[KT]) DecryptDataKey(ctx context.Context, encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	dataKey, err := kmsKP.keyProvider.decryptDataKey(ctx, kmsKP, encryptedDataKey, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

// DecryptDataKeyFromList iterates through EDK, calls DecryptDataKey
func (kmsKP *KmsKeyProvider[KT]) DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	dataKey, err := kmsKP.keyProvider.decryptDataKeyFromList(ctx, kmsKP, encryptedDataKeys, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

// var _ MasterKeyProvider = (*KmsKeyProvider[keys.MasterKeyBase])(nil)
var _ MasterKeyProvider = (*KmsKeyProvider[keys.KmsMasterKeyI])(nil)

// var _ KmsKeyProviderI = (*KmsKeyProvider[keys.MasterKeyBase])(nil)
var _ KmsKeyProviderI = (*KmsKeyProvider[keys.KmsMasterKeyI])(nil)

func regionForKeyID(keyID, defaultRegion string) (string, error) {
	parts := strings.Split(keyID, ":")
	if len(parts) < 3 { //nolint:gomnd
		// minimum chars in AWS region, i.e. sa-east-1
		if len(defaultRegion) >= _awsRegionMinLength {
			return defaultRegion, nil
		}
		return "", fmt.Errorf("InvalidRegionError: KeyID %v", keyID)
	}

	if len(parts[3]) >= _awsRegionMinLength {
		return parts[3], nil
	}

	return "", fmt.Errorf("UnknownRegionError: KeyID %v", keyID)
}
