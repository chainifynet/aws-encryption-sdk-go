// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/common"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys/kms"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/arn"
)

// KmsProvider is an interface for KMS providers.
type KmsProvider interface {
	model.MasterKeyProvider
	getClient(ctx context.Context, keyID string) (model.KMSClient, error)
}

// NewWithOpts creates a new [KmsKeyProvider] with the given keyIDs.
//
// It also accepts an optional variadic set of functional [Options] for configuring the provider.
//
// See usage below and check [examples] for more detailed usage.
//
// Example [StrictKmsProvider] with custom AWS config:
//
//	keyID := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    []string{keyID},
//	    kmsprovider.WithAwsLoadOptions(
//	        // add more AWS Config options if needed
//	        config.WithSharedConfigProfile("your_profile_name"),
//	        config.WithRegion("us-west-2"),
//	    ),
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [MrkAwareStrictKmsProvider]:
//
//	keyID := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    []string{keyID},                // KMS CMK ARNs
//	    kmsprovider.WithMrkAwareness(), // enable MRK-aware
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [DiscoveryKmsProvider] with discovery filter:
//
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    nil,
//	    // enable discovery, and filter by accountIDs and partition
//	    kmsprovider.WithDiscoveryFilter([]string{"123456789011"}, "aws"),
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [MrkAwareDiscoveryKmsProvider] with discovery region and filter:
//
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    nil,
//	    // enable discovery, and filter by accountIDs and partition
//	    kmsprovider.WithDiscoveryFilter([]string{"123456789011"}, "aws"),
//	    kmsprovider.WithMrkAwareness(),               // enable MRK-aware
//	    kmsprovider.WithDiscoveryRegion("us-west-2"), // specify region for discovery
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// [examples]: https://github.com/chainifynet/aws-encryption-sdk-go/tree/main/example
func NewWithOpts(keyIDs []string, optFns ...func(options *Options) error) (*KmsKeyProvider[model.MasterKey], error) {
	var options Options
	for _, optFn := range optFns {
		if err := optFn(&options); err != nil {
			return nil, fmt.Errorf("provider config error: %w", errors.Join(providers.ErrConfig, err))
		}
	}

	kmsProviderType := resolveProviderType(&options)
	resolveDefaultRegion(keyIDs, &options)
	resolveClientFactory(&options)
	resolveKeyFactory(kmsProviderType, &options)
	resolveKeyProvider(kmsProviderType, &options)

	if err := validateConfig(kmsProviderType, keyIDs, &options); err != nil {
		return nil, err
	}

	p := newKmsProvider(&options, kmsProviderType)
	if len(keyIDs) > 0 {
		for _, keyID := range keyIDs {
			if _, err := p.AddMasterKey(keyID); err != nil {
				return nil, fmt.Errorf("add MasterKey error: %w", errors.Join(providers.ErrMasterKeyProvider, err))
			}
		}
	}
	return p, nil
}

// New creates a new [KmsKeyProvider] with the given keyIDs.
//
// If no keyIDs are provided, [DiscoveryKmsProvider] will be created.
//
// Example [DiscoveryKmsProvider] in discovery mode:
//
//	kmsProvider, err := kmsprovider.New()
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [StrictKmsProvider] in strict mode:
//
//	keyID := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	kmsProvider, err := kmsprovider.New(keyID)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [StrictKmsProvider] with multiple keyIDs:
//
//	keyID1 := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	keyID2 := "arn:aws:kms:us-east-1:123456789011:key/22345678-1234-1234-1234-123456789012"
//	kmsProvider, err := kmsprovider.New(keyID1, keyID2)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// See [examples] for more detailed usage.
//
// [examples]: https://github.com/chainifynet/aws-encryption-sdk-go/tree/main/example
func New(keyIDs ...string) (*KmsKeyProvider[model.MasterKey], error) {
	if len(keyIDs) == 0 {
		return NewWithOpts(keyIDs, WithDiscovery())
	}
	return NewWithOpts(keyIDs)
}

func newKmsProvider(options *Options, pType ProviderType) *KmsKeyProvider[model.MasterKey] {
	return &KmsKeyProvider[model.MasterKey]{
		keyProvider:          options.keyProvider,
		options:              *options,
		providerType:         pType,
		regionalClients:      make(map[string]model.KMSClient, 5),                  // increase if needed
		keyEntriesForEncrypt: make(map[string]common.KeyEntry[model.MasterKey], 5), // increase if needed
		keyEntriesForDecrypt: make(map[string]common.KeyEntry[model.MasterKey], 5), // increase if needed
	}
}

// KmsKeyProvider is a KMS key provider.
type KmsKeyProvider[KT model.MasterKey] struct {
	keyProvider      model.BaseKeyProvider
	primaryMasterKey *common.KeyEntry[KT]

	options Options

	providerType ProviderType

	regionalClients map[string]model.KMSClient

	// keyEntriesForEncrypt where common.KeyEntry not a pointer
	keyEntriesForEncrypt map[string]common.KeyEntry[KT]
	keyEntriesForDecrypt map[string]common.KeyEntry[KT] // keyEntriesForDecrypt where common.KeyEntry not a pointer
}

// ProviderID returns the ID [types.KmsProviderID].
func (kmsKP *KmsKeyProvider[KT]) ProviderID() string {
	return kmsKP.keyProvider.ID()
}

// ProviderKind returns the kind [types.AwsKms].
func (kmsKP *KmsKeyProvider[KT]) ProviderKind() types.ProviderKind {
	return kmsKP.keyProvider.Kind()
}

// ValidateProviderID validates master key provider ID matches the given provider ID.
func (kmsKP *KmsKeyProvider[KT]) ValidateProviderID(otherID string) error {
	if kmsKP.keyProvider.ID() != otherID {
		return fmt.Errorf("%q providerID doesnt match to with MasterKeyProvider ID %q", otherID, kmsKP.keyProvider.ID())
	}
	return nil
}

// ValidateMasterKey validates the given keyID is a valid KMS key ARN.
func (kmsKP *KmsKeyProvider[KT]) ValidateMasterKey(keyID string) error {
	if err := arn.ValidateKeyArn(keyID); err != nil {
		return fmt.Errorf("invalid keyID %q: %w", keyID, err)
	}
	return nil
}

// AddMasterKey validates the given keyID, checks if it doesn't exist within the
// KMS Provider, creates Kms Master Key, and adds it to the master key provider.
func (kmsKP *KmsKeyProvider[KT]) AddMasterKey(keyID string) (model.MasterKey, error) {
	if err := kmsKP.ValidateMasterKey(keyID); err != nil {
		return nil, err
	}
	if _, exists := kmsKP.keyEntriesForEncrypt[keyID]; !exists {
		// TODO fix context at the some point
		key, err := kmsKP.NewMasterKey(context.Background(), keyID)
		if err != nil {
			// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
			return nil, err
		}

		castKey := key.(KT)

		kmsKeyEntry := common.NewKeyEntryPtr(castKey)

		if kmsKP.primaryMasterKey == nil {
			kmsKP.primaryMasterKey = kmsKeyEntry
		}

		//kmsKeyEntry2 := common.NewKeyEntry(castKey)
		kmsKP.keyEntriesForEncrypt[key.KeyID()] = common.NewKeyEntry(castKey)
	}

	return kmsKP.keyEntriesForEncrypt[keyID].GetEntry(), nil
}

// NewMasterKey returns a new instance of [kms.MasterKey] created by [kms.KeyFactory].
//
// It also checks if the keyID is allowed by the discovery filter.
func (kmsKP *KmsKeyProvider[KT]) NewMasterKey(ctx context.Context, keyID string) (model.MasterKey, error) {
	if kmsKP.providerType == MrkAwareDiscoveryKmsProvider {
		keyArn, _ := arn.ParseArn(keyID)
		if keyArn.IsMrk() {
			// this will set up regional client for original MRK keyID
			// before applying discovery region to the keyID
			_, err := kmsKP.getClient(ctx, keyID)
			if err != nil {
				return nil, err
			}
			keyArn.Region = kmsKP.options.discoveryRegion
			keyID = keyArn.String()
		}
	}

	if kmsKP.options.discovery && kmsKP.options.discoveryFilter != nil {
		if !kmsKP.options.discoveryFilter.isAllowed(keyID) {
			return nil, fmt.Errorf("%q keyID is not allowed by discovery filter: %w", keyID, providers.ErrFilterKeyNotAllowed)
		}
	}

	client, err := kmsKP.getClient(ctx, keyID)
	if err != nil {
		return nil, err
	}
	key, err := kmsKP.options.keyFactory.NewMasterKey(client, keyID)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (kmsKP *KmsKeyProvider[KT]) getClient(ctx context.Context, keyID string) (model.KMSClient, error) {
	regionName, err := regionForKeyID(keyID, kmsKP.options.defaultRegion)
	if err != nil {
		return nil, fmt.Errorf("KMS client error: %w", err)
	}
	if err := kmsKP.addRegionalClient(ctx, regionName); err != nil {
		return nil, fmt.Errorf("KMS client error: %w", err)
	}
	return kmsKP.regionalClients[regionName], nil
}

func (kmsKP *KmsKeyProvider[KT]) addRegionalClient(ctx context.Context, region string) error {
	// do nothing if requested KMS client already registered for a region
	if structs.MapContains(kmsKP.regionalClients, region) {
		return nil
	}

	opts := append(kmsKP.options.awsConfigLoaders, config.WithRegion(region)) //nolint:gocritic

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("unable to load AWS config: %w", err)
	}
	kmsClient := kmsKP.options.clientFactory.NewFromConfig(cfg)
	kmsKP.regionalClients[region] = kmsClient
	return nil
}

// MasterKeysForEncryption returns the primary [model.MasterKey] and a list of master
// keys registered with the KMS Provider for encryption.
func (kmsKP *KmsKeyProvider[KT]) MasterKeysForEncryption(_ context.Context, _ suite.EncryptionContext) (model.MasterKey, []model.MasterKey, error) {
	if kmsKP.primaryMasterKey == nil {
		return nil, nil, fmt.Errorf("no primary key: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderEncrypt, providers.ErrMasterKeyProviderNoPrimaryKey))
	}
	members := make([]model.MasterKey, 0, len(kmsKP.keyEntriesForEncrypt))
	for _, k := range kmsKP.keyEntriesForEncrypt {
		memberMasterKey := k.GetEntry()
		members = append(members, memberMasterKey)
	}

	if len(members) > 0 {
		return kmsKP.primaryMasterKey.GetEntry(), members, nil
	}

	return kmsKP.primaryMasterKey.GetEntry(), nil, nil
}

// MasterKeyForDecrypt returns [kms.MasterKey] for the given metadata.
//
// First, it checks registered keys for Encrypt, then checks registered keys for Decrypt.
//
// If the key is not found, it creates a new master key and adds it to the master
// key provider to be used for decryption.
//
// This method mainly used by keyprovider.KeyProvider when vendOnDecrypt is enabled.
func (kmsKP *KmsKeyProvider[KT]) MasterKeyForDecrypt(ctx context.Context, metadata model.KeyMeta) (model.MasterKey, error) {
	if err := kmsKP.ValidateProviderID(metadata.ProviderID); err != nil {
		return nil, fmt.Errorf("providerID validation: %w", errors.Join(providers.ErrMasterKeyProvider, err))
	}
	if err := kmsKP.ValidateMasterKey(metadata.KeyID); err != nil {
		return nil, fmt.Errorf("keyID validation: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecryptForbidden, err))
	}

	// first check available keys for Encrypt
	if mkForEncrypt, ok := kmsKP.keyEntriesForEncrypt[metadata.KeyID]; ok {
		return mkForEncrypt.GetEntry(), nil
	}

	// then second check available keys for Decrypt
	if mkForDecrypt, ok := kmsKP.keyEntriesForDecrypt[metadata.KeyID]; ok {
		return mkForDecrypt.GetEntry(), nil
	}

	decryptMasterKey, err := kmsKP.NewMasterKey(ctx, metadata.KeyID)
	if err != nil {
		if errors.Is(err, providers.ErrFilterKeyNotAllowed) {
			return nil, fmt.Errorf("NewMasterKey filter: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecryptForbidden, err))
		}
		return nil, fmt.Errorf("NewMasterKey error: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecrypt, err))
	}

	kmsKP.keyEntriesForDecrypt[metadata.KeyID] = common.NewKeyEntry(decryptMasterKey.(KT))

	return decryptMasterKey, nil
}

// MasterKeysForDecryption returns the list of master keys registered for
// encryption and decryption with the KMS Provider.
//
// This method mainly used by keyprovider.KeyProvider.
func (kmsKP *KmsKeyProvider[KT]) MasterKeysForDecryption() []model.MasterKey {
	var allMembers []model.MasterKey
	var allMemberKeys []string

	for keyID, entry := range kmsKP.keyEntriesForDecrypt {
		if !structs.Contains(allMemberKeys, keyID) {
			allMembers = append(allMembers, entry.GetEntry())
			allMemberKeys = append(allMemberKeys, keyID)
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

// DecryptDataKey attempts to decrypt the encrypted data key with a KeyProvider.
func (kmsKP *KmsKeyProvider[KT]) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, err := kmsKP.keyProvider.DecryptDataKey(ctx, kmsKP, encryptedDataKey, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

// DecryptDataKeyFromList attempts to decrypt the encrypted data keys with a
// KeyProvider.
func (kmsKP *KmsKeyProvider[KT]) DecryptDataKeyFromList(ctx context.Context, encryptedDataKeys []model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, err := kmsKP.keyProvider.DecryptDataKeyFromList(ctx, kmsKP, encryptedDataKeys, alg, ec)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

// checking that KmsKeyProvider implements both model.MasterKeyProvider and KmsProvider interfaces.
var _ model.MasterKeyProvider = (*KmsKeyProvider[model.MasterKey])(nil)
var _ model.MasterKeyProvider = (*KmsKeyProvider[kms.KeyHandler])(nil)

var _ KmsProvider = (*KmsKeyProvider[model.MasterKey])(nil)
var _ KmsProvider = (*KmsKeyProvider[kms.KeyHandler])(nil)
