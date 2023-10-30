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

const (
	_kmsProviderID = "aws-kms"
)

type KmsProviderOptions struct {
	Profile        string
	AwsLoadOptions []func(options *config.LoadOptions) error
}

type OptionFunc func(options *KmsProviderOptions) error

func WithProfile(p string) OptionFunc {
	return func(o *KmsProviderOptions) error {
		o.Profile = p
		return nil
	}
}

func WithAwsLoadOptions(opts ...func(options *config.LoadOptions) error) OptionFunc {
	return func(o *KmsProviderOptions) error {
		o.AwsLoadOptions = opts
		return nil
	}
}

type KmsKeyProviderI interface {
	MasterKeyProvider
	KmsKeyForEncrypt(base keys.MasterKeyBase) (keys.KmsMasterKeyI, error)
	KmsKeyForDecrypt(base keys.MasterKeyBase) (keys.KmsMasterKeyI, error)
	// TODO might be in setup method for KMS??
	//  or might move AddMasterKey, MasterKeysForEncryption... methods here
	//  to achieve constrains specifically on keys.KmsMasterKey regardless of interface keys.KmsMasterKeyI
}

// NewKmsKeyProviderWithOpts TODO add more options
// make possible to initialise provider without keys and with keys list
func NewKmsKeyProviderWithOpts(keyIDs []string, optFns ...func(options *KmsProviderOptions) error) (*KmsKeyProvider[keys.KmsMasterKeyI], error) {
	var options KmsProviderOptions
	for _, optFn := range optFns {
		if err := optFn(&options); err != nil {
			return nil, err
		}
	}

	p := newKmsKeyProvider(&options)
	if len(keyIDs) > 0 {
		for _, keyID := range keyIDs {
			if err := arn.ValidateKeyArn(keyID); err != nil {
				// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
				return nil, fmt.Errorf("invalid keyID %s, %w", keyID, err)
			}
			if _, err := p.addMasterKey(keyID); err != nil {
				// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
				return nil, err
			}
		}
	}
	return p, nil

	//return &KmsKeyProvider[keys.KmsMasterKeyI]{
	//	providerID:           _kmsProviderID,
	//	options:              options,
	//	regionalClients:      map[string]*kms.Client{},
	//	keyEntriesForEncrypt: make(map[string]keys.KeyEntry[keys.KmsMasterKeyI]),
	//	keyEntriesForDecrypt: make(map[string]keys.KeyEntry[keys.KmsMasterKeyI]),
	//}, nil

}

func NewKmsKeyProvider(keyIDs ...string) (*KmsKeyProvider[keys.KmsMasterKeyI], error) {
	return NewKmsKeyProviderWithOpts(keyIDs)
}

func newKmsKeyProvider(options *KmsProviderOptions) *KmsKeyProvider[keys.KmsMasterKeyI] {
	return &KmsKeyProvider[keys.KmsMasterKeyI]{
		providerID:           _kmsProviderID,
		options:              *options,
		regionalClients:      map[string]*kms.Client{},
		keyEntriesForEncrypt: make(map[string]keys.KeyEntry[keys.KmsMasterKeyI]),
		keyEntriesForDecrypt: make(map[string]keys.KeyEntry[keys.KmsMasterKeyI]),
	}
}

type KmsKeyProvider[KT keys.KmsMasterKeyI] struct {
	providerID       string
	primaryMasterKey *keys.KeyEntry[KT]

	options KmsProviderOptions

	regionalClients map[string]*kms.Client

	// keyEntriesForEncrypt where keys.KeyEntry not a pointer
	keyEntriesForEncrypt map[string]keys.KeyEntry[KT]
	keyEntriesForDecrypt map[string]keys.KeyEntry[KT] // keyEntriesForDecrypt where keys.KeyEntry not a pointer
}

func (kmsKP *KmsKeyProvider[KT]) ProviderID() string {
	return kmsKP.providerID
}

func (kmsKP *KmsKeyProvider[KT]) ValidateProviderID(otherID string) error {
	if kmsKP.providerID != otherID {
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		return fmt.Errorf("provided base MasterKey providerID %s doesnt match to with KeyProvider ID %s", otherID, kmsKP.providerID)
	}
	return nil
}

func (kmsKP *KmsKeyProvider[KT]) validateMasterKey(keyID string) error {
	if _, exists := kmsKP.keyEntriesForEncrypt[keyID]; !exists {
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		return fmt.Errorf("key %v doesnt exists", keyID)
	}
	return nil
}

func (kmsKP *KmsKeyProvider[KT]) addMasterKey(keyID string) (keys.MasterKeyBase, error) {

	if errKeyExists := kmsKP.validateMasterKey(keyID); errKeyExists != nil {
		//return nil, fmt.Errorf("key %v already exists", keyID)
		key, err := kmsKP.newMasterKey(keyID)
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

func (kmsKP *KmsKeyProvider[KT]) newMasterKey(keyID string) (keys.MasterKeyBase, error) {
	client, err := kmsKP.getClient(keyID)
	if err != nil {
		return nil, err
	}
	key := keys.NewKmsMasterKey(client, keyID)
	return key, nil
}

func (kmsKP *KmsKeyProvider[KT]) getClient(keyID string) (*kms.Client, error) {
	// TODO add configurable default region
	regionName, err := regionForKeyID(keyID, "")
	if err != nil {
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		return nil, err
	}
	kmsKP.addRegionalClient(regionName)
	log.Trace().
		Str("region", regionName).
		Str("keyID", keyID).
		Msg("GET regional KMS client")
	return kmsKP.regionalClients[regionName], nil
}

func (kmsKP *KmsKeyProvider[KT]) addRegionalClient(region string) {
	// do nothing if requested KMS client already registered for a region
	if structs.MapContains(kmsKP.regionalClients, region) {
		return
	}

	opts := append(kmsKP.options.AwsLoadOptions, config.WithRegion(region)) //nolint:gocritic

	// TODO andrew remove since we can use WithSharedConfigProfile when configuring KmsKeyProvider
	if kmsKP.options.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(kmsKP.options.Profile))
	}

	// TODO andrew refactor this
	cfgOpts := &config.LoadOptions{}
	for _, opt := range opts {
		if err := opt(cfgOpts); err != nil {
			log.Error().Err(err).Msg("unable to load Custom SDK config")
			// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
			// TODO andrew refactor return error
		}
	}
	if cfgOpts.SharedConfigProfile != "" {
		kmsKP.options.Profile = cfgOpts.SharedConfigProfile
	}

	// TODO pass Context
	cfg, err := config.LoadDefaultConfig(context.TODO(), opts...)
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

func (kmsKP *KmsKeyProvider[KT]) MasterKeysForEncryption(_ suite.EncryptionContext, _ []byte, _ int) (keys.MasterKeyBase, []keys.MasterKeyBase, error) {
	// TODO probably we need to AddMasterKey for each of keyEntriesForEncrypt that eventually adds primaryMasterKey
	//  andrew: cover with tests and we'll see

	if kmsKP.primaryMasterKey == nil {
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		return nil, nil, fmt.Errorf("no primary key")
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

// MasterKeyForEncrypt
// Deprecated: TODO andrew remove unused
func (kmsKP *KmsKeyProvider[KT]) MasterKeyForEncrypt(keyID string) (keys.MasterKeyBase, error) {
	if err := kmsKP.validateMasterKey(keyID); err != nil {
		//return nil, err
		return kmsKP.addMasterKey(keyID)
	}
	return kmsKP.keyEntriesForEncrypt[keyID].GetEntry(), nil
}

// MasterKeyForEncryptByKeyMetadata
// Deprecated: TODO andrew remove unused
func (kmsKP *KmsKeyProvider[KT]) MasterKeyForEncryptByKeyMetadata(metadata keys.KeyMeta) (keys.MasterKeyBase, error) {
	if err := kmsKP.ValidateProviderID(metadata.ProviderID); err != nil {
		return nil, err
	}
	if err := kmsKP.validateMasterKey(metadata.KeyID); err != nil {
		return kmsKP.addMasterKey(metadata.KeyID)
		//return nil, err
	}
	return kmsKP.keyEntriesForEncrypt[metadata.KeyID].GetEntry(), nil
}

func (kmsKP *KmsKeyProvider[KT]) MasterKeyForDecrypt(metadata keys.KeyMeta) (keys.MasterKeyBase, error) {
	// TODO add validation
	if mkForEncrypt, ok := kmsKP.keyEntriesForEncrypt[metadata.KeyID]; ok {
		return mkForEncrypt.GetEntry(), nil
	}

	if mkForDecrypt, ok := kmsKP.keyEntriesForDecrypt[metadata.KeyID]; ok {
		return mkForDecrypt.GetEntry(), nil
	}

	decryptMasterKey, err := kmsKP.newMasterKey(metadata.KeyID)
	if err != nil {
		return nil, err
	}

	kmsKP.keyEntriesForDecrypt[metadata.KeyID] = keys.NewKeyEntry(decryptMasterKey.(KT))

	return decryptMasterKey, nil
}

func (kmsKP *KmsKeyProvider[KT]) DecryptDataKey(encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	var dataKey keys.DataKeyI

	var allMembers []keys.MasterKeyBase
	var allMemberKeys []string
	// TODO check decrypt keys if they already there, skip below i.e. fast-path
	decryptMasterKey, err := kmsKP.MasterKeyForDecrypt(encryptedDataKey.KeyProvider())
	if err != nil {
		log.Warn().Msgf("cant reach MasterKey by kmsKP.MasterKeyForDecrypt for encryptedDataKey, keyID: %v", encryptedDataKey.KeyID())
	} else {
		allMembers = append(allMembers, decryptMasterKey)
		allMemberKeys = append(allMemberKeys, decryptMasterKey.KeyID())
	}

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

	// ref https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-aware-master-key.md#decrypt-data-key
	// For each encrypted data key in the filtered set, one at a time,
	//	the master key MUST attempt to decrypt the data key.
	for i, memberKey := range allMembers {
		log.Trace().
			Int("memberI", i).
			Str("keyID", memberKey.KeyID()).
			Str("method", "DecryptDataKey").
			Msg("Provider: DecryptDataKey")
		decryptedDataKey, errDecrypt := memberKey.DecryptDataKey(encryptedDataKey, alg, ec)
		if errDecrypt == nil {
			dataKey = decryptedDataKey
			// https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-aware-master-key.md#decrypt-data-key
			// If the AWS KMS response satisfies the requirements then it MUST be use
			//	and this function MUST return
			//	and not attempt to decrypt anymore encrypted data keys.
			break
		} else { //nolint:revive
			// if MasterKey returns keys.ErrDecryptKey, try to decrypt next provider member key
			if errors.Is(errDecrypt, keys.ErrDecryptKey) {
				continue
			} else { //nolint:revive
				break
			}
		}
	}

	// If this point is reached without having the data key decrypted
	//	then the data key has not been decrypted
	if dataKey == nil {
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		return nil, keys.ErrDecryptKey
	}

	return dataKey, nil
}

// DecryptDataKeyFromList iterates through EDK, calls DecryptDataKey
func (kmsKP *KmsKeyProvider[KT]) DecryptDataKeyFromList(encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	var dataKey keys.DataKeyI

	for i, edk := range encryptedDataKeys {
		log.Trace().Int("edkI", i).Str("method", "DecryptDataKeyFromList").
			Msg("DecryptDataKeyFromList")
		decryptedDataKey, errDecrypt := kmsKP.DecryptDataKey(edk, alg, ec)
		if errDecrypt == nil {
			dataKey = decryptedDataKey
			break
		} else { //nolint:revive
			if errors.Is(errDecrypt, keys.ErrDecryptKey) {
				continue
			} else { //nolint:revive
				break
			}
		}
	}

	if dataKey == nil {
		// TODO introduce provider errors in order distinguish between MasterKey and MasterKeyProvider errors
		return nil, keys.ErrDecryptKey
	}

	return dataKey, nil
}

// KmsKeyForEncrypt TODO probably remove, it wont be used
func (kmsKP *KmsKeyProvider[KT]) KmsKeyForEncrypt(base keys.MasterKeyBase) (keys.KmsMasterKeyI, error) {
	if err := kmsKP.ValidateProviderID(base.Metadata().ProviderID); err != nil {
		return nil, err
	}
	if err := kmsKP.validateMasterKey(base.KeyID()); err != nil {
		return nil, err
	}
	return kmsKP.keyEntriesForEncrypt[base.KeyID()].GetEntry(), nil
}

// KmsKeyForDecrypt TODO probably remove, it wont be used
func (kmsKP *KmsKeyProvider[KT]) KmsKeyForDecrypt(base keys.MasterKeyBase) (keys.KmsMasterKeyI, error) {
	if err := kmsKP.ValidateProviderID(base.Metadata().ProviderID); err != nil {
		return nil, err
	}
	if err := kmsKP.validateMasterKey(base.KeyID()); err != nil {
		return nil, err
	}
	return kmsKP.keyEntriesForEncrypt[base.KeyID()].GetEntry(), nil
}

// var _ MasterKeyProvider = (*KmsKeyProvider[keys.MasterKeyBase])(nil)
var _ MasterKeyProvider = (*KmsKeyProvider[keys.KmsMasterKeyI])(nil)

// var _ KmsKeyProviderI = (*KmsKeyProvider[keys.MasterKeyBase])(nil)
var _ KmsKeyProviderI = (*KmsKeyProvider[keys.KmsMasterKeyI])(nil)

const _regionMinLength = 9

func regionForKeyID(keyID, defaultRegion string) (string, error) {
	parts := strings.Split(keyID, ":")
	if len(parts) < 3 { //nolint:gomnd
		// minimum chars in AWS region, i.e. sa-east-1
		if len(defaultRegion) >= _regionMinLength {
			return defaultRegion, nil
		}
		return "", fmt.Errorf("InvalidRegionError, KeyID %v", keyID)
	}

	if len(parts[3]) >= _regionMinLength {
		return parts[3], nil
	}

	return "", fmt.Errorf("UnknownRegionError, KeyID %v", keyID)
}
