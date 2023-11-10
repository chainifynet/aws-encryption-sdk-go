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

type baseKeyProvider interface {
	ID() string
	Type() ProviderType
	decryptDataKey(ctx context.Context, MKP MasterKeyProvider, encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error)
	decryptDataKeyFromList(ctx context.Context, MKP MasterKeyProvider, encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error)
}

type KeyProvider struct {
	providerID   string
	providerType ProviderType
}

func newKeyProvider(providerID string, providerType ProviderType) *KeyProvider {
	return &KeyProvider{
		providerID:   providerID,
		providerType: providerType,
	}
}

func (kp *KeyProvider) ID() string {
	return kp.providerID
}

func (kp *KeyProvider) Type() ProviderType {
	return kp.providerType
}

func (kp *KeyProvider) String() string {
	return fmt.Sprintf("%s:%s", kp.providerID, kp.providerType)
}

func (kp *KeyProvider) GoString() string {
	return kp.String()
}

func (kp *KeyProvider) decryptDataKey(ctx context.Context, MKP MasterKeyProvider, encryptedDataKey keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	if err := MKP.ValidateProviderID(encryptedDataKey.KeyProvider().ProviderID); err != nil {
		return nil, fmt.Errorf("DecryptDataKey validate expected error: %w", errors.Join(ErrMasterKeyProviderDecrypt, err))
	}

	if err := MKP.validateMasterKey(encryptedDataKey.KeyID()); err != nil {
		return nil, fmt.Errorf("DecryptDataKey validateMasterKey error: %w", errors.Join(ErrMasterKeyProviderDecrypt, err))
	}

	var dataKey keys.DataKeyI

	var allMembers []keys.MasterKeyBase
	var allMemberKeys []string

	decryptMasterKey, err := MKP.MasterKeyForDecrypt(ctx, encryptedDataKey.KeyProvider())
	if err != nil {
		log.Trace().
			Stringer("EDK", encryptedDataKey.KeyProvider()).
			Str("MKP", MKP.Provider().providerID).
			Str("method", "DecryptDataKey").
			Err(err).Msgf("cant reach MasterKey for EDK keyID: %v", encryptedDataKey.KeyID())
		if errors.Is(err, ErrMasterKeyProviderDecryptForbidden) {
			return nil, fmt.Errorf("DecryptDataKey MKP.MasterKeyForDecrypt is forbidden for keyID %q with MKP %q: %w", encryptedDataKey.KeyID(), MKP.Provider().ID(), errors.Join(ErrMasterKeyProviderDecrypt, err))
		}
	} else {
		allMembers = append(allMembers, decryptMasterKey)
		allMemberKeys = append(allMemberKeys, decryptMasterKey.KeyID())
	}

	masterKeys := MKP.masterKeysForDecryption()
	if len(masterKeys) > 0 {
		for _, masterKey := range masterKeys {
			if !structs.Contains(allMemberKeys, masterKey.KeyID()) {
				allMembers = append(allMembers, masterKey)
				allMemberKeys = append(allMemberKeys, masterKey.KeyID())
			}
		}
	}

	var errMemberKey error

	// ref https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-aware-master-key.md#decrypt-data-key
	// For each encrypted data key in the filtered set, one at a time,
	//	the master key MUST attempt to decrypt the data key.
	for i, memberKey := range allMembers {
		log.Trace().
			Int("memberI", i).
			Stringer("EDK", encryptedDataKey.KeyProvider()).
			Str("MKP", MKP.Provider().providerID).
			Str("keyID", memberKey.KeyID()).
			Str("method", "DecryptDataKey").
			Msg("Provider: DecryptDataKey")
		decryptedDataKey, errDecrypt := memberKey.DecryptDataKey(ctx, encryptedDataKey, alg, ec)
		if errDecrypt == nil {
			dataKey = decryptedDataKey
			// https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-aware-master-key.md#decrypt-data-key
			// If the AWS KMS response satisfies the requirements then it MUST be use
			//	and this function MUST return
			//	and not attempt to decrypt anymore encrypted data keys.
			break
		} else { //nolint:revive
			errMemberKey = errDecrypt
			// if MasterKey returns keys.ErrDecryptKey, try to decrypt next provider member key
			if errors.Is(errDecrypt, keys.ErrDecryptKey) {
				log.Trace().
					Int("memberI", i).
					Stringer("EDK", encryptedDataKey.KeyProvider()).
					Str("MKP", MKP.Provider().providerID).
					Str("keyID", memberKey.KeyID()).
					Str("method", "DecryptDataKey").
					Err(errDecrypt).Msgf("cant decrypt data key by MasterKey %v, for EDK keyID: %v", memberKey.KeyID(), encryptedDataKey.KeyID())
				continue
			} else { //nolint:revive
				break
			}
		}
	}

	// If this point is reached without having the data key decrypted
	//	then the data key has not been decrypted
	if dataKey == nil {
		if errMemberKey != nil {
			return nil, fmt.Errorf("dataKey nil, member key error: %w", errors.Join(ErrMasterKeyProviderDecrypt, errMemberKey))
		}
		return nil, fmt.Errorf("dataKey nil: %w", ErrMasterKeyProviderDecrypt)
	}

	return dataKey, nil
}

func (kp *KeyProvider) decryptDataKeyFromList(ctx context.Context, MKP MasterKeyProvider, encryptedDataKeys []keys.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (keys.DataKeyI, error) {
	var dataKey keys.DataKeyI

	var errDecryptDataKey error
	for i, edk := range encryptedDataKeys {
		log.Trace().
			Int("edkI", i).
			Stringer("EDK", edk.KeyProvider()).    // EncryptedDataKeyI KeyMeta (ProviderID and KeyID)
			Str("MKP", MKP.Provider().providerID). // MasterKeyProvider ProviderID with which we try to decrypt EncryptedDataKeyI
			Str("method", "DecryptDataKeyFromList").
			Msg("DecryptDataKeyFromList")
		if err := MKP.ValidateProviderID(edk.KeyProvider().ProviderID); err != nil {
			log.Trace().Err(err).
				Int("edkI", i).
				Stringer("EDK", edk.KeyProvider()).
				Str("MKP", MKP.Provider().providerID).
				Str("method", "DecryptDataKeyFromList").
				Msg("DecryptDataKeyFromList validate expected error")
			errDecryptDataKey = fmt.Errorf("DecryptDataKeyFromList validate expected error: %w", errors.Join(ErrMasterKeyProviderDecrypt, err))
			continue
		}
		decryptedDataKey, errDecrypt := MKP.DecryptDataKey(ctx, edk, alg, ec)
		if errDecrypt == nil {
			dataKey = decryptedDataKey
			break
		} else { //nolint:revive
			errDecryptDataKey = errDecrypt
			if errors.Is(errDecrypt, ErrMasterKeyProviderDecrypt) {
				continue
			} else { //nolint:revive
				break
			}
		}
	}

	if dataKey == nil {
		if errDecryptDataKey != nil {
			return nil, fmt.Errorf("DecryptDataKeyFromList dataKey nil, member error: %w", errors.Join(ErrMasterKeyProvider, errDecryptDataKey))
		}
		return nil, fmt.Errorf("DecryptDataKeyFromList dataKey nil: %w", errors.Join(ErrMasterKeyProvider, ErrMasterKeyProviderDecrypt))
	}

	return dataKey, nil
}

var _ baseKeyProvider = (*KeyProvider)(nil)
