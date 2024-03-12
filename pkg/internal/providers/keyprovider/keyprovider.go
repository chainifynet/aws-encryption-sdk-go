// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type KeyProvider struct {
	providerID    string
	providerKind  types.ProviderKind
	vendOnDecrypt bool
}

func NewKeyProvider(providerID string, providerKind types.ProviderKind, vendOnDecrypt bool) *KeyProvider {
	return &KeyProvider{
		providerID:    providerID,
		providerKind:  providerKind,
		vendOnDecrypt: vendOnDecrypt,
	}
}

func (kp *KeyProvider) ID() string {
	return kp.providerID
}

func (kp *KeyProvider) Kind() types.ProviderKind {
	return kp.providerKind
}

func (kp *KeyProvider) VendOnDecrypt() bool {
	return kp.vendOnDecrypt
}

func (kp *KeyProvider) String() string {
	return fmt.Sprintf("%s:%s", kp.providerID, kp.providerKind)
}

func (kp *KeyProvider) GoString() string {
	return kp.String()
}

func (kp *KeyProvider) DecryptDataKey(ctx context.Context, MKP model.MasterKeyProvider, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	if err := MKP.ValidateProviderID(encryptedDataKey.KeyProvider().ProviderID); err != nil {
		return nil, fmt.Errorf("DecryptDataKey validate expected error: %w", errors.Join(providers.ErrMasterKeyProviderDecrypt, err))
	}

	var dataKey model.DataKeyI

	var allMembers []model.MasterKey
	var allMemberKeys []string

	masterKeys := MKP.MasterKeysForDecryption()
	if len(masterKeys) > 0 {
		for _, masterKey := range masterKeys {
			allMembers = append(allMembers, masterKey)
			allMemberKeys = append(allMemberKeys, masterKey.KeyID())
		}
	}

	if kp.vendOnDecrypt {
		decryptMasterKey, err := MKP.MasterKeyForDecrypt(ctx, encryptedDataKey.KeyProvider())
		if err != nil {
			if errors.Is(err, providers.ErrMasterKeyProviderDecryptForbidden) {
				return nil, fmt.Errorf("DecryptDataKey MKP.MasterKeyForDecrypt is forbidden for keyID %q with MKP %q: %w", encryptedDataKey.KeyID(), MKP.ProviderID(), errors.Join(providers.ErrMasterKeyProviderDecrypt, err))
			}
		} else if !structs.Contains(allMemberKeys, decryptMasterKey.KeyID()) {
			allMembers = append(allMembers, decryptMasterKey)
		}
	}

	var errMemberKey error

	// ref https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-aware-master-key.md#decrypt-data-key
	// For each encrypted data key in the filtered set, one at a time,
	//	the master key MUST attempt to decrypt the data key.
	for _, memberKey := range allMembers {
		if !memberKey.OwnsDataKey(encryptedDataKey) {
			// if memberKey does not own encryptedDataKey, try to decrypt next provider member key
			continue
		}
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
			return nil, fmt.Errorf("unable to decrypt data key, member key error: %w", errors.Join(providers.ErrMasterKeyProviderDecrypt, errMemberKey))
		}
		return nil, fmt.Errorf("unable to decrypt data key: %w", providers.ErrMasterKeyProviderDecrypt)
	}

	return dataKey, nil
}

func (kp *KeyProvider) DecryptDataKeyFromList(ctx context.Context, MKP model.MasterKeyProvider, encryptedDataKeys []model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	var dataKey model.DataKeyI

	var errDecryptDataKey error
	for _, edk := range encryptedDataKeys {
		if err := MKP.ValidateProviderID(edk.KeyProvider().ProviderID); err != nil {
			errDecryptDataKey = fmt.Errorf("DecryptDataKeyFromList validate expected error: %w", errors.Join(providers.ErrMasterKeyProviderDecrypt, err))
			continue
		}
		decryptedDataKey, errDecrypt := MKP.DecryptDataKey(ctx, edk, alg, ec)
		if errDecrypt == nil {
			dataKey = decryptedDataKey
			break
		} else { //nolint:revive
			errDecryptDataKey = errDecrypt
			if errors.Is(errDecrypt, providers.ErrMasterKeyProviderDecrypt) {
				continue
			} else { //nolint:revive
				break
			}
		}
	}

	if dataKey == nil {
		if errDecryptDataKey != nil {
			return nil, fmt.Errorf("unable to decrypt any data key, member error: %w", errors.Join(providers.ErrMasterKeyProvider, errDecryptDataKey))
		}
		return nil, fmt.Errorf("unable to decrypt any data key: %w", errors.Join(providers.ErrMasterKeyProvider, providers.ErrMasterKeyProviderDecrypt))
	}

	return dataKey, nil
}

var _ model.BaseKeyProvider = (*KeyProvider)(nil)
