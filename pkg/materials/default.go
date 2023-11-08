// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	b64 "encoding/base64"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

type DefaultCryptoMaterialsManager struct {
	primaryKeyProvider providers.MasterKeyProvider
	masterKeyProviders []providers.MasterKeyProvider
}

// compile checking that DefaultCryptoMaterialsManager implements CryptoMaterialsManager interface
var _ CryptoMaterialsManager = (*DefaultCryptoMaterialsManager)(nil)

func NewDefault(primary providers.MasterKeyProvider, extra ...providers.MasterKeyProvider) (*DefaultCryptoMaterialsManager, error) {
	if len(extra) == 0 {
		return &DefaultCryptoMaterialsManager{
			primaryKeyProvider: primary,
			masterKeyProviders: nil,
		}, nil
	}
	types := []string{primary.Provider().ID()}
	for _, mkp := range extra {
		if mkp.Provider().Type() == providers.Raw && structs.Contains(types, mkp.Provider().ID()) {
			return nil, fmt.Errorf("duplicate Raw providerID: %s: %w", mkp.Provider().ID(), ErrCMM)
		}
		types = append(types, mkp.Provider().ID())
	}
	return &DefaultCryptoMaterialsManager{
		primaryKeyProvider: primary,
		masterKeyProviders: extra,
	}, nil
}

func (composite *DefaultCryptoMaterialsManager) GetEncryptionMaterials(encReq EncryptionMaterialsRequest) (*EncryptionMaterials, error) {
	// copy encryption context map
	var encryptionContext suite.EncryptionContext
	encryptionContext = make(suite.EncryptionContext)
	for k, v := range encReq.EncryptionContext {
		encryptionContext[k] = v
	}

	// it only adds signing key to encryption context if signing algo
	signingKey, err := composite.generateSigningKeyUpdateEncryptionContext(encReq.Algorithm, encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("signing key update: %w", errors.Join(ErrCMM, err))
	}

	encryptionContext = structs.MapSort(encryptionContext)

	var masterKeys []keys.MasterKeyBase
	primaryMasterKey, primaryMemberKeys, err := composite.primaryKeyProvider.MasterKeysForEncryption(encryptionContext, encReq.PlaintextRoStream, encReq.PlaintextLength)
	if err != nil {
		return nil, fmt.Errorf("primary KeyProvider error: %w", errors.Join(ErrCMM, err))
	}
	masterKeys = append(masterKeys, primaryMemberKeys...)
	if len(composite.masterKeyProviders) > 0 {
		for _, mkp := range composite.masterKeyProviders {
			// here we dont really need primary master key, it is already in memberKeys
			_, memberKeys, errMember := mkp.MasterKeysForEncryption(encryptionContext, encReq.PlaintextRoStream, encReq.PlaintextLength)
			// here we can ignore providers.ErrMasterKeyProviderNoPrimaryKey
			//  assuming that provider could have only member keys
			if errMember != nil && !errors.Is(errMember, providers.ErrMasterKeyProviderNoPrimaryKey) {
				return nil, fmt.Errorf("member KeyProvider error: %w", errors.Join(ErrCMM, errMember))
			}
			if len(memberKeys) > 0 {
				masterKeys = append(masterKeys, memberKeys...)
			}
		}
	}

	dataEncryptionKey, encryptedDataKeys, err := prepareDataKeys(primaryMasterKey, masterKeys, encReq.Algorithm, encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("key error: %w", errors.Join(ErrCMM, err))
	}
	return &EncryptionMaterials{
		algorithm:         encReq.Algorithm,
		dataEncryptionKey: dataEncryptionKey,
		encryptedDataKeys: encryptedDataKeys,
		encryptionContext: encryptionContext,
		signingKey:        signingKey,
	}, nil

}

func (composite *DefaultCryptoMaterialsManager) DecryptMaterials(decReq DecryptionMaterialsRequest) (*DecryptionMaterials, error) {
	var dataKey keys.DataKeyI
	var errDecryptDataKey error
	dataKeyPrimary, err := composite.primaryKeyProvider.DecryptDataKeyFromList(decReq.EncryptedDataKeys, decReq.Algorithm, decReq.EncryptionContext)
	if err != nil {
		if !errors.Is(err, providers.ErrMasterKeyProviderDecrypt) {
			return nil, fmt.Errorf("primary KeyProvider error: %w", errors.Join(ErrCMM, err))
		}
		errDecryptDataKey = err
	}
	if dataKeyPrimary != nil { //nolint:nestif
		dataKey = dataKeyPrimary
	} else if len(composite.masterKeyProviders) > 0 {
		for _, mkp := range composite.masterKeyProviders {
			dataKeyMember, errMember := mkp.DecryptDataKeyFromList(decReq.EncryptedDataKeys, decReq.Algorithm, decReq.EncryptionContext)
			if errMember != nil {
				if !errors.Is(errMember, providers.ErrMasterKeyProviderDecrypt) {
					return nil, fmt.Errorf("member KeyProvider error: %w", errors.Join(ErrCMM, err))
				}
				errDecryptDataKey = errMember
				continue
			}
			if dataKeyMember != nil {
				dataKey = dataKeyMember
				break
			}
		}
	}

	if dataKey == nil {
		if errDecryptDataKey != nil {
			return nil, fmt.Errorf("no data key, last error: %w", errors.Join(ErrCMM, errDecryptDataKey))
		}
		//return nil, fmt.Errorf("no data key: %w", ErrCMM)
		return nil, fmt.Errorf("no data key: %w", ErrCMM)
	}

	// if not signing algo, return decryption materials without verification key
	if !decReq.Algorithm.IsSigning() {
		return &DecryptionMaterials{
			dataKey:         dataKey,
			verificationKey: nil,
		}, nil
	}

	// handle signing algo
	if _, ok := decReq.EncryptionContext[encryptedContextAWSKey]; !ok {
		return nil, fmt.Errorf("missing %s in encryption context: %w", encryptedContextAWSKey, errors.Join(ErrCMM, err))
	}
	pubKeyStr := decReq.EncryptionContext[encryptedContextAWSKey]
	verificationKey, err := b64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("ECDSA key error: %w", errors.Join(ErrCMM, err))
	}

	return &DecryptionMaterials{
		dataKey:         dataKey,
		verificationKey: verificationKey,
	}, nil
}

func (composite *DefaultCryptoMaterialsManager) GetInstance() CryptoMaterialsManager {
	//return composite
	return &DefaultCryptoMaterialsManager{
		primaryKeyProvider: composite.primaryKeyProvider,
		masterKeyProviders: composite.masterKeyProviders,
	}
}

func (composite *DefaultCryptoMaterialsManager) generateSigningKeyUpdateEncryptionContext(algorithm *suite.AlgorithmSuite, ec suite.EncryptionContext) (*ecdsa.PrivateKey, error) {
	// if not signing algo, return nil signing key, and dont change encryption context
	if !algorithm.IsSigning() {
		return nil, nil
	}
	private, err := ecdsa.GenerateKey(algorithm.Authentication.Algorithm, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ECDSA key error: %w", err)
	}
	pubCompressed := elliptic.MarshalCompressed(algorithm.Authentication.Algorithm, private.PublicKey.X, private.PublicKey.Y)

	ec[encryptedContextAWSKey] = b64.StdEncoding.EncodeToString(pubCompressed)
	return private, nil
}
