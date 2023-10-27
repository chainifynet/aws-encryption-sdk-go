// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	b64 "encoding/base64"
	"fmt"

	"github.com/pkg/errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

const (
	encryptedContextAWSKey = "aws-crypto-public-key"
)

var CMM cmm

type cmm struct{}

func (cmm) NewDefault(provider providers.MasterKeyProvider) *defaultCryptoMaterialsManager {
	return &defaultCryptoMaterialsManager{masterKeyProvider: provider}
}

type defaultCryptoMaterialsManager struct {
	masterKeyProvider providers.MasterKeyProvider
}

// compile checking that defaultCryptoMaterialsManager implements CryptoMaterialsManager interface
var _ CryptoMaterialsManager = (*defaultCryptoMaterialsManager)(nil)

func (defaultCMM *defaultCryptoMaterialsManager) GetInstance() CryptoMaterialsManager {
	//return *&defaultCMM
	return &defaultCryptoMaterialsManager{masterKeyProvider: defaultCMM.masterKeyProvider}
}

func (defaultCMM *defaultCryptoMaterialsManager) generateSigningKeyUpdateEncryptionContext(algorithm *suite.AlgorithmSuite, ec suite.EncryptionContext) (*ecdsa.PrivateKey, error) {
	// if not signing algo, return nil signing key, and dont change encryption context
	if !algorithm.IsSigning() {
		return nil, nil
	}
	private, err := ecdsa.GenerateKey(algorithm.Authentication.Algorithm, rand.Reader)
	if err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, err
	}
	pubCompressed := elliptic.MarshalCompressed(algorithm.Authentication.Algorithm, private.PublicKey.X, private.PublicKey.Y)

	ec[encryptedContextAWSKey] = b64.StdEncoding.EncodeToString(pubCompressed)
	return private, nil
}

func (defaultCMM *defaultCryptoMaterialsManager) GetEncryptionMaterials(encReq EncryptionMaterialsRequest) (*EncryptionMaterials, error) {
	// it is already done in: pkg/crypto/encryptor.go:69
	//if err := policy.Commitment.ValidatePolicyOnEncrypt(encReq.CommitmentPolicy, encReq.Algorithm); err != nil {
	//	return nil, err
	//}

	// copy encryption context map
	var encryptionContext suite.EncryptionContext
	encryptionContext = make(suite.EncryptionContext)
	for k, v := range encReq.EncryptionContext {
		encryptionContext[k] = v
	}

	// it only adds signing key to encryption context if signing algo
	signingKey, err := defaultCMM.generateSigningKeyUpdateEncryptionContext(encReq.Algorithm, encryptionContext)
	if err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, err
	}

	encryptionContext = structs.MapSort(encryptionContext)

	primaryMasterKey, masterKeys, err := defaultCMM.masterKeyProvider.MasterKeysForEncryption(encryptionContext, encReq.PlaintextRoStream, encReq.PlaintextLength)
	if err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, err
	}
	dataEncryptionKey, encryptedDataKeys, err := prepareDataKeys(primaryMasterKey, masterKeys, encReq.Algorithm, encryptionContext)
	if err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, err
	}
	return &EncryptionMaterials{
		algorithm:         encReq.Algorithm,
		dataEncryptionKey: dataEncryptionKey,
		encryptedDataKeys: encryptedDataKeys,
		encryptionContext: encryptionContext,
		signingKey:        signingKey,
	}, nil
}

func (defaultCMM *defaultCryptoMaterialsManager) DecryptMaterials(decReq DecryptionMaterialsRequest) (*DecryptionMaterials, error) {
	if err := policy.Commitment.ValidatePolicyOnDecrypt(decReq.CommitmentPolicy, decReq.Algorithm); err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, err
	}

	dataKey, err := defaultCMM.masterKeyProvider.DecryptDataKeyFromList(decReq.EncryptedDataKeys, decReq.Algorithm, decReq.EncryptionContext)
	if err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, err
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
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		return nil, fmt.Errorf("missing %s in encryption context", encryptedContextAWSKey)
	}
	pubKeyStr := decReq.EncryptionContext[encryptedContextAWSKey]
	verificationKey, err := b64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		// TODO introduce CMM errors, wrap err with fmt.Errorf wrapping inner err
		// TODO deprecate pkg/errors
		return nil, errors.Wrap(err, "ECDSA key error")
	}

	return &DecryptionMaterials{
		dataKey:         dataKey,
		verificationKey: verificationKey,
	}, nil
}
