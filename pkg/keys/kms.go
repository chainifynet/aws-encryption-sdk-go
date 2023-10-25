// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const (
	_kmsProviderID = "aws-kms"
)

var (
	log = logger.L().Level(zerolog.DebugLevel)
)

type KmsMasterKeyI interface {
	MasterKeyBase
	GenerateDataKey(alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
	EncryptDataKey(dataKey DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (EncryptedDataKeyI, error)
	DecryptDataKey(encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
}

type KmsMasterKey struct {
	metadata  KeyMeta
	kmsClient *kms.Client
}

func NewKmsMasterKey(client *kms.Client, keyID string) *KmsMasterKey {
	return &KmsMasterKey{
		metadata: KeyMeta{
			ProviderID: _kmsProviderID,
			KeyID:      keyID,
		},
		kmsClient: client,
	}
}

// checking that KmsMasterKey implements both MasterKeyBase and KmsMasterKeyI interfaces
var _ MasterKeyBase = (*KmsMasterKey)(nil)
var _ KmsMasterKeyI = (*KmsMasterKey)(nil)

func (kmsMK *KmsMasterKey) KeyID() string {
	return kmsMK.metadata.KeyID
}

func (kmsMK *KmsMasterKey) Metadata() KeyMeta {
	return kmsMK.metadata
}

func (kmsMK *KmsMasterKey) OwnsDataKey(key Key) bool {
	if kmsMK.metadata.KeyID == key.KeyID() {
		return true
	} else {
		return false
	}
}

// GenerateDataKey returns DataKey is generated from primaryMasterKey in MasterKeyProvider
// DataKey contains:
//
//	provider			keyID of this (MasterKey) KmsMasterKey
//	dataKey				Plaintext of this generated dataKey
//	encryptedDataKey	CiphertextBlob of this generated dataKey
func (kmsMK *KmsMasterKey) GenerateDataKey(alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error) {
	dataKeyRequest := kmsMK.buildGenerateDataKeyRequest(alg, ec)
	// TODO do something with Context
	dataKeyOutput, err := kmsMK.kmsClient.GenerateDataKey(context.TODO(), dataKeyRequest)
	if err != nil {
		log.Error().Caller().
			Err(err).
			Stringer("MasterKey", kmsMK.metadata).
			Msg("MasterKey: GenerateDataKey")
		return nil, GenerateDataKeyError
	}
	// TODO perform validation on suite.AlgorithmSuite length and generated data key length
	log.Trace().
		Stringer("MK", kmsMK.metadata).
		Msg("MasterKey: GenerateDataKey")
	return &DataKey{
		provider:         kmsMK.metadata,
		dataKey:          dataKeyOutput.Plaintext,
		encryptedDataKey: dataKeyOutput.CiphertextBlob,
	}, nil
}

func (kmsMK *KmsMasterKey) buildGenerateDataKeyRequest(alg *suite.AlgorithmSuite, ec suite.EncryptionContext) *kms.GenerateDataKeyInput {
	return &kms.GenerateDataKeyInput{
		KeyId:             aws.String(kmsMK.metadata.KeyID),
		EncryptionContext: ec,
		NumberOfBytes:     aws.Int32(int32(alg.EncryptionSuite.DataKeyLen)),
	}
}

// EncryptDataKey returns EncryptedDataKey which is encrypted from DataKey that was generated at GenerateDataKey
// EncryptedDataKey contains:
//
//	provider			keyID of this (MasterKey) KmsMasterKey
//	encryptedDataKey	CiphertextBlob is encrypted content of dataKey (this or other)
//
//	i.e. GenerateDataKey (encryption material generator), once per primaryMasterKey ->
//	-> for each MasterKey (KmsMasterKey) registered in providers.MasterKeyProvider do EncryptDataKey
func (kmsMK *KmsMasterKey) EncryptDataKey(dataKey DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (EncryptedDataKeyI, error) {
	// TODO add validations against suite.AlgorithmSuite
	encryptDataKeyRequest := kmsMK.buildEncryptRequest(dataKey, ec)
	// TODO do something with Context
	encryptOutput, err := kmsMK.kmsClient.Encrypt(context.TODO(), encryptDataKeyRequest)
	if err != nil {
		log.Error().Caller().
			Err(err).
			Stringer("MK", kmsMK.metadata).
			Stringer("DK", dataKey.KeyProvider()).
			Msg("MasterKey: EncryptDataKey")
		return nil, fmt.Errorf("KMS error: %v, KmsMasterKey: %w", err, EncryptKeyError)
	}
	log.Trace().
		Stringer("MK", kmsMK.metadata).
		Stringer("DK", dataKey.KeyProvider()).
		Msg("MasterKey: EncryptDataKey")

	return &EncryptedDataKey{
		provider:         kmsMK.metadata,
		encryptedDataKey: encryptOutput.CiphertextBlob,
	}, nil
}

func (kmsMK *KmsMasterKey) buildEncryptRequest(dataKey DataKeyI, ec suite.EncryptionContext) *kms.EncryptInput {
	return &kms.EncryptInput{
		KeyId:             aws.String(kmsMK.metadata.KeyID),
		Plaintext:         dataKey.DataKey(),
		EncryptionContext: ec,
	}
}

// DecryptDataKey returns DataKey which is decrypted from EncryptedDataKey that was encrypted by EncryptDataKey
// DataKey contains:
//
//	provider			keyID of this (MasterKey) KmsMasterKey MUST equals to EncryptedDataKey keyID
//	dataKey				Plaintext is decrypted content of EncryptedDataKey encryptedDataKey
//	encryptedDataKey	encrypted content of (this) EncryptedDataKey
//
// Decrypted dataKey (plaintext) MUST match DataKey (plaintext) that was originally generated at GenerateDataKey
func (kmsMK *KmsMasterKey) DecryptDataKey(encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error) {
	// TODO add validations against suite.AlgorithmSuite
	if kmsMK.OwnsDataKey(encryptedDataKey) == false {
		// that is expected, just log
		log.Trace().Caller().
			AnErr("kmsmk_err", fmt.Errorf("KMSMasterKey doesnt not own EncryptedDataKey, expected behaviour")).
			Stringer("MK", kmsMK.metadata).
			Stringer("EDK", encryptedDataKey.KeyProvider()).
			Msg("MasterKey: DecryptDataKey")
	}
	decryptRequest := kmsMK.buildDecryptRequest(encryptedDataKey, ec)
	// TODO do something with Context
	decryptOutput, err := kmsMK.kmsClient.Decrypt(context.TODO(), decryptRequest)
	if err != nil {
		if smhErr := err.(*smithy.OperationError); smhErr != nil {
			// TODO might handle more exceptions for edge-cases
			//  ref github.com/aws/aws-sdk-go-v2/service/kms@v1.18.5/types/errors.go
			if kmsErr := errors.Unwrap(smhErr.Unwrap()).(*types.IncorrectKeyException); kmsErr != nil {
				// that is normal behaviour
				log.Trace().Caller().AnErr("kmsErr", kmsErr).Msg("KMS expected error")
				return nil, fmt.Errorf("KMS expected error: %v, Error: %w", kmsErr, DecryptKeyError)
			}
		}

		log.Error().Caller().
			Err(err).
			Stringer("MK", kmsMK.metadata).
			Stringer("EDK", encryptedDataKey.KeyProvider()).
			Msg("MasterKey: DecryptDataKey")
		return nil, fmt.Errorf("KMS error: %v, Error: %w", err, DecryptKeyError)
	}

	log.Trace().
		Stringer("MK", kmsMK.metadata).
		Stringer("EDK", encryptedDataKey.KeyProvider()).
		Msg("MasterKey: DecryptDataKey")

	// TODO perform validation for lengths of suite.AlgorithmSuite on decryptOutput
	return &DataKey{
		provider:         encryptedDataKey.KeyProvider(),
		dataKey:          decryptOutput.Plaintext,
		encryptedDataKey: encryptedDataKey.EncryptedDataKey(),
	}, nil
}

func (kmsMK *KmsMasterKey) buildDecryptRequest(encryptedDataKey EncryptedDataKeyI, ec suite.EncryptionContext) *kms.DecryptInput {
	return &kms.DecryptInput{
		CiphertextBlob:    encryptedDataKey.EncryptedDataKey(),
		EncryptionContext: ec,
		KeyId:             aws.String(kmsMK.metadata.KeyID),
	}
}
