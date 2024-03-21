// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	typesaws "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/arn"
)

// ErrKmsClient is returned when AWS KMS encounters an error.
var ErrKmsClient = errors.New("KMSClient error")

// KeyHandler is an interface specific to the Kms [MasterKey] which is used by
// the KmsMasterKeyProvider.
type KeyHandler interface {
	model.MasterKey
	decryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, _ *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error)
	buildGenerateDataKeyRequest(alg *suite.AlgorithmSuite, ec suite.EncryptionContext) *kms.GenerateDataKeyInput
	buildEncryptRequest(dataKey model.DataKeyI, ec suite.EncryptionContext) *kms.EncryptInput
	buildDecryptRequest(encryptedDataKey model.EncryptedDataKeyI, ec suite.EncryptionContext) *kms.DecryptInput
	validateAllowedDecrypt(edkKeyID string) error
}

// KeyFactory is a factory for creating Kms [MasterKey].
type KeyFactory struct{}

// NewMasterKey factory method returns a new instance of Kms [MasterKey].
func (f *KeyFactory) NewMasterKey(args ...interface{}) (model.MasterKey, error) {
	if len(args) != 2 { //nolint:gomnd
		return nil, fmt.Errorf("invalid number of arguments")
	}

	client, ok := args[0].(model.KMSClient)
	if !ok {
		return nil, fmt.Errorf("invalid KMSClient")
	}
	keyID, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid keyID")
	}

	return newKmsMasterKey(client, keyID)
}

// MasterKey contains the Kms Master Key, KMS Client, and it implements the [model.MasterKey] interface.
type MasterKey struct {
	keys.BaseKey
	kmsClient model.KMSClient
}

func newKmsMasterKey(client model.KMSClient, keyID string) (*MasterKey, error) {
	if client == nil {
		return nil, fmt.Errorf("KMSMasterKey: client must not be nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("KMSMasterKey: keyID must not be empty")
	}
	return &MasterKey{
		BaseKey:   keys.NewBaseKey(model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: keyID}),
		kmsClient: client,
	}, nil
}

// checking that MasterKey implements both model.MasterKey and KeyHandler interfaces.
var _ model.MasterKey = (*MasterKey)(nil)
var _ KeyHandler = (*MasterKey)(nil)

// GenerateDataKey generates a new data key and returns it.
func (kmsMK *MasterKey) GenerateDataKey(ctx context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKeyRequest := kmsMK.buildGenerateDataKeyRequest(alg, ec)

	dataKeyOutput, err := kmsMK.kmsClient.GenerateDataKey(ctx, dataKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrGenerateDataKey, err))
	}
	if err := arn.ValidateKeyArn(aws.ToString(dataKeyOutput.KeyId)); err != nil {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrGenerateDataKey, err))
	}
	if len(dataKeyOutput.Plaintext) != alg.EncryptionSuite.DataKeyLen {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrGenerateDataKey, fmt.Errorf("plaintext length %d does not match expected length %d", len(dataKeyOutput.Plaintext), alg.EncryptionSuite.DataKeyLen)))
	}
	if len(dataKeyOutput.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrGenerateDataKey, fmt.Errorf("dataKeyOutput.CiphertextBlob length %d is empty", len(dataKeyOutput.CiphertextBlob))))
	}
	return model.NewDataKey(
		kmsMK.Metadata(),
		dataKeyOutput.Plaintext,
		dataKeyOutput.CiphertextBlob,
	), nil
}

func (kmsMK *MasterKey) buildGenerateDataKeyRequest(alg *suite.AlgorithmSuite, ec suite.EncryptionContext) *kms.GenerateDataKeyInput {
	return &kms.GenerateDataKeyInput{
		KeyId:             aws.String(kmsMK.Metadata().KeyID),
		EncryptionContext: ec,
		NumberOfBytes:     aws.Int32(int32(alg.EncryptionSuite.DataKeyLen)),
	}
}

// EncryptDataKey encrypts the data key and returns the encrypted data key.
func (kmsMK *MasterKey) EncryptDataKey(ctx context.Context, dataKey model.DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.EncryptedDataKeyI, error) {
	encryptDataKeyRequest := kmsMK.buildEncryptRequest(dataKey, ec)

	encryptOutput, err := kmsMK.kmsClient.Encrypt(ctx, encryptDataKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrEncryptKey, err))
	}
	if err := arn.ValidateKeyArn(aws.ToString(encryptOutput.KeyId)); err != nil {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrEncryptKey, err))
	}
	if len(dataKey.DataKey()) != alg.EncryptionSuite.DataKeyLen {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrEncryptKey, fmt.Errorf("plaintext length %d does not match expected length %d", len(dataKey.DataKey()), alg.EncryptionSuite.DataKeyLen)))
	}
	if len(encryptOutput.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrEncryptKey, fmt.Errorf("dataKeyOutput.CiphertextBlob length %d is empty", len(encryptOutput.CiphertextBlob))))
	}

	return model.NewEncryptedDataKey(
		kmsMK.Metadata(),
		encryptOutput.CiphertextBlob,
	), nil
}

func (kmsMK *MasterKey) buildEncryptRequest(dataKey model.DataKeyI, ec suite.EncryptionContext) *kms.EncryptInput {
	return &kms.EncryptInput{
		KeyId:             aws.String(kmsMK.Metadata().KeyID),
		Plaintext:         dataKey.DataKey(),
		EncryptionContext: ec,
	}
}

func (kmsMK *MasterKey) validateAllowedDecrypt(edkKeyID string) error {
	if kmsMK.Metadata().KeyID != edkKeyID {
		return fmt.Errorf("KMSMasterKey keyID %q does not match EncryptedDataKey keyID %q: %w", kmsMK.Metadata().KeyID, edkKeyID, keys.ErrDecryptKey)
	}
	return nil
}

// DecryptDataKey decrypts the encrypted data key and returns the data key.
func (kmsMK *MasterKey) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	if err := kmsMK.validateAllowedDecrypt(encryptedDataKey.KeyID()); err != nil {
		return nil, err
	}
	return kmsMK.decryptDataKey(ctx, encryptedDataKey, alg, ec)
}

func (kmsMK *MasterKey) decryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	_, err := arn.ParseArn(encryptedDataKey.KeyID())
	if err != nil {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrDecryptKey, err))
	}
	// TODO uncomment below when aliases are supported
	//if keyArn.ResourceType != arn.KeyResourceType {
	//	return nil, fmt.Errorf("KMSMasterKey invalid EDK keyID %q: %w", encryptedDataKey.KeyID(), ErrDecryptKey)
	//}
	decryptRequest := kmsMK.buildDecryptRequest(encryptedDataKey, ec)

	decryptOutput, err := kmsMK.kmsClient.Decrypt(ctx, decryptRequest)
	if err != nil {
		var smhErr1 *smithy.OperationError
		if errors.As(err, &smhErr1) {
			// smhErr is *smithy.OperationError here
			// smhErr.Unwrap() is *http.ResponseError - gets Err property which is ResponseError
			// calling responseError.Unwrap() - gets Err property which is *typesaws.IncorrectKeyException
			var responseError *http.ResponseError
			if errors.As(smhErr1.Unwrap(), &responseError) {
				var kmsErr *typesaws.IncorrectKeyException
				if errors.As(responseError.Unwrap(), &kmsErr) {
					// kmsErr is *typesaws.IncorrectKeyException here
					// TODO might handle more exceptions for edge-cases
					// ref github.com/aws/aws-sdk-go-v2/service/kms@v1.18.5/types/errors.go
					// ref2 https://github.com/aws/aws-sdk-go-v2/issues/1110
					// that is normal behaviour, we'll try to decrypt with other MasterKey in MasterKeyProvider
					return nil, fmt.Errorf("KMSMasterKey expected error: %w", errors.Join(keys.ErrDecryptKey, ErrKmsClient, kmsErr))
				}
			}
		}

		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrDecryptKey, ErrKmsClient, err))
	}

	if aws.ToString(decryptOutput.KeyId) != kmsMK.Metadata().KeyID {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrDecryptKey, fmt.Errorf("keyID %q does not match expected keyID %q", aws.ToString(decryptOutput.KeyId), kmsMK.Metadata().KeyID)))
	}

	if len(decryptOutput.Plaintext) != alg.EncryptionSuite.DataKeyLen {
		return nil, fmt.Errorf("KMSMasterKey error: %w", errors.Join(keys.ErrDecryptKey, fmt.Errorf("plaintext length %d does not match algorithm expected length %d", len(decryptOutput.Plaintext), alg.EncryptionSuite.DataKeyLen)))
	}

	return model.NewDataKey(
		kmsMK.Metadata(),
		decryptOutput.Plaintext,
		encryptedDataKey.EncryptedDataKey(),
	), nil
}

func (kmsMK *MasterKey) buildDecryptRequest(encryptedDataKey model.EncryptedDataKeyI, ec suite.EncryptionContext) *kms.DecryptInput {
	return &kms.DecryptInput{
		CiphertextBlob:    encryptedDataKey.EncryptedDataKey(),
		EncryptionContext: ec,
		KeyId:             aws.String(kmsMK.Metadata().KeyID),
	}
}
