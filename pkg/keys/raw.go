// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization/wrappingkey"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/keyderivation"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

type RawMasterKeyI interface {
	MasterKeyBase
	encryptDataKey(dataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error)
	decryptDataKey(encryptedDataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error)
}

type RawMasterKey struct {
	metadata       KeyMeta
	derivedDataKey []byte
	Encrypter      encryption.GcmBase
	keyWrapper     wrappingkey.Wrapper
}

func NewRawMasterKey(providerID, keyID string, rawKey []byte) *RawMasterKey {
	rawKeyCpy := make([]byte, len(rawKey))
	copy(rawKeyCpy, rawKey)

	derivedDataKey, err := keyderivation.DeriveDataEncryptionKey(
		rawKeyCpy,
		suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		nil,
	)
	if err != nil {
		log.Error().Err(err).Msg("derive data encryption key")
		panic(err)
	}

	return &RawMasterKey{
		metadata: KeyMeta{
			ProviderID: providerID,
			KeyID:      keyID,
		},
		derivedDataKey: derivedDataKey,
		Encrypter:      encryption.Gcm{},
		keyWrapper:     wrappingkey.WrappingKey{},
	}
}

// checking that RawMasterKey implements both MasterKeyBase and RawMasterKeyI interfaces.
var _ MasterKeyBase = (*RawMasterKey)(nil)
var _ RawMasterKeyI = (*RawMasterKey)(nil)

func (rawMK *RawMasterKey) KeyID() string {
	return rawMK.metadata.KeyID
}

func (rawMK *RawMasterKey) Metadata() KeyMeta {
	return rawMK.metadata
}

func (rawMK *RawMasterKey) OwnsDataKey(key Key) bool {
	return rawMK.metadata.KeyID == key.KeyID()
}

func (rawMK *RawMasterKey) GenerateDataKey(_ context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error) {
	dataKey, _ := rand.CryptoRandomBytes(alg.EncryptionSuite.DataKeyLen)

	encryptedDataKey, err := rawMK.encryptDataKey(dataKey, alg, ec)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", errors.Join(ErrGenerateDataKey, err))
	}

	return &DataKey{
		provider:         rawMK.metadata,
		dataKey:          dataKey,
		encryptedDataKey: encryptedDataKey,
	}, nil
}

func (rawMK *RawMasterKey) encryptDataKey(dataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error) {
	if len(dataKey) != alg.EncryptionSuite.DataKeyLen {
		return nil, fmt.Errorf("data key length is invalid")
	}
	serializedEncryptionContext := ec.Serialize()

	iv, _ := rand.CryptoRandomBytes(alg.EncryptionSuite.IVLen)

	encryptedKey, tag, err := rawMK.Encrypter.Encrypt(rawMK.derivedDataKey, iv, dataKey, serializedEncryptionContext)
	if err != nil {
		return nil, err
	}

	encryptedDataKey := rawMK.keyWrapper.SerializeEncryptedDataKey(encryptedKey, tag, iv)

	return encryptedDataKey, nil
}

func (rawMK *RawMasterKey) EncryptDataKey(_ context.Context, dk DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (EncryptedDataKeyI, error) {
	encryptedDataKey, err := rawMK.encryptDataKey(dk.DataKey(), alg, ec)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", errors.Join(ErrEncryptKey, err))
	}

	return &EncryptedDataKey{
		provider:         rawMK.metadata,
		encryptedDataKey: encryptedDataKey,
	}, nil
}

func (rawMK *RawMasterKey) DecryptDataKey(_ context.Context, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error) {
	if encryptedDataKey == nil {
		return nil, fmt.Errorf("RawMasterKey error: invalid encryptedDataKey: %w", ErrDecryptKey)
	}
	dataKey, err := rawMK.decryptDataKey(encryptedDataKey.EncryptedDataKey(), alg, ec)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", errors.Join(ErrDecryptKey, err))
	}

	return &DataKey{
		provider:         encryptedDataKey.KeyProvider(),
		dataKey:          dataKey,
		encryptedDataKey: encryptedDataKey.EncryptedDataKey(),
	}, nil
}

func (rawMK *RawMasterKey) decryptDataKey(encryptedDataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error) {
	if len(encryptedDataKey) != alg.EncryptionSuite.DataKeyLen+alg.EncryptionSuite.AuthLen+alg.EncryptionSuite.IVLen {
		return nil, fmt.Errorf("encrypted data key length is invalid")
	}
	serializedEncryptionContext := ec.Serialize()
	encryptedData, iv := rawMK.keyWrapper.DeserializeEncryptedDataKey(encryptedDataKey, alg.EncryptionSuite.IVLen)

	// encryptedData is ciphertext + tag, im too lazy to extract it
	dataKey, err := rawMK.Encrypter.Decrypt(rawMK.derivedDataKey, iv, encryptedData, nil, serializedEncryptionContext)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}
