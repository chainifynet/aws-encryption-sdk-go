// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization/wrappingkey"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/keyderivation"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

type KeyHandler interface {
	model.MasterKey
	encryptDataKey(dataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error)
	decryptDataKey(encryptedDataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error)
}

type KeyFactory struct{}

func (f *KeyFactory) NewMasterKey(args ...interface{}) (model.MasterKey, error) {
	if len(args) != 3 { //nolint:gomnd
		return nil, fmt.Errorf("invalid number of arguments")
	}
	providerID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid providerID")
	}
	keyID, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid keyID")
	}
	rawKey, ok := args[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid rawKey")
	}

	return NewRawMasterKey(providerID, keyID, rawKey)
}

type MasterKey struct {
	keys.BaseKey
	keyInfoPrefix  []byte
	derivedDataKey []byte
	Encrypter      encryption.GcmBase
	keyWrapper     model.Wrapper
}

func NewRawMasterKey(providerID, keyID string, rawKey []byte) (*MasterKey, error) {
	rawKeyCpy := make([]byte, len(rawKey))
	copy(rawKeyCpy, rawKey)

	derivedDataKey, err := keyderivation.DeriveDataEncryptionKey(
		rawKeyCpy,
		suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", err)
	}

	keyWrapper := wrappingkey.WrappingKey{}

	return &MasterKey{
		BaseKey:        keys.NewBaseKey(model.KeyMeta{ProviderID: providerID, KeyID: keyID}),
		keyInfoPrefix:  keyWrapper.SerializeKeyInfoPrefix(keyID),
		derivedDataKey: derivedDataKey,
		Encrypter:      encryption.Gcm{},
		keyWrapper:     keyWrapper,
	}, nil
}

// checking that MasterKey implements both model.MasterKey and KeyHandler interfaces.
var _ model.MasterKey = (*MasterKey)(nil)
var _ KeyHandler = (*MasterKey)(nil)

func (rawMK *MasterKey) GenerateDataKey(_ context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey, _ := rand.CryptoRandomBytes(alg.EncryptionSuite.DataKeyLen)

	encryptedDataKey, err := rawMK.encryptDataKey(dataKey, alg, ec)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", errors.Join(keys.ErrGenerateDataKey, err))
	}

	return model.NewDataKey(
		rawMK.Metadata(),
		dataKey,
		encryptedDataKey,
	), nil
}

func (rawMK *MasterKey) encryptDataKey(dataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error) {
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

func (rawMK *MasterKey) EncryptDataKey(_ context.Context, dk model.DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.EncryptedDataKeyI, error) {
	encryptedDataKey, err := rawMK.encryptDataKey(dk.DataKey(), alg, ec)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", errors.Join(keys.ErrEncryptKey, err))
	}

	return model.NewEncryptedDataKey(
		rawMK.Metadata(),
		encryptedDataKey,
	), nil
}

func (rawMK *MasterKey) OwnsDataKey(key model.Key) bool {
	otherKeyInfoPrefix := rawMK.keyWrapper.SerializeKeyInfoPrefix(key.KeyID())
	if rawMK.Metadata().ProviderID == key.KeyProvider().ProviderID &&
		len(otherKeyInfoPrefix) == len(rawMK.keyInfoPrefix) &&
		bytes.HasPrefix(otherKeyInfoPrefix, rawMK.keyInfoPrefix) {
		return true
	}
	return false
}

func (rawMK *MasterKey) DecryptDataKey(_ context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	if encryptedDataKey == nil {
		return nil, fmt.Errorf("RawMasterKey error: invalid encryptedDataKey: %w", keys.ErrDecryptKey)
	}
	dataKey, err := rawMK.decryptDataKey(encryptedDataKey.EncryptedDataKey(), alg, ec)
	if err != nil {
		return nil, fmt.Errorf("RawMasterKey error: %w", errors.Join(keys.ErrDecryptKey, err))
	}

	return model.NewDataKey(
		rawMK.Metadata(),
		dataKey,
		encryptedDataKey.EncryptedDataKey(),
	), nil
}

func (rawMK *MasterKey) decryptDataKey(encryptedDataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error) {
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
