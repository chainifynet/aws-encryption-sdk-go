// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package raw

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/serialization/wrappingkey"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/keyderivation"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/rand"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// KeyHandler is an interface specific to the RawMasterKey which is used by Raw
// Master Key Provider.
type KeyHandler interface {
	model.MasterKey
	encryptDataKey(dataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error)
	decryptDataKey(encryptedDataKey []byte, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) ([]byte, error)
}

// KeyFactory is a factory for creating RawMasterKey.
type KeyFactory struct{}

// NewMasterKey factory method returns a new instance of Raw [MasterKey].
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

	return newRawMasterKey(providerID, keyID, rawKey)
}

// MasterKey contains the Raw Master Key and implements the [model.MasterKey] interface.
type MasterKey struct {
	keys.BaseKey
	keyInfoPrefix  []byte
	derivedDataKey []byte
	Encrypter      model.GcmCrypter
	keyWrapper     model.Wrapper
}

func newRawMasterKey(providerID, keyID string, rawKey []byte) (*MasterKey, error) {
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

// GenerateDataKey generates a new data key and returns it.
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

// EncryptDataKey encrypts the data key and returns the encrypted data key.
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

// OwnsDataKey returns true if key is owned by the master key. In other words,
// the key was encrypted with the master key.
func (rawMK *MasterKey) OwnsDataKey(key model.Key) bool {
	otherKeyInfoPrefix := rawMK.keyWrapper.SerializeKeyInfoPrefix(key.KeyID())
	if rawMK.Metadata().ProviderID == key.KeyProvider().ProviderID &&
		len(otherKeyInfoPrefix) == len(rawMK.keyInfoPrefix) &&
		bytes.HasPrefix(otherKeyInfoPrefix, rawMK.keyInfoPrefix) {
		return true
	}
	return false
}

// DecryptDataKey decrypts the encrypted data key and returns the data key.
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
