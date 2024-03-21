// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package mykey provides a custom master key implementation.
//
// # Don't use this implementation in production
//
// [MyKey] implementation using base64 encoding for demonstration purposes only.
package mykey

import (
	"context"
	"crypto/rand"
	b64 "encoding/base64"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// KeyFactory implements [model.MasterKeyFactory] interface.
type KeyFactory struct{}

var _ model.MasterKeyFactory = (*KeyFactory)(nil)

// NewMasterKey is a factory method for creating a new [MyKey].
func (f *KeyFactory) NewMasterKey(args ...interface{}) (model.MasterKey, error) {
	if len(args) != 2 {
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

	return newMasterKey(providerID, keyID)
}

// MyKey implements [model.MasterKey] interface.
type MyKey struct {
	// BaseKey embeds [keys.BaseKey] to provide default implementation for [model.MasterKeyBase].
	keys.BaseKey
}

var _ model.MasterKey = (*MyKey)(nil)

// newMasterKey creates a new instance of [MyKey] with the given providerID and
// keyID embedding [keys.BaseKey].
func newMasterKey(providerID, keyID string) (*MyKey, error) {
	if providerID == "" {
		return nil, fmt.Errorf("providerID is required")
	}
	return &MyKey{
		BaseKey: keys.NewBaseKey(model.WithKeyMeta(providerID, keyID)),
	}, nil
}

// GenerateDataKey generates a new data key and returns it.
//
// # Don't use this implementation in production
//
// This implementation uses base64 encoding to encrypt the data key and must not
// be used in production.
func (m *MyKey) GenerateDataKey(_ context.Context, alg *suite.AlgorithmSuite, _ suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey := make([]byte, alg.EncryptionSuite.DataKeyLen)
	_, err := rand.Read(dataKey)
	if err != nil {
		return nil, fmt.Errorf("generate data key error: %w", err)
	}

	encryptedDataKey := make([]byte, b64.RawStdEncoding.EncodedLen(len(dataKey)))

	b64.RawStdEncoding.Encode(encryptedDataKey, dataKey)

	return model.NewDataKey(
		m.Metadata(),
		dataKey,
		encryptedDataKey,
	), nil
}

// EncryptDataKey encrypts the data key and returns the encrypted data key.
//
// # Don't use this implementation in production
//
// This implementation uses base64 encoding to encrypt the data key and must not
// be used in production.
func (m *MyKey) EncryptDataKey(_ context.Context, dataKey model.DataKeyI, _ *suite.AlgorithmSuite, _ suite.EncryptionContext) (model.EncryptedDataKeyI, error) {
	encryptedDataKey := make([]byte, b64.RawStdEncoding.EncodedLen(len(dataKey.DataKey())))
	b64.RawStdEncoding.Encode(encryptedDataKey, dataKey.DataKey())

	return model.NewEncryptedDataKey(
		m.Metadata(),
		encryptedDataKey,
	), nil
}

// DecryptDataKey decrypts the encrypted data key and returns the data key.
//
// # Don't use this implementation in production
//
// This implementation uses base64 encoding to decrypt the data key and must not
// be used in production.
func (m *MyKey) DecryptDataKey(_ context.Context, encryptedDataKey model.EncryptedDataKeyI, _ *suite.AlgorithmSuite, _ suite.EncryptionContext) (model.DataKeyI, error) {
	dataKey := make([]byte, b64.RawStdEncoding.DecodedLen(len(encryptedDataKey.EncryptedDataKey())))
	_, err := b64.RawStdEncoding.Decode(dataKey, encryptedDataKey.EncryptedDataKey())
	if err != nil {
		return nil, fmt.Errorf("decrypt data key error: %w", err)
	}

	return model.NewDataKey(
		m.Metadata(),
		dataKey,
		encryptedDataKey.EncryptedDataKey(),
	), nil
}
