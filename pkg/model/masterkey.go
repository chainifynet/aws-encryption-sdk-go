// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// MasterKeyBase is the base interface for all master keys.
type MasterKeyBase interface {
	// KeyID returns the key ID of the master key.
	KeyID() string

	// Metadata returns the metadata of the master key.
	Metadata() KeyMeta

	// OwnsDataKey returns true if key is owned by the master key. In other words,
	// the key was encrypted with the master key.
	OwnsDataKey(key Key) bool
}

// MasterKey is an interface for master key implementations.
type MasterKey interface {
	MasterKeyBase

	// GenerateDataKey generates a new data key and returns it.
	GenerateDataKey(ctx context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)

	// EncryptDataKey encrypts the data key and returns the encrypted data key.
	EncryptDataKey(ctx context.Context, dataKey DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (EncryptedDataKeyI, error)

	// DecryptDataKey decrypts the encrypted data key and returns the data key.
	DecryptDataKey(ctx context.Context, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
}

// MasterKeyFactory is an interface for master key factory.
type MasterKeyFactory interface {
	// NewMasterKey returns a new instance of master key.
	NewMasterKey(args ...interface{}) (MasterKey, error)
}
