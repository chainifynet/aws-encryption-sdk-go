// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type MasterKeyBase interface {
	KeyID() string
	Metadata() KeyMeta
	OwnsDataKey(key Key) bool
}

type MasterKey interface {
	MasterKeyBase
	GenerateDataKey(ctx context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
	EncryptDataKey(ctx context.Context, dataKey DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (EncryptedDataKeyI, error)
	DecryptDataKey(ctx context.Context, encryptedDataKey EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (DataKeyI, error)
}

type MasterKeyFactory interface {
	NewMasterKey(args ...interface{}) (MasterKey, error)
}
