// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// TODO andrew refactor, for sure it needs to be moved under keys or providers likely package
func prepareDataKeys(ctx context.Context, primaryMasterKey model.MasterKey, masterKeys []model.MasterKey, algorithm *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, []model.EncryptedDataKeyI, error) {
	encryptedDataKeys := make([]model.EncryptedDataKeyI, 0, len(masterKeys)+1) // +1 for primaryMasterKey

	var encryptedDataEncryptionKey model.EncryptedDataKeyI

	dataEncryptionKey, err := primaryMasterKey.GenerateDataKey(ctx, algorithm, ec)
	if err != nil {
		// TODO just wrap err
		return nil, nil, err
	}

	for _, masterKey := range masterKeys {
		if masterKey.Metadata().Equal(primaryMasterKey.Metadata()) {
			encryptedDataEncryptionKey = model.NewEncryptedDataKey(dataEncryptionKey.KeyProvider(), dataEncryptionKey.EncryptedDataKey())
			encryptedDataKeys = append(encryptedDataKeys, encryptedDataEncryptionKey)
			continue
		}
		encryptedKey, err := masterKey.EncryptDataKey(ctx, dataEncryptionKey, algorithm, ec)
		if err != nil {
			// TODO just wrap err
			return nil, nil, err
		}
		encryptedDataKeys = append(encryptedDataKeys, encryptedKey)
	}
	return dataEncryptionKey, encryptedDataKeys, nil
}
