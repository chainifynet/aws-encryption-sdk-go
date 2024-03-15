// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/arn"
)

type MrkMasterKey struct {
	MasterKey
}

type MrkKeyFactory struct{}

func (f *MrkKeyFactory) NewMasterKey(args ...interface{}) (model.MasterKey, error) {
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

	return NewKmsMrkMasterKey(client, keyID)
}

// checking that MrkMasterKey implements both model.MasterKey and KeyHandler interfaces.
var _ model.MasterKey = (*MrkMasterKey)(nil)
var _ KeyHandler = (*MrkMasterKey)(nil)

func NewKmsMrkMasterKey(client model.KMSClient, keyID string) (*MrkMasterKey, error) {
	if client == nil {
		return nil, fmt.Errorf("KMSMrkMasterKey: client must not be nil")
	}
	if keyID == "" {
		return nil, fmt.Errorf("KMSMrkMasterKey: keyID must not be empty")
	}
	return &MrkMasterKey{
		MasterKey: MasterKey{
			BaseKey:   keys.NewBaseKey(model.KeyMeta{ProviderID: types.KmsProviderID, KeyID: keyID}),
			kmsClient: client,
		},
	}, nil
}

func (kmsMrkMK *MrkMasterKey) OwnsDataKey(key model.Key) bool {
	if kmsMrkMK.Metadata().ProviderID == key.KeyProvider().ProviderID && arn.IsMrkArnEqual(kmsMrkMK.Metadata().KeyID, key.KeyID()) {
		return true
	}
	return false
}

func (kmsMrkMK *MrkMasterKey) validateAllowedDecrypt(edkKeyID string) error {
	if !arn.IsMrkArnEqual(kmsMrkMK.Metadata().KeyID, edkKeyID) {
		return fmt.Errorf("MrkMasterKey keyID %q does not match EncryptedDataKey keyID %q: %w", kmsMrkMK.Metadata().KeyID, edkKeyID, keys.ErrDecryptKey)
	}
	return nil
}

func (kmsMrkMK *MrkMasterKey) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	if err := kmsMrkMK.validateAllowedDecrypt(encryptedDataKey.KeyID()); err != nil {
		return nil, err
	}
	return kmsMrkMK.decryptDataKey(ctx, encryptedDataKey, alg, ec)
}
