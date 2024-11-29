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

// MrkMasterKey is a Kms [MasterKey] that uses a KMS multi-Region key. It embeds
// the Kms [MasterKey] and implements the Kms [KeyHandler] interface.
type MrkMasterKey struct {
	MasterKey
}

// MrkKeyFactory is a factory for creating Kms [MrkMasterKey].
type MrkKeyFactory struct{}

// NewMasterKey factory method returns a new instance of Kms [MrkMasterKey].
func (f *MrkKeyFactory) NewMasterKey(args ...interface{}) (model.MasterKey, error) {
	if len(args) != 2 { //nolint:mnd
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

	return newKmsMrkMasterKey(client, keyID)
}

// checking that MrkMasterKey implements both model.MasterKey and KeyHandler interfaces.
var _ model.MasterKey = (*MrkMasterKey)(nil)
var _ KeyHandler = (*MrkMasterKey)(nil)

func newKmsMrkMasterKey(client model.KMSClient, keyID string) (*MrkMasterKey, error) {
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

// OwnsDataKey checks if the key resource ARN matches the keyID of the master
// key. Both ARNs must be MRK ARNs.
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

// DecryptDataKey decrypts the encrypted data key and returns the data key.
func (kmsMrkMK *MrkMasterKey) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	if err := kmsMrkMK.validateAllowedDecrypt(encryptedDataKey.KeyID()); err != nil {
		return nil, err
	}
	return kmsMrkMK.decryptDataKey(ctx, encryptedDataKey, alg, ec)
}
