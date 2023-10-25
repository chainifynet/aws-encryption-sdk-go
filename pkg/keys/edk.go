// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

type DataKey struct {
	provider         KeyMeta
	dataKey          []byte
	encryptedDataKey []byte
}

var _ DataKeyI = (*DataKey)(nil)

func (dk DataKey) KeyProvider() KeyMeta {
	return dk.provider
}

func (dk DataKey) KeyID() string {
	return dk.provider.KeyID
}

func (dk DataKey) EncryptedDataKey() []byte {
	return dk.encryptedDataKey
}

func (dk DataKey) DataKey() []byte {
	return dk.dataKey
}

func NewEncryptedDataKey(provider KeyMeta, encryptedDataKey []byte) *EncryptedDataKey {
	return &EncryptedDataKey{
		provider:         provider,
		encryptedDataKey: encryptedDataKey,
	}
}

var _ EncryptedDataKeyI = (*EncryptedDataKey)(nil)

type EncryptedDataKey struct {
	provider         KeyMeta
	encryptedDataKey []byte
}

func (edk EncryptedDataKey) KeyProvider() KeyMeta {
	return edk.provider
}

func (edk EncryptedDataKey) KeyID() string {
	return edk.provider.KeyID
}

func (edk EncryptedDataKey) EncryptedDataKey() []byte {
	return edk.encryptedDataKey
}
