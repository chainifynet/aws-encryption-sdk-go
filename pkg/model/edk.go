// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

// DataKey contains unencrypted data key and its encrypted version.
type DataKey struct {
	provider         KeyMeta
	dataKey          []byte
	encryptedDataKey []byte
}

var _ DataKeyI = (*DataKey)(nil)

// NewDataKey returns a new [DataKey] with the given provider, dataKey, and encryptedDataKey.
func NewDataKey(provider KeyMeta, dataKey, encryptedDataKey []byte) *DataKey {
	return &DataKey{provider: provider, dataKey: dataKey, encryptedDataKey: encryptedDataKey}
}

// KeyProvider returns the [KeyMeta] of the key.
func (dk DataKey) KeyProvider() KeyMeta {
	return dk.provider
}

// KeyID returns the ID of the key.
func (dk DataKey) KeyID() string {
	return dk.provider.KeyID
}

// EncryptedDataKey returns the encrypted data key of data key.
func (dk DataKey) EncryptedDataKey() []byte {
	return dk.encryptedDataKey
}

// DataKey returns unencrypted data key.
func (dk DataKey) DataKey() []byte {
	return dk.dataKey
}

// EncryptedDataKey contains the encrypted data key and its provider.
type EncryptedDataKey struct {
	provider         KeyMeta
	encryptedDataKey []byte
}

var _ EncryptedDataKeyI = (*EncryptedDataKey)(nil)

// NewEncryptedDataKey returns a new [EncryptedDataKey] with the given provider and encryptedDataKey.
func NewEncryptedDataKey(provider KeyMeta, encryptedDataKey []byte) *EncryptedDataKey {
	return &EncryptedDataKey{
		provider:         provider,
		encryptedDataKey: encryptedDataKey,
	}
}

// KeyProvider returns the [KeyMeta] of the key.
func (edk EncryptedDataKey) KeyProvider() KeyMeta {
	return edk.provider
}

// KeyID returns the ID of the key.
func (edk EncryptedDataKey) KeyID() string {
	return edk.provider.KeyID
}

// EncryptedDataKey returns the encrypted data key of data key.
func (edk EncryptedDataKey) EncryptedDataKey() []byte {
	return edk.encryptedDataKey
}
