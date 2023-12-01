// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

type KeyBase interface {
	KeyProvider() KeyMeta
	KeyID() string
}

type Key interface {
	KeyBase
}

type DataKeyI interface {
	Key

	EncryptedDataKey() []byte
	DataKey() []byte
}

type EncryptedDataKeyI interface {
	Key
	EncryptedDataKey() []byte
}

type KeyMeta struct {
	ProviderID string
	KeyID      string
}

func WithKeyMeta(providerID, keyID string) KeyMeta {
	return KeyMeta{
		ProviderID: providerID,
		KeyID:      keyID,
	}
}

func (km KeyMeta) Equal(other KeyMeta) bool {
	if km.ProviderID != other.ProviderID || km.KeyID != other.KeyID {
		return false
	}
	return true
}

func (km KeyMeta) String() string {
	return km.ProviderID + "__" + km.KeyID
}
