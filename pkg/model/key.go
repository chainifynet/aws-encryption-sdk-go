// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

// Key is a base interface for both [DataKey] and [EncryptedDataKey].
type Key interface {
	// KeyProvider returns the KeyMeta of the key.
	KeyProvider() KeyMeta

	// KeyID returns the ID of the key.
	KeyID() string
}

// DataKeyI is an interface for [DataKey].
type DataKeyI interface {
	Key

	// EncryptedDataKey returns the encrypted data key of data key.
	EncryptedDataKey() []byte

	// DataKey returns unencrypted data key.
	DataKey() []byte
}

// EncryptedDataKeyI is an interface for [EncryptedDataKey].
type EncryptedDataKeyI interface {
	Key

	// EncryptedDataKey returns the encrypted data key of data key.
	EncryptedDataKey() []byte
}

// KeyMeta is a struct that holds metadata of a [Key].
type KeyMeta struct {
	// ProviderID is the ID of the key provider.
	ProviderID string

	// KeyID is the ID of the key.
	KeyID string
}

// WithKeyMeta returns a new [KeyMeta] with the given providerID and keyID.
func WithKeyMeta(providerID, keyID string) KeyMeta {
	return KeyMeta{
		ProviderID: providerID,
		KeyID:      keyID,
	}
}

// Equal returns true if the given [KeyMeta] is equal to the current [KeyMeta].
func (km KeyMeta) Equal(other KeyMeta) bool {
	if km.ProviderID != other.ProviderID || km.KeyID != other.KeyID {
		return false
	}
	return true
}

// String returns a string representation of the [KeyMeta].
func (km KeyMeta) String() string {
	return km.ProviderID + "__" + km.KeyID
}
