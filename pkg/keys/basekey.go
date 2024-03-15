// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"

// BaseKey is implementation of [model.MasterKeyBase] that methods can be reused or
// overridden by other master key implementations.
type BaseKey struct {
	metadata model.KeyMeta
}

// NewBaseKey returns a new instance of [BaseKey].
func NewBaseKey(metadata model.KeyMeta) BaseKey {
	return BaseKey{metadata: metadata}
}

// KeyID returns the key ID of the master key.
func (mk *BaseKey) KeyID() string {
	return mk.metadata.KeyID
}

// Metadata returns the [model.KeyMeta] metadata of the master key.
func (mk *BaseKey) Metadata() model.KeyMeta {
	return mk.metadata
}

// OwnsDataKey returns true if key is owned by the master key. In other words,
// the key was encrypted with the master key.
//
// Raw Master Key and KMS MRK Master Key implementations are using a different
// logic to determine if the key is owned by the master key.
func (mk *BaseKey) OwnsDataKey(key model.Key) bool {
	return mk.metadata.KeyID == key.KeyID()
}
