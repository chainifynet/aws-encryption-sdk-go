// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"hash"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

type keyHasher struct {
	hasher hash.Hash
}

// NewKeyHasher returns a new instance of the key hasher.
func NewKeyHasher() model.CacheHasher {
	return &keyHasher{hasher: sha512.New()}
}

// Update processes the input byte slice `p` to update the hash state.
func (h *keyHasher) Update(p []byte) {
	h.hasher.Write(p)
}

// Compute finalizes the hash computation and returns the hash as a string.
// The method should be invoked after providing all input to the hasher using
// the Update method. The resulting string is typically used as a cache key.
// After calling, the hasher state is reset and can be reused.
func (h *keyHasher) Compute() string {
	result := hex.EncodeToString(h.hasher.Sum(nil))
	h.hasher.Reset()
	return result
}

// ComputeEncCacheKey generates a unique cache key for encryption materials.
// It considers partition data, algorithm ID, and serialized encryption context.
func ComputeEncCacheKey(partition []byte, r model.EncryptionMaterialsRequest, hasherFn model.KeyHasherFunc) string {
	if hasherFn == nil {
		hasherFn = NewKeyHasher
	}
	h := hasherFn()

	h.Update(partition)
	algorithmInfo := func() []byte {
		if r.Algorithm != nil {
			return append([]byte{0x01}, r.Algorithm.IDBytes()...)
		}
		return []byte{0x00}
	}
	h.Update(algorithmInfo())
	h.Update(r.EncryptionContext.Serialize())
	return h.Compute()
}

// ComputeDecCacheKey generates a cache key for decryption requests.
//
// The function considers several components:
// - partition data
// - Algorithm ID
// - Serialized encrypted data keys
// - Fixed-size padding (64 bytes)
// - Serialized encryption context
//
// The result is a hexadecimal string of computed hash.
func ComputeDecCacheKey(partition []byte, r model.DecryptionMaterialsRequest, hasherFn model.KeyHasherFunc) string {
	if hasherFn == nil {
		hasherFn = NewKeyHasher
	}
	h := hasherFn()

	h.Update(partition)
	if r.Algorithm != nil {
		h.Update(r.Algorithm.IDBytes())
	}
	serializeEdk := func() []byte {
		if len(r.EncryptedDataKeys) == 0 {
			return []byte{}
		}
		buf := new(bytes.Buffer)
		for _, edk := range r.EncryptedDataKeys {
			if edk == nil {
				continue // Skip nil entries, handle gracefully
			}
			buf.WriteString(edk.KeyProvider().ProviderID)
			buf.WriteString(edk.KeyID())
			buf.Write(edk.EncryptedDataKey())
		}
		return buf.Bytes()
	}
	h.Update(serializeEdk())
	h.Update(make([]byte, 64))
	h.Update(r.EncryptionContext.Serialize())
	return h.Compute()
}
