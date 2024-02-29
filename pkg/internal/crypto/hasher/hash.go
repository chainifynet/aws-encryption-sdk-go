// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package hasher provides a Hasher interface for hashing data with a given elliptic.Curve.
package hasher

import (
	"crypto/elliptic"
	"fmt"
	"hash"
	"io"
)

type Hasher interface {
	// Writer Write (via the embedded io.Writer interface) adds more data to the running hash.
	// It never returns an error.
	io.Writer

	// Sum appends the current hash to []byte(nil) and returns the resulting slice.
	// It does not change the underlying hash state.
	Sum() []byte

	// Curve returns the elliptic.Curve associated with the Hasher.
	Curve() elliptic.Curve
}

type ECCHasher struct {
	hasher hash.Hash
	curve  elliptic.Curve
}

var _ Hasher = (*ECCHasher)(nil)

func NewECCHasher(hashFn func() hash.Hash, c elliptic.Curve) *ECCHasher {
	return &ECCHasher{hasher: hashFn(), curve: c}
}

func (h *ECCHasher) Write(p []byte) (int, error) {
	n, err := h.hasher.Write(p)
	if err != nil {
		return n, fmt.Errorf("hasher write: %w", err)
	}
	return n, nil
}

func (h *ECCHasher) Sum() []byte {
	return h.hasher.Sum([]byte(nil))
}

func (h *ECCHasher) Curve() elliptic.Curve {
	return h.curve
}
