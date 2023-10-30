// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rand

import (
	"crypto/rand"
	"fmt"
	"io"
)

//nolint:gochecknoinits
func init() {
	Reader = rand.Reader
}

// Reader provides a random reader that can reset during testing.
var Reader io.Reader //nolint:gochecknoglobals

// RandomBytes returns a slice with random bytes from an io.Reader source.
func RandomBytes(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read random value, %w", err)
	}
	return buf, nil
}

// CryptoRandomBytes returns a slice with random bytes
// obtained from the crypto rand source.
func CryptoRandomBytes(max int) ([]byte, error) {
	return RandomBytes(Reader, max)
}
