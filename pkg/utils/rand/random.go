// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rand

import (
	"crypto/rand"
	"fmt"
	"io"
)

func init() {
	Reader = rand.Reader
}

// Reader provides a random reader that can reset during testing.
var Reader io.Reader

// RandomBytes returns a slice with random bytes from an io.Reader source.
func RandomBytes(reader io.Reader, len int) ([]byte, error) {
	buf := make([]byte, len)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read random value, %w", err)
	}
	return buf, nil
}

// CryptoRandomBytes returns a slice with random bytes
// obtained from the crypto rand source
func CryptoRandomBytes(max int) ([]byte, error) {
	return RandomBytes(Reader, max)
}
