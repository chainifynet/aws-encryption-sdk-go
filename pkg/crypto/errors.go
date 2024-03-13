// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"errors"
)

var (
	// ErrDecryption is returned when decryption fails.
	ErrDecryption = errors.New("decryption error")
	// ErrEncryption is returned when encryption fails.
	ErrEncryption = errors.New("encryption error")
)
