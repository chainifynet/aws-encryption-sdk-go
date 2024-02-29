// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"errors"
)

var (
	ErrInvalidMessage = errors.New("invalid message format")
	ErrDecryption     = errors.New("decryption error")
	ErrEncryption     = errors.New("encryption error")
)
