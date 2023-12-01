// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import "errors"

var (
	ErrDecryptKey      = errors.New("unable to decrypt data key")
	ErrGenerateDataKey = errors.New("unable to generate data key")
	ErrEncryptKey      = errors.New("unable to encrypt data key")
)
