// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import "errors"

// ErrDecryptKey is returned when the data key cannot be decrypted.
var ErrDecryptKey = errors.New("unable to decrypt data key")

// ErrGenerateDataKey is returned when the data key cannot be generated.
var ErrGenerateDataKey = errors.New("unable to generate data key")

// ErrEncryptKey is returned when the data key cannot be encrypted.
var ErrEncryptKey = errors.New("unable to encrypt data key")
