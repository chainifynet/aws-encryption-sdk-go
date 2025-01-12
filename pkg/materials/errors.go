// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"errors"
)

// ErrCMM is a generic [model.CryptoMaterialsManager] error.
var ErrCMM = errors.New("CMM error")

// ErrInvalidConfig is returned when CMM configuration is invalid.
var ErrInvalidConfig = errors.New("CMM invalid config")
