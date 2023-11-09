// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"errors"
)

var (
	ErrCMM = errors.New("CMM error")
)

type CryptoMaterialsManager interface {
	GetEncryptionMaterials(ctx context.Context, request EncryptionMaterialsRequest) (*EncryptionMaterials, error)
	DecryptMaterials(ctx context.Context, request DecryptionMaterialsRequest) (*DecryptionMaterials, error)
	GetInstance() CryptoMaterialsManager // TODO research and test
}
