// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// validateParams validates the parameters for the given context, source, and CryptoMaterialsManager
func validateParams(ctx context.Context, b []byte, cmm model.CryptoMaterialsManager) error {
	if ctx == nil {
		return fmt.Errorf("nil context")
	}
	if len(b) == 0 {
		return fmt.Errorf("empty source")
	}
	if cmm == nil {
		return fmt.Errorf("nil materials manager")
	}
	return nil
}
