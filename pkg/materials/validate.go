// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// validateCachingParams checks if the provided cache and master key provider are non-nil.
func validateCachingParams(c model.Cache, primary model.MasterKeyProvider, opts *CachingOptions) error {
	if c == nil {
		return fmt.Errorf("cache is nil")
	}

	// only check primary if you haven't provided a custom manager
	if primary == nil && opts.Manager == nil {
		return fmt.Errorf("primary MasterKeyProvider nil")
	}
	return nil
}
