// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"fmt"
	"strings"
)

func regionForKeyID(keyID, defaultRegion string) (string, error) {
	parts := strings.Split(keyID, ":")
	if len(parts) < 3 { //nolint:mnd
		// minimum chars in AWS region, i.e. sa-east-1
		if len(defaultRegion) >= _awsRegionMinLength {
			return defaultRegion, nil
		}
		return "", fmt.Errorf("InvalidRegionError: keyID %q", keyID)
	}

	if len(parts[3]) >= _awsRegionMinLength {
		return parts[3], nil
	}

	return "", fmt.Errorf("UnknownRegionError: keyID %q", keyID)
}
