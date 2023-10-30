// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import (
	"errors"
	"fmt"
	"strings"
)

var ErrMalformedArn = errors.New("malformed Key ARN")

func ValidateKeyArn(keyID string) error {
	elements := strings.SplitN(keyID, ":", 6)

	if len(elements) < 6 {
		return fmt.Errorf("keyID is missing required ARN components, %w", ErrMalformedArn)
	}

	if elements[0] != "arn" {
		return fmt.Errorf("keyID is missing 'arn' string, %w", ErrMalformedArn)
	}

	partition := elements[1]
	service := elements[2]
	region := elements[3]
	account := elements[4]

	if partition == "" {
		return fmt.Errorf("keyID is missing partition, %w", ErrMalformedArn)
	}

	if account == "" {
		return fmt.Errorf("keyID is missing account, %w", ErrMalformedArn)
	}

	if region == "" {
		return fmt.Errorf("keyID is missing region, %w", ErrMalformedArn)
	}

	if service != "kms" {
		return fmt.Errorf("keyID has unknown service, %w", ErrMalformedArn)
	}

	resource := elements[5]
	if resource == "" {
		return fmt.Errorf("keyID is missing resource, %w", ErrMalformedArn)
	}

	resourceElements := strings.SplitN(resource, "/", 2)
	if len(resourceElements) != 2 {
		return fmt.Errorf("keyID resource section is malformed, %w", ErrMalformedArn)
	}

	resourceType := resourceElements[0]
	resourceID := resourceElements[1]

	if resourceType == "alias" {
		return fmt.Errorf("alias keyID is not supported yet, %w", ErrMalformedArn)
	}

	if resourceType != "key" {
		return fmt.Errorf("keyID has unknown resource type, %w", ErrMalformedArn)
	}

	if resourceID == "" {
		return fmt.Errorf("keyID is missing resource id, %w", ErrMalformedArn)
	}

	if resourceType == "key" && strings.HasPrefix(resourceID, "mrk-") {
		return fmt.Errorf("KMS MRK not supported yet, %w", ErrMalformedArn)
	}

	return nil
}
