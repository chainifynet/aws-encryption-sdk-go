// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import (
	"errors"
	"fmt"
	"strings"
)

var ErrMalformedArn = errors.New("malformed Key ARN")

type KeyArn struct {
	Partition    string
	Service      string
	Region       string
	Account      string
	ResourceType string
	ResourceID   string
}

func (a *KeyArn) String() string {
	return fmt.Sprintf(
		"%s/%s",
		strings.Join([]string{
			"arn",
			a.Partition,
			a.Service,
			a.Region,
			a.Account,
			a.ResourceType,
		}, ":"),
		a.ResourceID,
	)
}

func ParseArn(str string) (*KeyArn, error) {
	elements := strings.SplitN(str, ":", 6)

	if len(elements) < 6 {
		return nil, fmt.Errorf("keyID is missing required ARN components, %w", ErrMalformedArn)
	}

	if elements[0] != "arn" {
		return nil, fmt.Errorf("keyID is missing 'arn' string, %w", ErrMalformedArn)
	}

	partition := elements[1]
	service := elements[2]
	region := elements[3]
	account := elements[4]

	if partition == "" {
		return nil, fmt.Errorf("keyID is missing partition, %w", ErrMalformedArn)
	}

	if account == "" {
		return nil, fmt.Errorf("keyID is missing account, %w", ErrMalformedArn)
	}

	if region == "" {
		return nil, fmt.Errorf("keyID is missing region, %w", ErrMalformedArn)
	}

	if service != "kms" {
		return nil, fmt.Errorf("keyID has unknown service, %w", ErrMalformedArn)
	}

	resource := elements[5]
	if resource == "" {
		return nil, fmt.Errorf("keyID is missing resource, %w", ErrMalformedArn)
	}

	resourceElements := strings.SplitN(resource, "/", 2)
	if len(resourceElements) != 2 {
		return nil, fmt.Errorf("keyID resource section is malformed, %w", ErrMalformedArn)
	}

	resourceType := resourceElements[0]
	resourceID := resourceElements[1]

	if resourceType == "alias" {
		return nil, fmt.Errorf("alias keyID is not supported yet, %w", ErrMalformedArn)
	}

	if resourceType != "key" {
		return nil, fmt.Errorf("keyID has unknown resource type, %w", ErrMalformedArn)
	}

	if resourceID == "" {
		return nil, fmt.Errorf("keyID is missing resource id, %w", ErrMalformedArn)
	}

	if resourceType == "key" && strings.HasPrefix(resourceID, "mrk-") {
		return nil, fmt.Errorf("KMS MRK not supported yet, %w", ErrMalformedArn)
	}

	return &KeyArn{
		Partition:    partition,
		Service:      service,
		Region:       region,
		Account:      account,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}, nil
}

func ValidateKeyArn(keyID string) error {
	_, err := ParseArn(keyID)
	if err != nil {
		return err
	}
	return nil
}
