// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import (
	"errors"
	"fmt"
	"strings"
)

const (
	arnPrefix         = "arn:"
	delim             = ":"
	mrkPrefix         = "mrk-"
	KeyResourceType   = "key"
	aliasResourceType = "alias"
)

// ErrMalformedArn is returned when the ARN is malformed.
var ErrMalformedArn = errors.New("malformed Key ARN")

// KeyArn represents an AWS Key ARN.
type KeyArn struct {
	Partition    string // AWS partition, e.g. aws, aws-cn, aws-us-gov
	Service      string // AWS service, kms
	Region       string // AWS region, us-east-1, eu-west-1
	Account      string // AWS account ID, 12 digits
	ResourceType string // AWS resource type, either "key" or "alias"
	ResourceID   string // AWS resource ID, resource ID or alias name
}

// String returns the string representation of the ARN.
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
		}, delim),
		a.ResourceID,
	)
}

// IsMrk returns true if the ARN is a multi-region key (MRK) ARN, otherwise false.
func (a *KeyArn) IsMrk() bool {
	// If resource type is "alias", this is an AWS KMS alias ARN and MUST
	// return "false".
	//
	// If resource type is "key" and resource ID does not start with "mrk-",
	// this is a (single-region) AWS KMS key ARN and MUST return "false".
	//
	// If resource type is "key" and resource ID starts with
	// "mrk-", this is an AWS KMS multi-Region key ARN and MUST return "true".
	return a.ResourceType == KeyResourceType && strings.HasPrefix(a.ResourceID, mrkPrefix)
}

// ParseArn parses str string as an ARN (KeyArn).
func ParseArn(str string) (*KeyArn, error) {
	elements := strings.SplitN(str, delim, 6)

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

	// TODO remove below to support aliases
	if resourceType == aliasResourceType {
		return nil, fmt.Errorf("alias keyID is not supported yet, %w", ErrMalformedArn)
	}

	if resourceType != KeyResourceType {
		return nil, fmt.Errorf("keyID has unknown resource type, %w", ErrMalformedArn)
	}

	if resourceID == "" {
		return nil, fmt.Errorf("keyID is missing resource id, %w", ErrMalformedArn)
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

// ValidateKeyArn validates the keyID as an ARN.
func ValidateKeyArn(keyID string) error {
	_, err := ParseArn(keyID)
	if err != nil {
		return err
	}
	return nil
}
