// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/arn"
)

type KmsProviderOptions struct {
	awsLoadOptions  []func(options *config.LoadOptions) error
	discovery       bool
	discoveryFilter *discoveryFilter
}

type KmsOptionFunc func(options *KmsProviderOptions) error

func WithAwsLoadOptions(opts ...func(options *config.LoadOptions) error) KmsOptionFunc {
	return func(o *KmsProviderOptions) error {
		o.awsLoadOptions = opts
		return nil
	}
}

func WithDiscovery(enabled bool) KmsOptionFunc {
	return func(o *KmsProviderOptions) error {
		o.discovery = enabled
		return nil
	}
}

func WithDiscoveryFilter(accountIDs []string, partition string) KmsOptionFunc {
	return func(o *KmsProviderOptions) error {
		if len(accountIDs) == 0 {
			return fmt.Errorf("discovery filter accountIDs must not be empty")
		}
		if partition != _awsPartition {
			return fmt.Errorf("discovery filter partition %s is not supported", partition)
		}
		for _, accountID := range accountIDs {
			if accountID == "" {
				return fmt.Errorf("discovery filter accountID must not be empty")
			}
			if _, err := strconv.Atoi(accountID); err != nil {
				return fmt.Errorf("discovery filter accountID %q must contain only digits", accountID)
			}
		}
		filter := &discoveryFilter{accountIDs: accountIDs, partition: partition}
		o.discovery = true
		o.discoveryFilter = filter
		return nil
	}
}

type discoveryFilter struct {
	accountIDs []string
	partition  string
}

func (df *discoveryFilter) IsAllowed(keyID string) bool {
	keyArn, err := arn.ParseArn(keyID)
	if err != nil {
		return false
	}
	if keyArn.Partition != df.partition {
		return false
	}
	for _, accountID := range df.accountIDs {
		if keyArn.Account == accountID {
			return true
		}
	}
	return false
}
