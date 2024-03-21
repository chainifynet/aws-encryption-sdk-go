// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/arn"
)

// Options contains the configuration options for the [KmsKeyProvider].
type Options struct {
	awsConfigLoaders []func(options *config.LoadOptions) error
	clientFactory    model.KMSClientFactory
	defaultRegion    string
	discovery        bool
	discoveryFilter  *discoveryFilter
	mrkAware         bool
	discoveryRegion  string
	keyFactory       model.MasterKeyFactory
	keyProvider      model.BaseKeyProvider
}

// OptionsFunc is a function that applies an option to the [Options].
type OptionsFunc func(options *Options) error

// WithAwsLoadOptions sets the AWS configuration loaders for the KMS provider.
func WithAwsLoadOptions(optFns ...func(options *config.LoadOptions) error) OptionsFunc {
	return func(o *Options) error {
		o.awsConfigLoaders = optFns
		return nil
	}
}

// WithClientFactory sets the KMS client factory for the KMS provider.
func WithClientFactory(factory model.KMSClientFactory) OptionsFunc {
	return func(o *Options) error {
		o.clientFactory = factory
		return nil
	}
}

// WithDiscovery enables the discovery mode for the KMS provider.
func WithDiscovery() OptionsFunc {
	return func(o *Options) error {
		o.discovery = true
		return nil
	}
}

// WithDiscoveryFilter sets the discovery filter for the KMS provider, it also
// enables the discovery mode.
func WithDiscoveryFilter(accountIDs []string, partition string) OptionsFunc {
	return func(o *Options) error {
		filter := &discoveryFilter{accountIDs: accountIDs, partition: partition}
		o.discovery = true
		o.discoveryFilter = filter
		return nil
	}
}

// WithMrkAwareness enables the multi-region key awareness for the KMS provider.
func WithMrkAwareness() OptionsFunc {
	return func(o *Options) error {
		o.mrkAware = true
		return nil
	}
}

// WithDiscoveryRegion sets the discovery region for the KMS provider.
func WithDiscoveryRegion(region string) OptionsFunc {
	return func(o *Options) error {
		o.discoveryRegion = region
		return nil
	}
}

// WithKeyFactory sets the master key factory for the KMS provider.
func WithKeyFactory(keyFactory model.MasterKeyFactory) OptionsFunc {
	return func(o *Options) error {
		o.keyFactory = keyFactory
		return nil
	}
}

// WithKeyProvider sets the base key provider for the KMS provider.
func WithKeyProvider(keyProvider model.BaseKeyProvider) OptionsFunc {
	return func(o *Options) error {
		o.keyProvider = keyProvider
		return nil
	}
}

type discoveryFilter struct {
	accountIDs []string
	partition  string
}

func (df *discoveryFilter) isAllowed(keyID string) bool {
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
