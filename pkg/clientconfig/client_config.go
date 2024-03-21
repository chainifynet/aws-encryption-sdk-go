// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import (
	"fmt"
	"math"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// ConfigOptions is a holder of the configuration options for the client.
type ConfigOptions struct {
	// CommitmentPolicy is the commitment policy for the client.
	CommitmentPolicy suite.CommitmentPolicy

	// MaxEncryptedDataKeys is the maximum number of encrypted data keys that can be used in a single message.
	MaxEncryptedDataKeys int
}

// ConfigOptionFunc is a function that sets a configuration option.
type ConfigOptionFunc func(o *ConfigOptions) error

// ClientConfig is the configuration for the client.
type ClientConfig struct {
	commitmentPolicy     suite.CommitmentPolicy
	maxEncryptedDataKeys int
}

// CommitmentPolicy returns the commitment policy for the client.
func (c ClientConfig) CommitmentPolicy() suite.CommitmentPolicy {
	return c.commitmentPolicy
}

// MaxEncryptedDataKeys returns the maximum number of encrypted data keys that can be used in a single message.
func (c ClientConfig) MaxEncryptedDataKeys() int {
	return c.maxEncryptedDataKeys
}

// NewConfig returns a new client configuration with the default options.
func NewConfig() (*ClientConfig, error) {
	return NewConfigWithOpts()
}

// NewConfigWithOpts returns a new client configuration with the provided options.
// The options are passed as [ConfigOptionFunc] functions, which modify the [ConfigOptions] struct.
//
// The default values for the configuration options are as follows:
//   - CommitmentPolicy: [DefaultCommitment]
//   - MaxEncryptedDataKeys: [DefaultMaxEDK]
//
// Example usage:
//
//	cfg, err := NewConfigWithOpts(
//		WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptAllowDecrypt),
//		WithMaxEncryptedDataKeys(5),
//	)
func NewConfigWithOpts(optFns ...ConfigOptionFunc) (*ClientConfig, error) {
	opts := ConfigOptions{
		CommitmentPolicy:     DefaultCommitment,
		MaxEncryptedDataKeys: DefaultMaxEDK,
	}
	for _, optFn := range optFns {
		if err := optFn(&opts); err != nil {
			return nil, err
		}
	}
	return &ClientConfig{
		commitmentPolicy:     opts.CommitmentPolicy,
		maxEncryptedDataKeys: opts.MaxEncryptedDataKeys,
	}, nil
}

// WithCommitmentPolicy returns a [ConfigOptionFunc] that sets the commitment policy for the client.
func WithCommitmentPolicy(policy suite.CommitmentPolicy) ConfigOptionFunc {
	return func(o *ConfigOptions) error {
		if err := suite.ValidateCommitmentPolicy(policy); err != nil {
			return err
		}
		o.CommitmentPolicy = policy
		return nil
	}
}

// WithMaxEncryptedDataKeys returns a [ConfigOptionFunc] that sets the maximum
// number of encrypted data keys that can be used in a single message.
func WithMaxEncryptedDataKeys(maxEncryptedDataKeys int) ConfigOptionFunc {
	return func(o *ConfigOptions) error {
		if maxEncryptedDataKeys > math.MaxUint8 {
			return fmt.Errorf("maxEncryptedDataKeys must be less than %v", math.MaxUint8)
		}
		o.MaxEncryptedDataKeys = maxEncryptedDataKeys
		return nil
	}
}
