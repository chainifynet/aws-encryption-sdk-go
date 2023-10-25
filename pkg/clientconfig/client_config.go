// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import (
	"fmt"
	"math"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type ConfigOptions struct {
	CommitmentPolicy     suite.CommitmentPolicy
	MaxEncryptedDataKeys int
}

type ConfigOptionFunc func(o *ConfigOptions) error

type ClientConfig struct {
	commitmentPolicy     suite.CommitmentPolicy
	maxEncryptedDataKeys int
}

func (c ClientConfig) CommitmentPolicy() suite.CommitmentPolicy {
	return c.commitmentPolicy
}

func (c ClientConfig) MaxEncryptedDataKeys() int {
	return c.maxEncryptedDataKeys
}

func NewConfig() (*ClientConfig, error) {
	return NewConfigWithOpts()
}

func NewConfigWithOpts(optFns ...ConfigOptionFunc) (*ClientConfig, error) {
	opts := ConfigOptions{
		CommitmentPolicy:     defaultCommitment,
		MaxEncryptedDataKeys: defaultMaxEDK,
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

func WithCommitmentPolicy(policy suite.CommitmentPolicy) ConfigOptionFunc {
	return func(o *ConfigOptions) error {
		if policy < suite.CommitmentPolicyForbidEncryptAllowDecrypt || policy > suite.CommitmentPolicyRequireEncryptRequireDecrypt {
			return fmt.Errorf("CommitmentPolicy not allowed")
		}
		o.CommitmentPolicy = policy
		return nil
	}
}

func WithMaxEncryptedDataKeys(maxEncryptedDataKeys int) ConfigOptionFunc {
	return func(o *ConfigOptions) error {
		if maxEncryptedDataKeys > math.MaxUint8 {
			return fmt.Errorf("maxEncryptedDataKeys must be less than %v", math.MaxUint8)
		}
		o.MaxEncryptedDataKeys = maxEncryptedDataKeys
		return nil
	}
}
