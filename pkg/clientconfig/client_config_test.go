// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewConfig(t *testing.T) {
	defaultCfg, err := NewConfig()
	assert.NoError(t, err)

	assert.Equal(t, DefaultCommitment, defaultCfg.CommitmentPolicy())
	assert.Equal(t, DefaultMaxEDK, defaultCfg.MaxEncryptedDataKeys())
}

func TestNewConfigWithOpts(t *testing.T) {
	cfg, err := NewConfigWithOpts(
		WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptAllowDecrypt),
		WithMaxEncryptedDataKeys(255),
	)
	assert.NoError(t, err)

	assert.Equal(t, 255, cfg.MaxEncryptedDataKeys())
	assert.Equal(t, suite.CommitmentPolicyRequireEncryptAllowDecrypt, cfg.CommitmentPolicy())
}

func TestNewConfigWithOptsFaulty(t *testing.T) {
	cfg, err := NewConfigWithOpts(
		WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptAllowDecrypt),
		WithMaxEncryptedDataKeys(1000),
	)

	assert.Error(t, err)
	assert.Nil(t, cfg)

	cfg2, err2 := NewConfigWithOpts(
		WithCommitmentPolicy(-1),
		WithMaxEncryptedDataKeys(10),
	)

	assert.Error(t, err2)
	assert.Nil(t, cfg2)

	cfg3, err3 := NewConfigWithOpts(
		WithCommitmentPolicy(4),
		WithMaxEncryptedDataKeys(10),
	)

	assert.Error(t, err3)
	assert.Nil(t, cfg3)
}
