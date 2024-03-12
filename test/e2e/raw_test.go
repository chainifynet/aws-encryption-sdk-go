// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/rawprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/test/e2e/logger"
)

func Test_Integration_StaticKeysEncrypt(t *testing.T) {
	ctx := context.Background()

	// setup client config
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
		clientconfig.WithMaxEncryptedDataKeys(2),
	)
	require.NoError(t, err)

	// setup SDK client
	c := client.NewClientWithConfig(cfg)
	require.NotNil(t, c)

	// setup raw key provider
	rawKeyProvider, err := rawprovider.NewWithOpts(
		"raw",
		rawprovider.WithStaticKey("static1", staticKey1),
		rawprovider.WithStaticKey("static2", staticKey2),
	)
	require.NoError(t, err)
	assert.NotNil(t, rawKeyProvider)

	// setup crypto materials manager
	cmm, err := materials.NewDefault(rawKeyProvider)
	require.NoError(t, err)
	assert.NotNil(t, cmm)

	log.Debug().Str("bytes", logger.FmtBytes(random32kb)).Msg("Input")

	// encrypt data
	ciphertext1, header1, err := c.Encrypt(ctx, random32kb, testEc, cmm,
		client.WithAlgorithm(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384),
		client.WithFrameLength(4096),
	)
	require.NoError(t, err)
	assert.NotNil(t, ciphertext1)
	assert.NotNil(t, header1)
	log.Debug().Str("bytes", logger.FmtBytes(ciphertext1)).Msg("ciphertext1")

	// decrypt ciphertext
	plaintext1, header1Dec, err := c.Decrypt(ctx, ciphertext1, cmm)
	require.NoError(t, err)
	assert.NotNil(t, plaintext1)
	assert.NotNil(t, header1Dec)
	log.Debug().Str("bytes", logger.FmtBytes(plaintext1)).Msg("plaintext1")
	require.Equal(t, random32kb, plaintext1)
}

func Test_Integration_StaticKeysDecrypt(t *testing.T) {
	ctx := context.Background()

	// setup client config
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
		clientconfig.WithMaxEncryptedDataKeys(2),
	)
	require.NoError(t, err)

	// setup SDK client
	c := client.NewClientWithConfig(cfg)
	require.NotNil(t, c)

	// setup raw key provider with only static key 1
	rawKeyProvider1, err := rawprovider.NewWithOpts(
		"raw",
		rawprovider.WithStaticKey("static1", staticKey1),
	)
	require.NoError(t, err)
	assert.NotNil(t, rawKeyProvider1)

	// setup raw key provider with only static key 2
	rawKeyProvider2, err := rawprovider.NewWithOpts(
		"raw",
		rawprovider.WithStaticKey("static2", staticKey2),
	)
	require.NoError(t, err)
	assert.NotNil(t, rawKeyProvider2)

	// setup crypto materials manager using raw key provider 1
	cmm1, err := materials.NewDefault(rawKeyProvider1)
	require.NoError(t, err)
	assert.NotNil(t, cmm1)

	// setup crypto materials manager using raw key provider 2
	cmm2, err := materials.NewDefault(rawKeyProvider2)
	require.NoError(t, err)
	assert.NotNil(t, cmm1)

	log.Debug().Str("bytes", logger.FmtBytes(random32kbEncryptedStatic)).Msg("Input")

	// decrypt ciphertext using raw key provider 1 (only with static key 1)
	plaintext1, header1Dec, err := c.Decrypt(ctx, random32kbEncryptedStatic, cmm1)
	require.NoError(t, err)
	assert.NotNil(t, plaintext1)
	assert.NotNil(t, header1Dec)
	log.Debug().Str("bytes", logger.FmtBytes(plaintext1)).Msg("plaintext1")

	// decrypt ciphertext using raw key provider 2 (only with static key 2)
	plaintext2, header2Dec, err := c.Decrypt(ctx, random32kbEncryptedStatic, cmm2)
	require.NoError(t, err)
	assert.NotNil(t, plaintext2)
	assert.NotNil(t, header2Dec)
	log.Debug().Str("bytes", logger.FmtBytes(plaintext2)).Msg("plaintext2")

	// assert plaintexts
	assert.Equal(t, random32kb, plaintext1)
	assert.Equal(t, random32kb, plaintext2)
	assert.Equal(t, plaintext1, plaintext2)

	// setup raw key provider with same providerID (it must match) and other keyID, static key 2
	rawKeyProvider3, err := rawprovider.NewWithOpts(
		"raw",
		rawprovider.WithStaticKey("static2", staticKey2),
	)
	require.NoError(t, err)
	assert.NotNil(t, rawKeyProvider3)

	// setup crypto materials manager using raw key provider 3
	cmm3, err := materials.NewDefault(rawKeyProvider3)
	require.NoError(t, err)
	assert.NotNil(t, cmm3)

	// decrypt ciphertext using raw key provider 3
	plaintext3, header3Dec, err := c.Decrypt(ctx, random32kbEncryptedStatic, cmm3)
	require.NoError(t, err)
	assert.NotNil(t, plaintext3)
	assert.NotNil(t, header3Dec)
	log.Debug().Str("bytes", logger.FmtBytes(plaintext2)).Msg("plaintext3")

	// assert plaintexts
	assert.Equal(t, random32kb, plaintext3)
}
