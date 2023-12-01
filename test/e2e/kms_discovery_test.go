// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/arn"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
)

func Test_Integration_KmsDiscovery(t *testing.T) {
	setupGroupTest(t)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()

	provider1, err := kmsprovider.New(key1Arn)
	require.NoError(t, err)
	assert.NotNil(t, provider1)

	decryptMk2, err := provider1.MasterKeyForDecrypt(ctx, model.WithKeyMeta("aws-kms", key2Arn))
	require.NoError(t, err)
	assert.NotNil(t, decryptMk2)

	decryptMk1, err := provider1.MasterKeyForDecrypt(ctx, model.WithKeyMeta("aws-kms", key1Arn))
	require.NoError(t, err)
	assert.NotNil(t, decryptMk1)

	provider2, err := kmsprovider.NewWithOpts(
		nil,
		kmsprovider.WithAwsLoadOptions(testAwsLoadOptions...),
		kmsprovider.WithDiscovery(),
	)
	require.NoError(t, err)
	assert.NotNil(t, provider2)

	decryptP2Mk1, err := provider2.MasterKeyForDecrypt(ctx, model.WithKeyMeta("aws-kms", key1Arn))
	require.NoError(t, err)
	assert.NotNil(t, decryptP2Mk1)

	decryptP2Mk3, err := provider2.MasterKeyForDecrypt(ctx, model.WithKeyMeta("aws-kms", key3Arn))
	require.NoError(t, err)
	assert.NotNil(t, decryptP2Mk3)

	arnKey3, err := arn.ParseArn(key3Arn)
	require.NoError(t, err)
	assert.NotNil(t, arnKey3)

	provider3, err := kmsprovider.NewWithOpts(
		nil,
		kmsprovider.WithAwsLoadOptions(testAwsLoadOptions...),
		kmsprovider.WithDiscoveryFilter([]string{arnKey3.Account}, "aws"),
	)
	require.NoError(t, err)
	assert.NotNil(t, provider3)

	decryptP3Mk1, err := provider3.MasterKeyForDecrypt(ctx, model.WithKeyMeta("aws-kms", key1Arn))
	require.NoError(t, err)
	assert.NotNil(t, decryptP3Mk1)

	decryptP3MkOtherAccount, err := provider3.MasterKeyForDecrypt(ctx, model.WithKeyMeta("aws-kms", "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320"))
	require.Error(t, err)
	assert.Nil(t, decryptP3MkOtherAccount)
}
