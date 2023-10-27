// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main_test

import (
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	u "github.com/chainifynet/aws-encryption-sdk-go/test/e2e/testutils"
)

type testFile struct {
	Name string
	data []byte
}

var testAwsLoadOptions = []func(options *config.LoadOptions) error{
	config.WithRegion("us-east-1"),
}

var (
	algNoSig = suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY
	algSig   = suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
)

var testEc = map[string]string{
	"keyId":  "4a5c8ebf-f7d0-4d09-88c3-5edb48539163",
	"orgId":  "org-uuid-test",
	"someId": "someId-uuid-test",
	"abcKey": "abcValue",
}

var (
	cmm123keys = u.SetupCMM([]string{key1Arn, key2Arn, key3Arn}, testAwsLoadOptions...)
	cmm1keys   = u.SetupCMM([]string{key1Arn}, testAwsLoadOptions...)
	cmm1keys2  = u.SetupCMM([]string{key2Arn}, testAwsLoadOptions...)
	cmm1keys3  = u.SetupCMM([]string{key3Arn}, testAwsLoadOptions...)
	cmm2keys23 = u.SetupCMM([]string{key2Arn, key3Arn}, testAwsLoadOptions...)
	cmm0keys   = u.SetupCMM(nil, testAwsLoadOptions...)
)
