// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import "strings"

// IsValidMrkArn checks if the given string can be a valid MRK ARN
//
// Spec: [aws-kms-key-arn]
//
// [aws-kms-key-arn]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/c35fbd91b28303d69813119088c44b5006395eb4/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn
func IsValidMrkArn(str string) (bool, error) {
	// This function MUST take a single AWS KMS ARN
	a, err := ParseArn(str)
	if err != nil {
		// If the input is an invalid AWS KMS ARN this function MUST error.
		return false, err
	}
	return a.IsMrk(), nil
}

// IsValidMrkIdentifier checks if the given string can be a valid MRK identifier
//
// Spec: [aws-kms-key-arn]
//
// [aws-kms-key-arn]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/c35fbd91b28303d69813119088c44b5006395eb4/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-identifier
func IsValidMrkIdentifier(str string) (bool, error) {
	// This function MUST take a single AWS KMS identifier
	switch {
	case strings.HasPrefix(str, arnPrefix):
		// If the input starts with "arn:", this MUST return the output of
		// identifying an AWS KMS multi-Region ARN called with this input.
		return IsValidMrkArn(str)
	case strings.HasPrefix(str, aliasResourceType+"/"):
		// If the input starts with "alias/", this an AWS KMS alias and not a
		// multi-Region key id and MUST return "false".
		return false, nil
	case strings.HasPrefix(str, mrkPrefix):
		// If the input starts with "mrk-", this is a multi-Region key id
		// and MUST return "true".
		return false, nil // bare keys are not supported yet
		//return true, nil
	default:
		// If the input does not start with any of the above, this is not a
		// multi-Region key id and MUST return "false".
		return false, nil
	}
}

// IsMrkArnEqual compares two MRK ARNs
//
// Spec: [aws-kms-mrk-match-for-decrypt]
//
// Given two KMS key arns, determines whether they refer to related KMS MRKs.
//
// [aws-kms-mrk-match-for-decrypt]: https://github.com/awslabs/aws-encryption-sdk-specification/blob/c35fbd91b28303d69813119088c44b5006395eb4/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation
func IsMrkArnEqual(key1, key2 string) bool {
	if key1 == key2 {
		// If both identifiers are identical, this function MUST return "true".
		return true
	}
	arn1, err := ParseArn(key1)
	if err != nil {
		return false
	}
	arn2, err := ParseArn(key2)
	if err != nil {
		return false
	}
	if !arn1.IsMrk() || !arn2.IsMrk() {
		// Otherwise if either input is not identified as a multi-Region key
		// https://github.com/awslabs/aws-encryption-sdk-specification/blob/c35fbd91b28303d69813119088c44b5006395eb4/framework/aws-kms/aws-kms-key-arn.md#identifying-an-an-aws-kms-multi-region-arn
		// then this function MUST return "false".
		return false
	}
	// Otherwise if both inputs are identified as a multi-Region keys,
	// this function MUST return the result of comparing the "partition",
	// "service", "accountId", "resourceType", and "resource" parts of both ARN inputs.
	return arn1.Partition == arn2.Partition &&
		arn1.Service == arn2.Service &&
		arn1.Account == arn2.Account &&
		arn1.ResourceType == arn2.ResourceType &&
		arn1.ResourceID == arn2.ResourceID
}
