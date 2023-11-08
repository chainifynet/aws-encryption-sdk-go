// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

const (
	_kmsProviderID      = "aws-kms"
	_awsPartition       = "aws"
	_awsRegionMinLength = 9  // min length of AWS region name (e.g. "us-east-1")
	_rawMinKeyLength    = 32 // min length of raw key (e.g. 256 bits)
)

type ProviderType int8

const (
	_noneProvider ProviderType = iota // 0 is NONE
	AwsKms                            // 1 is AWS_KMS key provider
	Raw                               // 2 is RAW key provider
)

func (p ProviderType) String() string {
	switch p {
	case _noneProvider:
		return "NONE"
	case AwsKms:
		return "AWS_KMS"
	case Raw:
		return "RAW"
	default:
		return "NONE"
	}
}

func (p ProviderType) GoString() string {
	return p.String()
}
