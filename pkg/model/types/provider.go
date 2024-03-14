// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package types

const (
	// KmsProviderID is the ID of the AWS KMS key provider.
	KmsProviderID = "aws-kms"
)

// ProviderKind represents the kind of key provider.
type ProviderKind int8

const (
	_noneProvider ProviderKind = iota // 0 is NONE
	AwsKms                            // 1 is AWS_KMS key provider
	Raw                               // 2 is RAW key provider
)

func (p ProviderKind) String() string {
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

func (p ProviderKind) GoString() string {
	return p.String()
}
