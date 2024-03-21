// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

const (
	_awsPartition       = "aws"
	_awsRegionMinLength = 9  // min length of AWS region name (e.g. "us-east-1")
	_awsAccountIDLength = 12 // length of AWS account ID (e.g. "123456789012")
)

// ProviderType represents the type of KMS Provider.
type ProviderType int

const (
	StrictKmsProvider            ProviderType = iota // Default Strict KMS Provider
	MrkAwareStrictKmsProvider                        // MRK-Aware Strict KMS Provider
	DiscoveryKmsProvider                             // Discovery-Enabled KMS Provider
	MrkAwareDiscoveryKmsProvider                     // MRK-Aware Discovery-Enabled KMS Provider
)

// String returns the string representation of the KMS Provider type.
func (k ProviderType) String() string {
	switch k {
	case StrictKmsProvider:
		return "StrictKmsProvider"
	case MrkAwareStrictKmsProvider:
		return "MrkAwareStrictKmsProvider"
	case DiscoveryKmsProvider:
		return "DiscoveryKmsProvider"
	case MrkAwareDiscoveryKmsProvider:
		return "MrkAwareDiscoveryKmsProvider"
	default:
		return "UnknownKmsProvider"
	}
}
