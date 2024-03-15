// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package kmsprovider contains KMS Master Key Provider implementation.
//
// Example [DiscoveryKmsProvider] in discovery mode:
//
//	kmsProvider, err := kmsprovider.New()
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [StrictKmsProvider] in strict mode:
//
//	keyID := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	kmsProvider, err := kmsprovider.New(keyID)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [StrictKmsProvider] with custom AWS config:
//
//	keyID := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    []string{keyID},
//	    kmsprovider.WithAwsLoadOptions(
//	        // add more AWS Config options if needed
//	        config.WithSharedConfigProfile("your_profile_name"),
//	        config.WithRegion("us-west-2"),
//	    ),
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [MrkAwareStrictKmsProvider]:
//
//	keyID := "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011"
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    []string{keyID},                // KMS CMK ARNs
//	    kmsprovider.WithMrkAwareness(), // enable MRK-aware
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [DiscoveryKmsProvider] with discovery filter:
//
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    nil,
//	    // enable discovery, and filter by accountIDs and partition
//	    kmsprovider.WithDiscoveryFilter([]string{"123456789011"}, "aws"),
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// Example [MrkAwareDiscoveryKmsProvider] with discovery region and filter:
//
//	kmsProvider, err := kmsprovider.NewWithOpts(
//	    nil,
//	    // enable discovery, and filter by accountIDs and partition
//	    kmsprovider.WithDiscoveryFilter([]string{"123456789011"}, "aws"),
//	    kmsprovider.WithMrkAwareness(),               // enable MRK-aware
//	    kmsprovider.WithDiscoveryRegion("us-west-2"), // specify region for discovery
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// See [examples] for more detailed usage.
//
// [examples]: https://github.com/chainifynet/aws-encryption-sdk-go/tree/main/example
package kmsprovider
