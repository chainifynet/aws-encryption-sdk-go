// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package rawprovider contains Raw Master Key Provider implementation.
//
// See usage below or check [examples] for more detailed use.
//
// Example configuration:
//
//	// static key to use for encryption and decryption
//	staticKey1 := []byte("superSecureKeySecureKey32bytes32")
//	rawProvider, err := rawprovider.NewWithOpts(
//	    "raw",
//	    rawprovider.WithStaticKey("static1", staticKey1),
//	)
//	if err != nil {
//	    panic(err) // handle error
//	}
//
// [examples]: https://github.com/chainifynet/aws-encryption-sdk-go/tree/main/example
package rawprovider
