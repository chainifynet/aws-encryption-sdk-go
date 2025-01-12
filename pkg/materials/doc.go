// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package materials provides CryptoMaterialsManager implementations.
//
// The cryptographic materials manager (CMM) assembles the cryptographic
// materials that are used to encrypt and decrypt data.
//
// # Supported Cryptographic Materials Managers
//
//   - [DefaultCryptoMaterialsManager]: A default interacts with your Master Key
//     Providers without any caching.
//   - [CachingCryptoMaterialsManager]: A caching CMM that uses a cache to store
//     cryptographic materials.
//
// # Usage
//
// The following example demonstrates how to use the [DefaultCryptoMaterialsManager].
//
//	 // Set up your key provider.
//	 cmm, err := materials.NewDefault(keyProvider)
//	 if err != nil {
//		  panic("materials manager setup failed") // handle error
//	 }
//
// Use of [CachingCryptoMaterialsManager] example.
//
//	cache, err := cache.NewMemoryCache(10)
//	if err != nil {
//	    // handle error
//	}
//	cachingManager, err := NewCaching(cache, provider)
//
// Check [example] for more advanced usage.
//
// [example]: https://github.com/chainifynet/aws-encryption-sdk-go/blob/main/example/multipleKeyProvider/main.go
package materials
