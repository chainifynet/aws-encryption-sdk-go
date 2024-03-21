// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This example demonstrates how to use the AWS Encryption SDK for Go with a
// custom key provider.
//
// # Don't use this implementation in production
//
// [myprovider.MyProvider] and underlying mykey.MyKey implementations using
// base64 encoding for demonstration purposes only.
package main

import (
	"context"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go-tests/example/customKeyProvider/myprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
)

func main() {
	// KeyIDs to use for encryption and decryption
	keyID1 := "myKey1"
	keyID2 := "myKey2"

	keyIDs := []string{keyID1, keyID2}

	// an encryption context to be associated with the encrypted data
	encryptionContext := map[string]string{
		"Year":    "2023",
		"User":    "Alice",
		"Purpose": "testing",
	}

	// data to encrypt
	secretData := []byte("secret data to encrypt")

	// setup Encryption SDK client with default configuration
	sdkClient := client.NewClient()

	// setup Custom Key provider
	keyProvider, err := myprovider.NewMyProvider("myProviderID", keyIDs...)
	if err != nil {
		panic(err) // handle error
	}

	// setup crypto materials manager
	cmm, err := materials.NewDefault(keyProvider)
	if err != nil {
		panic(err) // handle error
	}

	// Warning: This example is for demonstration purposes only.
	// Do not use myprovider.MyProvider to encrypt data in production.

	// encrypt the secret data:
	encrypted, header, err := sdkClient.Encrypt(context.TODO(), secretData, encryptionContext, cmm)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("encrypted data key count: %d\n", header.EncryptedDataKeyCount())
	fmt.Printf("encrypted encryption context: %v\n", header.AADData().EncryptionContext())

	// for each original master key, create a Custom Key Provider that only lists
	// that key, and use that provider to create corresponding CMM, and then decrypt
	// the "encrypted" message using that CMM.
	for i, keyID := range keyIDs {
		// create a Custom Key Provider that only lists the current key
		provider, err := myprovider.NewMyProvider("myProviderID", keyID)
		if err != nil {
			panic(err) // handle error
		}
		// create a CMM that only uses the provider with the current key
		cmmWithOneKey, err := materials.NewDefault(provider)
		if err != nil {
			panic(err) // handle error
		}
		// decrypt the "encrypted" message using the CMM with the current key
		decrypted, decHeader, err := sdkClient.Decrypt(context.TODO(), encrypted, cmmWithOneKey)
		if err != nil {
			panic(err) // handle error
		}

		// verify that "decrypted" encryption context in header has the same keys and values
		// as the original encryption context before using "decrypted" data.
		decryptionContext := decHeader.AADData().EncryptionContext()
		for k, v := range encryptionContext {
			if decryptionContext[k] != v {
				panic("decrypted encryption context does not match with the original encryption context")
			}
		}

		fmt.Printf("decrypted data using key %d: %s\n", i+1, decrypted)

		// verify that "decrypted" plaintext is identical to the original secret data
		if string(decrypted) != string(secretData) {
			panic("decrypted data does not match with the original data")
		}
	}
}
