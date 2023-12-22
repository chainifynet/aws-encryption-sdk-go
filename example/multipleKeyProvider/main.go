// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/rawprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// encrypts and then decrypts a string under two Master Key Providers.
func main() {
	// KMS key ARNs to be used for encryption and decryption
	kmsKeyID1 := getEnvVar("KEY_1_ARN", "arn:aws:kms:us-east-1:123456789011:key/12345678-1234-1234-1234-123456789011")
	kmsKeyID2 := getEnvVar("KEY_2_ARN", "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012")

	keyArns := []string{
		kmsKeyID1,
		kmsKeyID2,
	}

	// static key to use for encryption and decryption
	staticKey1 := []byte("superSecureKeySecureKey32bytes32")

	// an encryption context to be associated with the encrypted data
	encryptionContext := map[string]string{
		"Year":    "2023",
		"User":    "Alice",
		"Purpose": "testing",
	}

	// data to encrypt
	secretData := []byte("super secret data you want to protect")

	// setup SDK client config with an explicit commitment policy and maximum number of
	// allowed encrypted data keys
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
		clientconfig.WithMaxEncryptedDataKeys(3),
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup Encryption SDK client with a custom config
	sdkClient := client.NewClientWithConfig(cfg)

	// setup KMS key provider with two KMS CMK keys
	kmsKeyProvider, err := kmsprovider.NewWithOpts(
		keyArns, // KMS CMK ARNs
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup Raw Key provider
	rawKeyProvider, err := rawprovider.NewWithOpts(
		"mynamespace",
		rawprovider.WithStaticKey("key1", staticKey1),
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup crypto materials manager with KMS and Raw Key providers.
	// the KMS provider will be used to generate the data key, e.g. "generator" in terms of Keyring.
	cmm, err := materials.NewDefault(kmsKeyProvider, rawKeyProvider)
	if err != nil {
		panic(err) // handle error
	}

	// encrypt data
	encrypted, header, err := sdkClient.Encrypt(context.TODO(), secretData, encryptionContext, cmm)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("encrypted data key count: %d\n", header.EncryptedDataKeyCount())
	fmt.Printf("encrypted encryption context: %v\n", header.AADData().EncryptionContext())

	// for each original master key, create a KMS key provider that only lists
	// that key, and use that provider to create corresponding CMM, and then
	// decrypt the "encrypted" message using that CMM.
	for i, keyID := range keyArns {
		// create a KMS key provider that only lists the current key
		provider, err := kmsprovider.New(keyID)
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

		fmt.Printf("decrypted data using KMS key %d: %s\n", i+1, decrypted)

		// verify that "decrypted" plaintext is identical to the original secret data
		if string(decrypted) != string(secretData) {
			panic("decrypted data does not match with the original data")
		}
	}

	// repeat the same process with a raw key provider and static key 1.
	// decrypt the "encrypted" message using that CMM.

	// create a Raw key provider that only lists static key 1
	rawProvider, err := rawprovider.NewWithOpts(
		"mynamespace", // namespace must match the one used to encrypt
		rawprovider.WithStaticKey("key1", staticKey1),
	)
	if err != nil {
		panic(err) // handle error
	}
	// create a CMM that only uses the provider with the static key 1
	cmmWithRawKey, err := materials.NewDefault(rawProvider)
	if err != nil {
		panic(err) // handle error
	}
	// decrypt the "encrypted" message using that CMM
	decrypted, decHeader, err := sdkClient.Decrypt(context.TODO(), encrypted, cmmWithRawKey)
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

	fmt.Printf("decrypted data using raw static key 1: %s\n", decrypted)

	// verify that "decrypted" plaintext is identical to the original secret data
	if string(decrypted) != string(secretData) {
		panic("decrypted data does not match with the original data")
	}
}
