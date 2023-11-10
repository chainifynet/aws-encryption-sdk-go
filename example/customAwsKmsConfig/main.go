// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func main() {
	// KMS key ARN to be used for encryption and decryption
	kmsKeyID := getEnvVar("KEY_1_ARN", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")

	// create an encryption context
	encryptionContext := map[string]string{
		"Year":    "2023",
		"User":    "Alice",
		"Purpose": "testing",
	}

	// data to encrypt
	secretData := []byte("super secret data to encrypt")

	// setup Encryption SDK client with default configuration
	sdkClient := client.NewClient()

	// setup KMS key provider with custom AWS Config options
	kmsKeyProvider, err := providers.NewKmsKeyProviderWithOpts(
		[]string{kmsKeyID},
		providers.WithAwsLoadOptions(
			// config.WithSharedConfigProfile("your_profile_name"),
			config.WithDefaultRegion("us-east-2"),
			config.WithRetryMaxAttempts(5),
			// add more AWS Config options if needed
		),
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup crypto materials manager
	cmm, err := materials.NewDefault(kmsKeyProvider)
	if err != nil {
		panic(err) // handle error
	}

	// encrypt data with custom frame length and signing algorithm
	encrypted, header, err := sdkClient.Encrypt(context.TODO(), secretData, encryptionContext, cmm,
		client.WithFrameLength(2048), // use custom 2048 byte frame length for encryption
		client.WithAlgorithm(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384), // algorithm with signing
	)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("header AlgorithmSuite: %s\n", header.AlgorithmSuite.String())
	// Output: header AlgorithmSuite: AlgID 0x0578: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384

	fmt.Printf("header frameLength: %d\n", header.FrameLength)
	// Output: header frameLength: 2048

	fmt.Printf("encrypted data key count: %d\n", header.EncryptedDataKeyCount)
	// Output: encrypted data key count: 1

	fmt.Printf("encrypted encryption context: %v\n", header.AADData.AsEncryptionContext())

	// decrypt "encrypted" data
	decrypted, _, err := sdkClient.Decrypt(context.TODO(), encrypted, cmm)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("decrypted data: %s\n", decrypted)
	// Output: decrypted data: super secret data to encrypt

	// verify that "decrypted" plaintext is identical to the original secret data
	if string(decrypted) != string(secretData) {
		panic("decrypted data does not match with the original data")
	}
}
