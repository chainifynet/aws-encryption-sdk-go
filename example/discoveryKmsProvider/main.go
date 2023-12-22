// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// encrypts and then decrypts a string using KMS key provider with discovery enabled mode
func main() {
	// KMS key ARN to be used for encryption
	// for decryption the KeyID are discovered automatically by the SDK from the encrypted message
	kmsKeyID := getEnvVar("KEY_1_ARN", "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")

	// an encryption context to be associated with the encrypted data
	encryptionContext := map[string]string{
		"Year":     "2023",
		"username": "john",
		"Purpose":  "testing",
	}

	// data to encrypt
	secretData := []byte("secret discovery test data you want to protect")

	// setup SDK client config with an explicit commitment policy and maximum number of
	// allowed encrypted data keys
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
		clientconfig.WithMaxEncryptedDataKeys(2),
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup Encryption SDK client with a custom config
	sdkClient := client.NewClientWithConfig(cfg)

	// setup KMS key provider
	kmsKeyProvider, err := kmsprovider.New(kmsKeyID)
	if err != nil {
		panic(err) // handle error
	}

	// setup crypto materials manager
	cmm, err := materials.NewDefault(kmsKeyProvider)
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

	// create a KMS key provider specifying explicitly nil for keyIDs, and enable discovery
	provider, err := kmsprovider.NewWithOpts(
		nil,
		kmsprovider.WithDiscovery(), // enable discovery
		kmsprovider.WithAwsLoadOptions(
			config.WithDefaultRegion("us-east-2"),
		),
	)
	if err != nil {
		panic(err) // handle error
	}
	// create a CMM that only uses the discovery enabled provider
	cmmDiscovery, err := materials.NewDefault(provider)
	if err != nil {
		panic(err) // handle error
	}
	// decrypt the "encrypted" message using that "cmmDiscovery" CMM
	decrypted, decHeader, err := sdkClient.Decrypt(context.TODO(), encrypted, cmmDiscovery)
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

	fmt.Printf("decrypted data: %s\n", decrypted)

	// verify that "decrypted" plaintext is identical to the original secret data
	if string(decrypted) != string(secretData) {
		panic("decrypted data does not match with the original data")
	}
}
