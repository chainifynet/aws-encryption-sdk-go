// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/arn"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// encrypts and then decrypts a string using MRK-aware KMS key provider
func main() {
	// MRK KMS key ARN to be used for encryption in first region
	kmsKeyID1 := getEnvVar("MRK_KEY_1_ARN", "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012")

	// MRK KMS key ARN to be used for encryption in second region
	kmsKeyID2 := getEnvVar("MRK_KEY_2_ARN", "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678-1234-1234-1234-123456789012")

	// for decryption the KeyID are discovered automatically by the SDK from the encrypted message

	// an encryption context to be associated with the encrypted data
	encryptionContext := map[string]string{
		"Year":     "2023",
		"username": "john",
		"Purpose":  "testing",
	}

	// data to encrypt
	secretData := []byte("secret mrk aware test data")

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

	// setup MRK-aware KMS key provider for encryption
	mrkKmsKeyProvider, err := kmsprovider.NewWithOpts(
		[]string{kmsKeyID1},            // KMS CMK ARNs to be used for encryption in first region
		kmsprovider.WithMrkAwareness(), // enable MRK-aware
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup crypto materials manager
	cmm, err := materials.NewDefault(mrkKmsKeyProvider)
	if err != nil {
		panic(err) // handle error
	}

	// encrypt data
	encrypted, header, err := sdkClient.Encrypt(context.TODO(), secretData, encryptionContext, cmm)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("encrypted data key count: %d\n", header.EncryptedDataKeyCount)
	fmt.Printf("encrypted encryption context: %v\n", header.AADData.AsEncryptionContext())

	// create a MRK-aware KMS key provider specifying KMS MRK keyID in second region
	mrkKmsProvider2, err := kmsprovider.NewWithOpts(
		[]string{kmsKeyID2},            // KMS CMK ARNs to be used for encryption in second region
		kmsprovider.WithMrkAwareness(), // enable MRK-aware
	)
	if err != nil {
		panic(err) // handle error
	}
	// create a CMM that uses the MRK-aware enabled provider in second region
	cmmMrk2, err := materials.NewDefault(mrkKmsProvider2)
	if err != nil {
		panic(err) // handle error
	}
	// decrypt the "encrypted" message using that "cmmMrk2" CMM
	decrypted, decHeader, err := sdkClient.Decrypt(context.TODO(), encrypted, cmmMrk2)
	if err != nil {
		panic(err) // handle error
	}

	// verify that "decrypted" encryption context in header has the same keys and values
	// as the original encryption context before using "decrypted" data.
	decryptionContext := decHeader.AADData.AsEncryptionContext()
	for k, v := range encryptionContext {
		if decryptionContext[k] != v {
			panic("decrypted encryption context does not match with the original encryption context")
		}
	}

	fmt.Printf("decrypted data using mrkKmsProvider2: %s\n", decrypted)

	// verify that "decrypted" plaintext is identical to the original secret data
	if string(decrypted) != string(secretData) {
		panic("decrypted data does not match with the original data")
	}

	// parse KMS keyID to get the ARN
	kmsKey2Arn, _ := arn.ParseArn(kmsKeyID2)

	// create MRK-aware Discovery KMS key provider specifying explicitly nil for keyIDs, with
	// discovery enabled filter by accountIDs and partition from second region
	// and specifying region for discovery to be second region
	mrkDiscoveryProvider, err := kmsprovider.NewWithOpts(
		nil,
		// enable discovery, and filter by accountIDs and partition from second region
		kmsprovider.WithDiscoveryFilter([]string{kmsKey2Arn.Account}, kmsKey2Arn.Partition),
		kmsprovider.WithMrkAwareness(),                     // enable MRK-aware
		kmsprovider.WithDiscoveryRegion(kmsKey2Arn.Region), // specify region for discovery
	)
	if err != nil {
		panic(err) // handle error
	}
	// create a CMM that only uses MRK-aware discovery filter enabled provider
	cmmDiscovery, err := materials.NewDefault(mrkDiscoveryProvider)
	if err != nil {
		panic(err) // handle error
	}
	// decrypt the "encrypted" message using that "cmmDiscovery" CMM
	decrypted2, decHeader2, err := sdkClient.Decrypt(context.TODO(), encrypted, cmmDiscovery)
	if err != nil {
		panic(err) // handle error
	}

	// verify that "decrypted2" encryption context in header has the same keys and values
	// as the original encryption context before using "decrypted2" data.
	decryptionContext2 := decHeader2.AADData.AsEncryptionContext()
	for k, v := range encryptionContext {
		if decryptionContext2[k] != v {
			panic("decrypted2 encryption context does not match with the original encryption context")
		}
	}

	fmt.Printf("decrypted data using mrkDiscoveryProvider: %s\n", decrypted2)

	// verify that "decrypted2" plaintext is identical to the original secret data
	if string(decrypted2) != string(secretData) {
		panic("decrypted2 data does not match with the original data")
	}
}
