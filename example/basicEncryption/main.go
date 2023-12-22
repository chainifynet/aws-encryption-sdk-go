// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/rawprovider"
)

func main() {
	// static key to use for encryption and decryption
	staticKey1 := []byte("superSecureKeySecureKey32bytes32")

	// data to encrypt
	secretData := []byte("secret data to encrypt")

	// setup Encryption SDK client with default configuration
	sdkClient := client.NewClient()

	// setup Raw Key provider
	rawKeyProvider, err := rawprovider.NewWithOpts(
		"raw",
		rawprovider.WithStaticKey("static1", staticKey1),
	)
	if err != nil {
		panic(err) // handle error
	}

	// setup crypto materials manager
	cmm, err := materials.NewDefault(rawKeyProvider)
	if err != nil {
		panic(err) // handle error
	}

	// encrypt data without encryption context passing nil as the third argument
	encrypted, header, err := sdkClient.Encrypt(context.TODO(), secretData, nil, cmm)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("encrypted encryption context: %v\n", header.AADData().EncryptionContext())

	// decrypt "encrypted" data
	decrypted, _, err := sdkClient.Decrypt(context.TODO(), encrypted, cmm)
	if err != nil {
		panic(err) // handle error
	}

	fmt.Printf("decrypted data: %s\n", decrypted)

	// verify that "decrypted" plaintext is identical to the original secret data
	if string(decrypted) != string(secretData) {
		panic("decrypted data does not match with the original data")
	}
}
