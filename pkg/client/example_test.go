// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func ExampleNewClient() {
	var c = client.NewClient()
	fmt.Printf("%#v", *c)
	// Output: client.Client{config:clientconfig.ClientConfig{commitmentPolicy:2, maxEncryptedDataKeys:10}}
}

func ExampleNewClientWithConfig() {
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
		clientconfig.WithMaxEncryptedDataKeys(2),
	)
	if err != nil {
		panic(err)
	}
	var c = client.NewClientWithConfig(cfg)
	fmt.Printf("%#v", *c)
	// Output: client.Client{config:clientconfig.ClientConfig{commitmentPolicy:2, maxEncryptedDataKeys:2}}
}
