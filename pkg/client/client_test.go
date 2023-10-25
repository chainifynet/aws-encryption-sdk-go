// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
)

func Test_NewClient(t *testing.T) {
	cl1 := client.NewClient()
	assert.NotNil(t, cl1)
}

func Test_NewClientWithConfig(t *testing.T) {
	cfg, _ := clientconfig.NewConfig()

	cl1 := client.NewClientWithConfig(cfg)
	cl2 := client.NewClientWithConfig(cfg)
	assert.NotNil(t, cl1)
	assert.NotNil(t, cl2)
	assert.NotSame(t, cl1, cl2)
	assert.NotSame(t, *cl1, *cl2)
	assert.Equal(t, fmt.Sprintf("%v", cl1), fmt.Sprintf("%v", cl2))
}
