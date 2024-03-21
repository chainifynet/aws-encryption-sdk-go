// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package structs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapSort(t *testing.T) {
	stringMap := map[string]string{
		"test": "testkey",
		"org":  "orgkey",
		"abc":  "abckey",
		"aws":  "awskey",
	}
	mStringSorted := MapSort(stringMap)

	assert.Len(t, stringMap, len(mStringSorted))

	for k, v := range mStringSorted {
		fmt.Printf("key: %s, value: %s\n", k, v)
		assert.Equal(t, stringMap[k], v)
	}

	intMap := map[int]string{
		4: "testkey",
		2: "orgkey",
		3: "abckey",
		1: "awskey",
	}
	mIntSorted := MapSort(intMap)

	assert.Len(t, intMap, len(mIntSorted))

	for k, v := range mIntSorted {
		//t.Logf("key: %d, value: %s", k, v)
		fmt.Printf("key: %d, value: %s\n", k, v)
		assert.Equal(t, intMap[k], v)
	}
}
