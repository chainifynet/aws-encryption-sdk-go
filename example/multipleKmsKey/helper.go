// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

// getEnvVar returns the value of an environment variable (env) if present or a default (val) provided
func getEnvVar(env string, val string) string {
	v, ok := os.LookupEnv(env)
	if !ok {
		fmt.Printf("%s not set\nusing default value: %s\n", env, val)
		return val
	} else {
		return v
	}
}
