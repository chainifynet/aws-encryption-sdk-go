// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommitmentPolicy_String(t *testing.T) {
	tests := []struct {
		name           string
		commitment     CommitmentPolicy
		expectedString string
	}{
		{name: "CommitmentPolicy NONE", commitment: _commitmentPolicyNone, expectedString: "NONE"},
		{name: "CommitmentPolicy FORBID_ENCRYPT_ALLOW_DECRYPT", commitment: CommitmentPolicyForbidEncryptAllowDecrypt, expectedString: "FORBID_ENCRYPT_ALLOW_DECRYPT"},
		{name: "CommitmentPolicy REQUIRE_ENCRYPT_ALLOW_DECRYPT", commitment: CommitmentPolicyRequireEncryptAllowDecrypt, expectedString: "REQUIRE_ENCRYPT_ALLOW_DECRYPT"},
		{name: "CommitmentPolicy REQUIRE_ENCRYPT_REQUIRE_DECRYPT", commitment: CommitmentPolicyRequireEncryptRequireDecrypt, expectedString: "REQUIRE_ENCRYPT_REQUIRE_DECRYPT"},
		// a value not defined in our constants
		{name: "Unknown CommitmentPolicy (fallback)", commitment: CommitmentPolicy(10), expectedString: "NONE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, tt.commitment.String())
		})
	}
}
