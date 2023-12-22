// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommitmentPolicy_String(t *testing.T) {
	tests := []struct {
		name       string
		commitment CommitmentPolicy
		wantString string
		wantNum    int
	}{
		{name: "CommitmentPolicy NONE", commitment: _commitmentPolicyNone, wantString: "NONE", wantNum: 0},
		{name: "CommitmentPolicy FORBID_ENCRYPT_ALLOW_DECRYPT", commitment: CommitmentPolicyForbidEncryptAllowDecrypt, wantString: "FORBID_ENCRYPT_ALLOW_DECRYPT", wantNum: 1},
		{name: "CommitmentPolicy REQUIRE_ENCRYPT_ALLOW_DECRYPT", commitment: CommitmentPolicyRequireEncryptAllowDecrypt, wantString: "REQUIRE_ENCRYPT_ALLOW_DECRYPT", wantNum: 2},
		{name: "CommitmentPolicy REQUIRE_ENCRYPT_REQUIRE_DECRYPT", commitment: CommitmentPolicyRequireEncryptRequireDecrypt, wantString: "REQUIRE_ENCRYPT_REQUIRE_DECRYPT", wantNum: 3},
		// a value not defined in our constants
		{name: "Unknown CommitmentPolicy (fallback)", commitment: CommitmentPolicy(10), wantString: "NONE", wantNum: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantString, tt.commitment.String())
			assert.Equal(t, tt.wantString, fmt.Sprintf("%#v", tt.commitment))
			assert.Equal(t, tt.wantNum, int(tt.commitment))
		})
	}
}
