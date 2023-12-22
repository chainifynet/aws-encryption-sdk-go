// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestValidateOnEncrypt(t *testing.T) {
	type args struct {
		policy    suite.CommitmentPolicy
		algorithm *suite.AlgorithmSuite
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{"Invalid Policy", args{0, nil}, assert.Error},
		{"Algorithm Nil", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt, nil}, assert.Error},
		{"Policy 1 Require Non Committed Messages", args{suite.CommitmentPolicyForbidEncryptAllowDecrypt, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY}, assert.Error},
		{"Policy 2 Require Committed Messages", args{suite.CommitmentPolicyRequireEncryptAllowDecrypt, suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256}, assert.Error},
		{"Policy 3 Require Committed Messages", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt, suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256}, assert.Error},
		{"Policy 2 Allow Committed Messages", args{suite.CommitmentPolicyRequireEncryptAllowDecrypt, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY}, assert.NoError},
		{"Policy 3 Allow Committed Messages", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY}, assert.NoError},
		{"Policy 1 Allow Non Committed Messages", args{suite.CommitmentPolicyForbidEncryptAllowDecrypt, suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, policy.ValidateOnEncrypt(tt.args.policy, tt.args.algorithm), fmt.Sprintf("ValidateOnEncrypt(%v, %v)", tt.args.policy, tt.args.algorithm))
		})
	}
}

func TestValidateOnDecrypt(t *testing.T) {
	type args struct {
		policy    suite.CommitmentPolicy
		algorithm *suite.AlgorithmSuite
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{"Invalid Policy", args{0, nil}, assert.Error},
		{"Algorithm Nil", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt, nil}, assert.Error},
		{"Policy 1 Allow Non Committed Messages", args{suite.CommitmentPolicyForbidEncryptAllowDecrypt, suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256}, assert.NoError},
		{"Policy 2 Allow Non Committed Messages", args{suite.CommitmentPolicyRequireEncryptAllowDecrypt, suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256}, assert.NoError},
		{"Policy 3 Require Committed Messages", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt, suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256}, assert.Error},
		{"Policy 1 Allow Committed Messages", args{suite.CommitmentPolicyForbidEncryptAllowDecrypt, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY}, assert.NoError},
		{"Policy 2 Allow Committed Messages", args{suite.CommitmentPolicyRequireEncryptAllowDecrypt, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY}, assert.NoError},
		{"Policy 3 Allow Committed Messages", args{suite.CommitmentPolicyRequireEncryptRequireDecrypt, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, policy.ValidateOnDecrypt(tt.args.policy, tt.args.algorithm), fmt.Sprintf("ValidateOnDecrypt(%v, %v)", tt.args.policy, tt.args.algorithm))
		})
	}
}
