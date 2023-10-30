// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var Commitment commitmentValidator //nolint:gochecknoglobals

type commitmentValidator struct{}

var errCommitmentEncryptNonCommitted = errors.New("configuration conflict. Cannot encrypt due to CommitmentPolicy requiring only non-committed messages")
var errCommitmentEncrypt = errors.New("configuration conflict. Cannot encrypt due to CommitmentPolicy requiring only committed messages")
var errCommitmentDecrypt = errors.New("configuration conflict. Cannot decrypt due to CommitmentPolicy requiring only committed messages")

func (commitmentValidator) ValidatePolicyOnEncrypt(policy suite.CommitmentPolicy, algorithm *suite.AlgorithmSuite) error {
	if policy == suite.CommitmentPolicyForbidEncryptAllowDecrypt {
		if algorithm != nil && algorithm.IsCommitting() {
			return errCommitmentEncryptNonCommitted
		}
	}
	if policy == suite.CommitmentPolicyRequireEncryptAllowDecrypt || policy == suite.CommitmentPolicyRequireEncryptRequireDecrypt {
		if algorithm != nil && !algorithm.IsCommitting() {
			return errCommitmentEncrypt
		}
	}
	return nil
}

func (commitmentValidator) ValidatePolicyOnDecrypt(policy suite.CommitmentPolicy, algorithm *suite.AlgorithmSuite) error {
	if policy == suite.CommitmentPolicyRequireEncryptRequireDecrypt && !algorithm.IsCommitting() {
		return errCommitmentDecrypt
	}
	return nil
}
