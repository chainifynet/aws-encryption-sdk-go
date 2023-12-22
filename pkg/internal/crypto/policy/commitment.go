// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var errCommitmentEncryptNonCommitted = errors.New("configuration conflict. Cannot encrypt due to CommitmentPolicy requiring only non-committed messages")
var errCommitmentEncrypt = errors.New("configuration conflict. Cannot encrypt due to CommitmentPolicy requiring only committed messages")
var errCommitmentDecrypt = errors.New("configuration conflict. Cannot decrypt due to CommitmentPolicy requiring only committed messages")

func ValidateOnEncrypt(policy suite.CommitmentPolicy, algorithm *suite.AlgorithmSuite) error {
	if err := suite.ValidateCommitmentPolicy(policy); err != nil {
		return err
	}
	if algorithm == nil {
		return fmt.Errorf("algorithm cannot be nil")
	}
	if policy == suite.CommitmentPolicyForbidEncryptAllowDecrypt && algorithm.IsCommitting() {
		return errCommitmentEncryptNonCommitted
	}
	if policy == suite.CommitmentPolicyRequireEncryptAllowDecrypt || policy == suite.CommitmentPolicyRequireEncryptRequireDecrypt {
		if !algorithm.IsCommitting() {
			return errCommitmentEncrypt
		}
	}
	return nil
}

func ValidateOnDecrypt(policy suite.CommitmentPolicy, algorithm *suite.AlgorithmSuite) error {
	if err := suite.ValidateCommitmentPolicy(policy); err != nil {
		return err
	}
	if algorithm == nil {
		return fmt.Errorf("algorithm cannot be nil")
	}
	if policy == suite.CommitmentPolicyRequireEncryptRequireDecrypt && !algorithm.IsCommitting() {
		return errCommitmentDecrypt
	}
	return nil
}
