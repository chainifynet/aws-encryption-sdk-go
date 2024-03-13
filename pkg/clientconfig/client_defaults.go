// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientconfig

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"

const (
	// DefaultCommitment is the default commitment policy for the client.
	DefaultCommitment = suite.CommitmentPolicyRequireEncryptRequireDecrypt

	// DefaultMaxEDK is the default maximum number of encrypted data keys that can be
	// used to encrypt or decrypt a single message.
	DefaultMaxEDK = 10
)
