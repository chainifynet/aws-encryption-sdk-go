// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import "math"

const (
	MinFrameSize = int(128)
	MaxFrameSize = math.MaxUint32
)

type ContentType uint8

const (
	NonFramedContent ContentType = 0x01
	FramedContent    ContentType = 0x02
)

type ContentAADString string

const (
	ContentAADFrame      ContentAADString = "AWSKMSEncryptionClient Frame"
	ContentAADFinalFrame ContentAADString = "AWSKMSEncryptionClient Final Frame"
)

type EncryptionContext map[string]string

type CommitmentPolicy int8

const (
	_commitmentPolicyNone                        CommitmentPolicy = iota - 1 // -1 is NONE
	CommitmentPolicyForbidEncryptAllowDecrypt                                // 0 - FORBID_ENCRYPT_ALLOW_DECRYPT
	CommitmentPolicyRequireEncryptAllowDecrypt                               // 1 - REQUIRE_ENCRYPT_ALLOW_DECRYPT
	CommitmentPolicyRequireEncryptRequireDecrypt                             // 2 - REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

func (cp CommitmentPolicy) String() string {
	switch cp {
	case _commitmentPolicyNone:
		return "NONE"
	case CommitmentPolicyForbidEncryptAllowDecrypt:
		return "FORBID_ENCRYPT_ALLOW_DECRYPT"
	case CommitmentPolicyRequireEncryptAllowDecrypt:
		return "REQUIRE_ENCRYPT_ALLOW_DECRYPT"
	case CommitmentPolicyRequireEncryptRequireDecrypt:
		return "REQUIRE_ENCRYPT_REQUIRE_DECRYPT"
	default:
		return "NONE"
	}
}

func (cp CommitmentPolicy) GoString() string {
	return cp.String()
}
