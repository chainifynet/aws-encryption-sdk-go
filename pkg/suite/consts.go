// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"math"
)

const (
	MinFrameSize = int(128)      // Minimum allowed frame size
	MaxFrameSize = math.MaxInt32 // Maximum allowed frame size which is math.MaxInt32
	BlockSize    = int(128)      // BlockSize is aes.BlockSize in bits (16 * 8)
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

type CommitmentPolicy int8

const (
	_commitmentPolicyNone                        CommitmentPolicy = iota // 0 is NONE
	CommitmentPolicyForbidEncryptAllowDecrypt                            // 1 - FORBID_ENCRYPT_ALLOW_DECRYPT
	CommitmentPolicyRequireEncryptAllowDecrypt                           // 2 - REQUIRE_ENCRYPT_ALLOW_DECRYPT
	CommitmentPolicyRequireEncryptRequireDecrypt                         // 3 - REQUIRE_ENCRYPT_REQUIRE_DECRYPT
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

type MessageFormatVersion uint8

const (
	V1 MessageFormatVersion = iota + 1 // 1 is V1 MessageFormatVersion
	V2                                 // 2 is V2 MessageFormatVersion
)

type MessageType int

const (
	CustomerAEData MessageType = 128 // 128 is 80 in hex
)
