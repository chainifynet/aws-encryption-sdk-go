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

// ContentType is the type of encrypted data, either non-framed or framed.
type ContentType uint8

// Supported content types.
const (
	NonFramedContent ContentType = 0x01 // Non-framed content is type 1, encoded as the byte 01 in hexadecimal notation.
	FramedContent    ContentType = 0x02 // Framed content is type 2, encoded as the byte 02 in hexadecimal notation.
)

// CommitmentPolicy is a configuration setting that determines whether your
// application encrypts and decrypts with [key commitment].
//
// See [Commitment policy] for more information.
//
// [Commitment policy]: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#commitment-policy
// [key commitment]: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#key-commitment
type CommitmentPolicy int8

// Supported commitment policies.
const (
	_commitmentPolicyNone                        CommitmentPolicy = iota // 0 is NONE
	CommitmentPolicyForbidEncryptAllowDecrypt                            // 1 - FORBID_ENCRYPT_ALLOW_DECRYPT
	CommitmentPolicyRequireEncryptAllowDecrypt                           // 2 - REQUIRE_ENCRYPT_ALLOW_DECRYPT
	CommitmentPolicyRequireEncryptRequireDecrypt                         // 3 - REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

// String returns the string representation of the [CommitmentPolicy].
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

// GoString returns the same as String().
func (cp CommitmentPolicy) GoString() string {
	return cp.String()
}

// MessageFormatVersion is the version of the message format.
type MessageFormatVersion uint8

// Supported message format versions.
//
//   - Algorithm suites without key commitment use message format version 1.
//   - Algorithm suites with key commitment use message format version 2.
const (
	V1 MessageFormatVersion = iota + 1 // Version 1 encoded as the byte 01 in hexadecimal notation.
	V2                                 // Version 2 encoded as the byte 02 in hexadecimal notation.
)
