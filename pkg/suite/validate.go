// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import "fmt"

// ValidateMessageVersion validates the message format version values.
//
// The only supported message format versions are [V1] and [V2].
func ValidateMessageVersion(v uint8) error {
	version := MessageFormatVersion(v)
	if version != V1 && version != V2 {
		return fmt.Errorf("invalid message format version %v", v)
	}
	return nil
}

// ValidateContentType validates the content type values.
//
// The only supported content type is [FramedContent].
func ValidateContentType(t ContentType) error {
	if t != FramedContent {
		return fmt.Errorf("ContentType %v not supported", t)
	}
	return nil
}

// ValidateCommitmentPolicy validates the commitment policy values.
func ValidateCommitmentPolicy(p CommitmentPolicy) error {
	if p < CommitmentPolicyForbidEncryptAllowDecrypt || p > CommitmentPolicyRequireEncryptRequireDecrypt {
		return fmt.Errorf("invalid CommitmentPolicy %v", p)
	}
	return nil
}

// ValidateFrameLength validates the length of a frame.
// It checks if the frame length is within the allowed range and if it is
// a multiple of the block size of the crypto algorithm.
//
// If the frame length is out of range or not a multiple of the [BlockSize]
// (128), an error is returned.
// The allowed minimum frame size is [MinFrameSize] (128).
//
// The allowed maximum frame size is [MaxFrameSize] the maximum value of
// a signed 32-bit integer.
//
// The block size of the crypto algorithm is [BlockSize] 128.
func ValidateFrameLength(frameLength int) error {
	if frameLength < MinFrameSize || frameLength%BlockSize != 0 {
		return fmt.Errorf("frame length must be larger than %d and a multiple of the block size of the crypto algorithm: %d", MinFrameSize, BlockSize)
	}
	if frameLength > MaxFrameSize {
		return fmt.Errorf("frame length too large: %d > %d", frameLength, MaxFrameSize)
	}
	return nil
}
