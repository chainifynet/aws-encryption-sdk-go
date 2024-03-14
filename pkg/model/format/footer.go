// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

// MessageFooter contains information about the message footer.
type MessageFooter interface {
	Serializable

	// SignLen returns the length of the signature.
	SignLen() int

	// Signature returns the signature.
	Signature() []byte
}
