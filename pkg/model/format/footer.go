// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package format

type MessageFooter interface {
	Serializable
	SignLen() int
	Signature() []byte
}
