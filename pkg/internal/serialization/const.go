// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

const (
	lenFieldBytes         = int(2) // lenFieldBytes is length of lenField's in bytes, 2 bytes, 16-bit unsigned integer
	countFieldBytes       = int(2) // countFieldBytes is length of countField's in bytes, 2 bytes, 16-bit unsigned integer
	singleFieldBytes      = int(1) // singleFieldBytes is length of a single field in bytes, 1 byte, 8-bit unsigned integer
	frameFieldBytes       = int(4) // frameFieldBytes is length of a Frame field in bytes, 4 byte, 32-bit unsigned integer
	algorithmIDFieldBytes = int(2) // algorithmIDFieldBytes is length of a AlgorithmID field in bytes, 2 byte, 16-bit unsigned integer represented as uint16
)
