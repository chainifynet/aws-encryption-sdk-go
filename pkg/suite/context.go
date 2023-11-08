// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"bytes"
	"encoding/binary"
	"sort"
)

// EncryptionContext represents a map of string key-value pairs
// that are used to store contextual information for encryption operations.
type EncryptionContext map[string]string

// keyValueBytes is the number of bytes used to store the length of both
// the key and value as a big-endian encoded 16-bit integer, which totals 4 bytes
// (2 for the key and 2 for the value).
const keyValueBytes = 4

// Serialize transforms the EncryptionContext into a byte slice. The serialized
// format prepends the length of each key and value as a 2-byte big-endian integer.
// Keys are sorted to ensure deterministic output. The function accounts for
// the additional keyValueBytes for each key-value pair when estimating the buffer size
// to minimize reallocations.
//
// The serialization format is as follows for each key-value pair:
//
//	[keyLength][key][valueLength][value]
//	 - keyLength: 2 bytes representing the length of the key as a big-endian integer
//	 - key: actual bytes of the key
//	 - valueLength: 2 bytes representing the length of the value as a big-endian integer
//	 - value: actual bytes of the value
//
// Serialization ensures that keys are sorted and the output is consistent for the same
// EncryptionContext content.
//
// Returns:
//
//	[]byte: A byte slice representing the serialized EncryptionContext.
//
// Example:
//
//	ec := EncryptionContext{"user": "Alice", "purpose": "encryption"}
//	serialized := ec.Serialize()
//	The output will be a byte slice with each key-value pair preceded by their lengths.
func (ec EncryptionContext) Serialize() []byte {
	if len(ec) == 0 {
		return nil
	}
	// Estimate the buffer size to avoid reallocations
	var estimatedSize int

	keys := make([]string, 0, len(ec))
	for k, v := range ec {
		keys = append(keys, k)
		estimatedSize += len(k) + len(v) + keyValueBytes
	}

	sort.Strings(keys)

	buf := bytes.NewBuffer(make([]byte, 0, estimatedSize))

	for _, k := range keys {
		_ = binary.Write(buf, binary.BigEndian, uint16(len(k)))
		buf.WriteString(k)
		_ = binary.Write(buf, binary.BigEndian, uint16(len(ec[k])))
		buf.WriteString(ec[k])
	}

	return buf.Bytes()
}
