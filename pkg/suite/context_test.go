// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite_test

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// serializeKeyValuePair helper function in order to
// construct the expected byte slices (want) for the test cases.
func serializeKeyValuePair(key, value string) []byte {
	keyLength := uint16(len(key))
	valueLength := uint16(len(value))

	// Allocate a byte slice of the correct size
	buf := make([]byte, 2+keyLength+2+valueLength)

	// Write lengths and strings into the byte slice
	binary.BigEndian.PutUint16(buf[0:2], keyLength)
	copy(buf[2:2+keyLength], key)
	binary.BigEndian.PutUint16(buf[2+keyLength:4+keyLength], valueLength)
	copy(buf[4+keyLength:], value)

	return buf
}

func TestEncryptionContext_Serialize(t *testing.T) {
	tests := []struct {
		name    string
		context suite.EncryptionContext
		want    []byte
	}{
		{
			name:    "empty context",
			context: suite.EncryptionContext{},
			want:    nil,
		},
		{
			name:    "single key-value pair",
			context: suite.EncryptionContext{"user": "Alice"},
			want:    serializeKeyValuePair("user", "Alice"),
		},
		{
			name:    "multiple key-value pairs sorted",
			context: suite.EncryptionContext{"user": "Alice", "purpose": "encryption", "year": "2023"},
			want: append(serializeKeyValuePair("purpose", "encryption"),
				append(serializeKeyValuePair("user", "Alice"),
					serializeKeyValuePair("year", "2023")...)...),
		},
		{
			name:    "context with empty string value",
			context: suite.EncryptionContext{"empty": ""},
			want:    serializeKeyValuePair("empty", ""),
		},
		{
			name:    "context with special characters",
			context: suite.EncryptionContext{"data": "%%$$##@@!!"},
			want:    serializeKeyValuePair("data", "%%$$##@@!!"),
		},
		{
			name:    "context with numeric values",
			context: suite.EncryptionContext{"max": "12345", "min": "67890"},
			want: append(serializeKeyValuePair("max", "12345"),
				serializeKeyValuePair("min", "67890")...),
		},
		{
			name:    "context with mixed case keys",
			context: suite.EncryptionContext{"CaseSensitive": "true", "casesensitive": "false"},
			want: append(serializeKeyValuePair("CaseSensitive", "true"),
				serializeKeyValuePair("casesensitive", "false")...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.context.Serialize()
			assert.Equal(t, tt.want, got, "Serialized output should match the wanted output")
		})
	}
}
