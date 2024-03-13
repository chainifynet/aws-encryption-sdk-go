// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

func Test_newAAD(t *testing.T) {
	tests := []struct {
		name        string
		ec          map[string]string
		want        *messageAAD
		wantErr     bool
		wantErrType error
	}{
		{
			name: "Empty Encryption Context",
			ec:   map[string]string{},
			want: &messageAAD{
				kv: []*keyValuePair{},
			},
			wantErr: false,
		},
		{
			name: "Nil Encryption Context",
			ec:   nil,
			want: &messageAAD{
				kv: []*keyValuePair{},
			},
			wantErr: false,
		},
		{
			name:        "Key Value Pair Error",
			ec:          map[string]string{"test": ""},
			want:        nil,
			wantErr:     true,
			wantErrType: errAAD,
		},
		{
			name: "Valid Encryption Context Sorted",
			ec:   map[string]string{"test": "testing", "aws": "awsValue"},
			want: &messageAAD{
				kv: []*keyValuePair{
					{
						keyLen:   3,
						key:      "aws",
						valueLen: 8,
						value:    "awsValue",
					},
					{
						keyLen:   4,
						key:      "test",
						valueLen: 7,
						value:    "testing",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newAAD(tt.ec)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func buildAADKVPair(keyLen int, key string, valueLen int, value string) []byte {
	var keyLenBytes, keyBytes, valueLenBytes, valueBytes []byte
	if keyLen > 0 {
		keyLenBytes = conv.FromInt.Uint16BigEndian(keyLen)
	}
	if key != "" {
		keyBytes = []byte(key)
	}
	if valueLen > 0 {
		valueLenBytes = conv.FromInt.Uint16BigEndian(valueLen)
	}
	if value != "" {
		valueBytes = []byte(value)
	}
	return concatSlices(keyLenBytes, keyBytes, valueLenBytes, valueBytes)
}

func Test_validateKeyValuePair(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		value         string
		wantErr       bool
		wantErrString string
		wantErrType   error
	}{
		{
			name:          "Empty Key",
			key:           "",
			value:         "testing",
			wantErr:       true,
			wantErrString: "key and value cannot be empty",
		},
		{
			name:          "Empty Value",
			key:           "test",
			value:         "",
			wantErr:       true,
			wantErrString: "key and value cannot be empty",
		},
		{
			name:        "Out of Range",
			key:         strings.Repeat("a", 65536),
			value:       "testing",
			wantErr:     true,
			wantErrType: errAadLen,
		},
		{
			name:    "Valid Key Value",
			key:     "test",
			value:   "testing",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyValuePair(tt.key, tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrString != "" {
					assert.ErrorContains(t, err, tt.wantErrString)
				}
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_messageAAD_readKeyValuePair(t *testing.T) {
	tests := []struct {
		name          string
		buf           *bytes.Buffer
		want          *keyValuePair
		wantErr       bool
		wantErrString string
	}{
		{
			name:          "Empty Buffer",
			buf:           bytes.NewBuffer([]byte{}),
			want:          nil,
			wantErr:       true,
			wantErrString: "cant read keyLen",
		},
		{
			name:          "Empty Key Data",
			buf:           bytes.NewBuffer(buildAADKVPair(4, "", 0, "")),
			want:          nil,
			wantErr:       true,
			wantErrString: "empty buffer, cant read key data",
		},
		{
			name:          "Empty Value Len",
			buf:           bytes.NewBuffer(buildAADKVPair(4, "test", 0, "")),
			want:          nil,
			wantErr:       true,
			wantErrString: "cant read valueLen",
		},
		{
			name:          "Empty Value Data",
			buf:           bytes.NewBuffer(buildAADKVPair(4, "test", 7, "")),
			want:          nil,
			wantErr:       true,
			wantErrString: "empty buffer, cant read value data",
		},
		{
			name: "Valid Read",
			buf:  bytes.NewBuffer(buildAADKVPair(5, "tests", 7, "testing")),
			want: &keyValuePair{
				keyLen:   5,
				key:      "tests",
				valueLen: 7,
				value:    "testing",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &messageAAD{
				kv: []*keyValuePair{},
			}
			got, err := a.readKeyValuePair(tt.buf)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				if tt.wantErrString != "" {
					assert.ErrorContains(t, err, tt.wantErrString)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_messageAAD_addKeyValue(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		value         string
		want          *messageAAD
		wantErr       bool
		wantErrString string
	}{
		{
			name:          "Invalid Key",
			key:           "",
			value:         "testing",
			want:          nil,
			wantErr:       true,
			wantErrString: "invalid key-value pair",
		},
		{
			name:          "Invalid Value",
			key:           "test",
			value:         "",
			want:          nil,
			wantErr:       true,
			wantErrString: "invalid key-value pair",
		},
		{
			name:  "Valid Key Value",
			key:   "test",
			value: "testing",
			want: &messageAAD{
				kv: []*keyValuePair{
					{
						keyLen:   4,
						key:      "test",
						valueLen: 7,
						value:    "testing",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &messageAAD{
				kv: []*keyValuePair{},
			}
			err := a.addKeyValue(tt.key, tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrString != "" {
					assert.ErrorContains(t, err, tt.wantErrString)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, a)
			}
		})
	}
}

func Test_deserializeAAD(t *testing.T) {
	tests := []struct {
		name          string
		buf           *bytes.Buffer
		want          *messageAAD
		wantErr       bool
		wantErrType   error
		wantErrString string
	}{
		{
			name:          "Empty Buffer",
			buf:           bytes.NewBuffer([]byte{}),
			want:          nil,
			wantErr:       true,
			wantErrType:   errAAD,
			wantErrString: "cant read keyValueCount",
		},
		{
			name: "KeyValue Count Zero",
			buf:  bytes.NewBuffer([]byte{0x00, 0x00}),
			want: &messageAAD{
				kv: []*keyValuePair{},
			},
			wantErr: false,
		},
		{
			name: "Key Value Error",
			buf: bytes.NewBuffer(concatSlices(
				[]byte{0x00, 0x01},
				buildAADKVPair(4, "", 0, "")),
			),
			want:    nil,
			wantErr: true,
		},
		{
			name: "Key Value Count Exceeds Buffer",
			buf: bytes.NewBuffer(concatSlices(
				[]byte{0x00, 0x03},
				buildAADKVPair(4, "test", 7, "testing"),
				buildAADKVPair(5, "test2", 8, "testing2"),
			)),
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Deserialize",
			buf: bytes.NewBuffer(concatSlices(
				[]byte{0x00, 0x01},
				buildAADKVPair(5, "tests", 8, "testings"),
			)),
			want: &messageAAD{
				kv: []*keyValuePair{
					{
						keyLen:   5,
						key:      "tests",
						valueLen: 8,
						value:    "testings",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid Deserialize Keep KV Order",
			buf: bytes.NewBuffer(concatSlices(
				[]byte{0x00, 0x02},
				buildAADKVPair(4, "test", 7, "testing"),
				buildAADKVPair(3, "aws", 8, "awsValue"),
			)),
			want: &messageAAD{
				kv: []*keyValuePair{
					{
						keyLen:   4,
						key:      "test",
						valueLen: 7,
						value:    "testing",
					},
					{
						keyLen:   3,
						key:      "aws",
						valueLen: 8,
						value:    "awsValue",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deserializeAAD(tt.buf)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrString != "" {
					assert.ErrorContains(t, err, tt.wantErrString)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_keyValuePair_Len(t *testing.T) {
	type fields struct {
		keyLen   int
		valueLen int
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			name: "Empty",
			fields: fields{
				keyLen:   0,
				valueLen: 0,
			},
			want: 4,
		},
		{
			name: "Valid",
			fields: fields{
				keyLen:   4,
				valueLen: 7,
			},
			want: 15,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := keyValuePair{
				keyLen:   tt.fields.keyLen,
				valueLen: tt.fields.valueLen,
			}
			assert.Equal(t, tt.want, kv.Len())
		})
	}
}

func Test_keyValuePair_Bytes(t *testing.T) {
	type fields struct {
		keyLen   int
		key      string
		valueLen int
		value    string
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "Empty",
			fields: fields{
				keyLen:   0,
				key:      "",
				valueLen: 0,
				value:    "",
			},
			want: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "Empty Values",
			fields: fields{
				keyLen:   1,
				key:      "",
				valueLen: 1,
				value:    "",
			},
			want: []byte{0x00, 0x01, 0x00, 0x01},
		},
		{
			name: "Valid Values",
			fields: fields{
				keyLen:   4,
				key:      "test",
				valueLen: 7,
				value:    "testing",
			},
			want: buildAADKVPair(4, "test", 7, "testing"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := keyValuePair{
				keyLen:   tt.fields.keyLen,
				key:      tt.fields.key,
				valueLen: tt.fields.valueLen,
				value:    tt.fields.value,
			}
			assert.Equal(t, tt.want, kv.Bytes())
		})
	}
}

func Test_messageAAD_kvLen(t *testing.T) {
	tests := []struct {
		name string
		kv   []*keyValuePair
		want int
	}{
		{
			name: "Empty",
			kv:   []*keyValuePair{},
			want: 0,
		},
		{
			name: "One Pair",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					valueLen: 7,
				},
			},
			want: 15,
		},
		{
			name: "Two Pairs",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					valueLen: 7,
				},
				{
					keyLen:   5,
					valueLen: 8,
				},
			},
			want: 32,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &messageAAD{
				kv: tt.kv,
			}
			assert.Equal(t, tt.want, a.kvLen())
		})
	}
}

func Test_messageAAD_Len(t *testing.T) {
	tests := []struct {
		name string
		kv   []*keyValuePair
		want int
	}{
		{
			name: "Empty",
			kv:   []*keyValuePair{},
			want: 0,
		},
		{
			name: "One Pair",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					valueLen: 7,
				},
			},
			want: 2 + 15, // 2 bytes count field + 15 bytes kv
		},
		{
			name: "Two Pairs",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					valueLen: 7,
				},
				{
					keyLen:   5,
					valueLen: 8,
				},
			},
			want: 2 + 32, // 2 bytes count field + 32 bytes kv
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &messageAAD{
				kv: tt.kv,
			}
			assert.Equal(t, tt.want, a.Len())
		})
	}
}

func Test_messageAAD_Bytes(t *testing.T) {
	tests := []struct {
		name string
		kv   []*keyValuePair
		want []byte
	}{
		{
			name: "Empty",
			kv:   []*keyValuePair{},
			want: nil,
		},
		{
			name: "One Pair",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					key:      "test",
					valueLen: 7,
					value:    "testing",
				},
			},
			want: concatSlices(
				[]byte{0x00, 0x01},
				buildAADKVPair(4, "test", 7, "testing"),
			),
		},
		{
			name: "Two Pairs",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					key:      "test",
					valueLen: 7,
					value:    "testing",
				},
				{
					keyLen:   3,
					key:      "aws",
					valueLen: 8,
					value:    "awsValue",
				},
			},
			want: concatSlices(
				[]byte{0x00, 0x02},
				buildAADKVPair(4, "test", 7, "testing"),
				buildAADKVPair(3, "aws", 8, "awsValue"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &messageAAD{
				kv: tt.kv,
			}
			assert.Equal(t, tt.want, a.Bytes())
		})
	}
}

func Test_messageAAD_EncryptionContext(t *testing.T) {
	tests := []struct {
		name string
		kv   []*keyValuePair
		want suite.EncryptionContext
	}{
		{
			name: "Empty",
			kv:   []*keyValuePair{},
			want: suite.EncryptionContext{},
		},
		{
			name: "One Pair",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					key:      "test",
					valueLen: 7,
					value:    "testing",
				},
			},
			want: suite.EncryptionContext{
				"test": "testing",
			},
		},
		{
			name: "Two Pairs Ordered",
			kv: []*keyValuePair{
				{
					keyLen:   4,
					key:      "test",
					valueLen: 7,
					value:    "testing",
				},
				{
					keyLen:   3,
					key:      "aws",
					valueLen: 8,
					value:    "awsValue",
				},
			},
			want: suite.EncryptionContext{
				"aws":  "awsValue",
				"test": "testing",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &messageAAD{
				kv: tt.kv,
			}
			assert.Equal(t, tt.want, a.EncryptionContext())
		})
	}
}
