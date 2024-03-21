// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const aadLenFields = int(2)

var (
	errAadLen = errors.New("key or value length is out of range")
	errAAD    = errors.New("AAD error")
)

type messageAAD struct {
	// N.B.: messageAAD serializes into 2 bytes count field (Key-Value Pair Count) + length of kv
	kv []*keyValuePair
}

type keyValuePair struct {
	keyLen   int    // 2, keyLen is length of key, 2 bytes
	key      string // key is AAD Key name
	valueLen int    // 2, valueLen is length of value, 2 bytes
	value    string // value is AAD Value
}

func newAAD(ec map[string]string) (*messageAAD, error) {
	a := &messageAAD{
		kv: []*keyValuePair{},
	}

	if len(ec) == 0 {
		return a, nil
	}

	// it is extra important to keep an order of encryption context
	keys := make([]string, 0, len(ec))
	for k := range ec {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		err := a.addKeyValue(k, ec[k])
		if err != nil {
			return nil, fmt.Errorf("key-value pair error: %w", errors.Join(errAAD, err))
		}
	}

	return a, nil
}

func deserializeAAD(buf *bytes.Buffer) (*messageAAD, error) {
	a := &messageAAD{
		kv: []*keyValuePair{},
	}

	keyValueCount, err := fieldReader.ReadCountField(buf) // Key-Value Pair Count
	if err != nil {
		return nil, fmt.Errorf("cant read keyValueCount: %w", errors.Join(errAAD, err))
	}
	if keyValueCount == 0 {
		return a, nil
	}

	for i := 0; i < keyValueCount; i++ {
		kv, err := a.readKeyValuePair(buf)
		if err != nil {
			return nil, err
		}
		a.kv = append(a.kv, kv)
	}

	return a, nil
}

func (a *messageAAD) addKeyValue(key, value string) error {
	if err := validateKeyValuePair(key, value); err != nil {
		return fmt.Errorf("invalid key-value pair: %w", err)
	}
	a.kv = append(a.kv, &keyValuePair{
		keyLen:   len(key),
		key:      key,
		valueLen: len(value),
		value:    value,
	})
	return nil
}

func (a *messageAAD) readKeyValuePair(buf *bytes.Buffer) (*keyValuePair, error) {
	keyLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant read keyLen: %w", err)
	}
	if buf.Len() < keyLen {
		return nil, fmt.Errorf("empty buffer, cant read key data")
	}
	key := buf.Next(keyLen)

	valueLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant read valueLen: %w", err)
	}
	if buf.Len() < valueLen {
		return nil, fmt.Errorf("empty buffer, cant read value data")
	}
	value := buf.Next(valueLen)

	return &keyValuePair{
		keyLen:   keyLen,
		key:      string(key),
		valueLen: valueLen,
		value:    string(value),
	}, nil
}

// Len returns length of AADData
// N.B.: aadData serializes into 2 bytes count field (Key-Value Pair Count) + length of kv
// When there is no encryption context or the encryption context is empty, this field is not present in the AAD structure.
func (a *messageAAD) Len() int {
	if len(a.kv) == 0 {
		return 0
	}
	return countFieldBytes + a.kvLen()
}

func (a *messageAAD) kvLen() int {
	var kvLen int
	for _, k := range a.kv {
		kvLen += k.Len()
	}
	return kvLen
}

func (a *messageAAD) Bytes() []byte {
	if len(a.kv) == 0 {
		return nil
	}
	var buf []byte
	buf = make([]byte, 0, a.Len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(len(a.kv))...)
	for _, k := range a.kv {
		buf = append(buf, k.Bytes()...)
	}
	return buf
}

func (a *messageAAD) EncryptionContext() suite.EncryptionContext {
	ec := make(suite.EncryptionContext)

	for _, pair := range a.kv {
		ec[pair.key] = pair.value
	}

	// not sure if I need to preserve the order of encryption context
	// when decrypting data
	// maybe I should leave it as it was in ciphertext
	var encryptionContext suite.EncryptionContext
	encryptionContext = structs.MapSort(ec)

	return encryptionContext
}

func (kv keyValuePair) Len() int {
	return (aadLenFields * lenFieldBytes) +
		kv.keyLen +
		kv.valueLen
}

func (kv keyValuePair) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, kv.Len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(kv.keyLen)...)
	buf = append(buf, []byte(kv.key)...)
	buf = append(buf, conv.FromInt.Uint16BigEndian(kv.valueLen)...)
	buf = append(buf, []byte(kv.value)...)
	return buf
}

func validateKeyValuePair(key, value string) error {
	if key == "" || value == "" {
		return fmt.Errorf("key and value cannot be empty")
	}
	if len(key) > math.MaxUint16 || len(value) > math.MaxUint32 {
		return errAadLen
	}
	return nil
}
