// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

const aadLenFields = int(2)

var errAadLen = errors.New("key or value length is out of range")

var AAD = aad{ //nolint:gochecknoglobals
	lenFields: aadLenFields,
}

type aad struct {
	lenFields int
}

type aadData struct {
	// N.B.: aadData serializes into 2 bytes count field (Key-Value Pair Count) + length of kv
	kv []keyValuePair
}

type keyValuePair struct {
	keyLen   int    // 2, keyLen is length of key, 2 bytes
	key      string // key is AAD Key name
	valueLen int    // 2, valueLen is length of value, 2 bytes
	value    string // value is AAD Value
}

// NewAAD TODO andrew change to unexported
func (s aad) NewAAD() *aadData {
	return &aadData{
		kv: []keyValuePair{},
	}
}

// NewAADWithEncryptionContext
//
// used during encryption process
// TODO andrew refactor to return (nil, error)
func (s aad) NewAADWithEncryptionContext(ec map[string]string) *aadData {
	// just return new AAD if empty map provided
	if len(ec) == 0 {
		return AAD.NewAAD()
	}
	// it is extra important to keep an order of encryption context
	keys := make([]string, 0, len(ec))
	for k := range ec {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	data := AAD.NewAAD()

	for _, k := range keys {
		err := data.addKeyValue(k, ec[k])
		if err != nil {
			fmt.Printf("ec: %#v, err: %v", ec, err)
			// TODO andrew refactor to return (nil, error)
			panic(err)
		}
	}
	return data
}

func (d *aadData) addKeyValue(key, value string) error {
	if len(key) > math.MaxUint16 || len(value) > math.MaxUint32 {
		return errAadLen
	}
	d.kv = append(d.kv, keyValuePair{
		keyLen:   len(key),
		key:      key,
		valueLen: len(value),
		value:    value,
	})
	return nil
}

// Len returns length of AADData
// N.B.: aadData serializes into 2 bytes count field (Key-Value Pair Count) + length of kv
// When there is no encryption context or the encryption context is empty, this field is not present in the AAD structure.
// TODO andrew change to unexported
func (d *aadData) Len() int {
	if len(d.kv) == 0 {
		return 0
	}
	return countFieldBytes + d.kvLen()
}

func (d *aadData) String() string {
	return fmt.Sprintf("%#v", *d)
}

func (d *aadData) kvLen() int {
	var kvLen int
	for _, k := range d.kv {
		kvLen += k.Len()
	}
	return kvLen
}

// Bytes TODO andrew change to unexported
func (d *aadData) Bytes() []byte {
	if len(d.kv) == 0 {
		return nil
	}
	var buf []byte
	buf = make([]byte, 0, d.Len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(len(d.kv))...)
	for _, k := range d.kv {
		buf = append(buf, k.Bytes()...)
	}
	return buf
}

// AsEncryptionContext
//
// used during decryption process
func (d *aadData) AsEncryptionContext() suite.EncryptionContext {
	ec := make(suite.EncryptionContext)

	for _, pair := range d.kv {
		ec[pair.key] = pair.value
	}

	// not sure if I need to preserve the order of encryption context
	// when decrypting data
	// maybe I should leave it as it was in ciphertext
	var encryptionContext suite.EncryptionContext
	encryptionContext = structs.MapSort(ec)

	return encryptionContext
}

// FromBuffer TODO andrew refactor this to return (*aadData, error)
func (s aad) FromBuffer(buf *bytes.Buffer) *aadData {
	keyValueCount := fieldReader.ReadCountField(buf) // Key-Value Pair Count
	if keyValueCount <= 0 {
		return nil
	}

	data := &aadData{kv: []keyValuePair{}}

	for i := 0; i < keyValueCount; i++ {
		err := data.keyValueFromBuffer(buf)
		if err != nil {
			fmt.Printf("%v", err)
			// TODO andrew refactor do not panic here, return (nil, error)
			panic(err)
		}
	}
	return data
}

// Len TODO andrew change to unexported
func (kv keyValuePair) Len() int {
	return (AAD.lenFields * lenFieldBytes) +
		kv.keyLen +
		kv.valueLen
}

// Bytes TODO andrew change to unexported
func (kv keyValuePair) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, kv.Len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(kv.keyLen)...)
	buf = append(buf, []byte(kv.key)...)
	buf = append(buf, conv.FromInt.Uint16BigEndian(kv.valueLen)...)
	buf = append(buf, []byte(kv.value)...)
	return buf
}

func (d *aadData) keyValueFromBuffer(buf *bytes.Buffer) error {
	keyLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return fmt.Errorf("cant read keyLen: %w", errors.Join(errAadLen, err))
	}
	key := buf.Next(keyLen)
	valueLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return fmt.Errorf("cant read valueLen: %w", errors.Join(errAadLen, err))
	}
	value := buf.Next(valueLen)

	if len(key) > math.MaxUint16 || len(value) > math.MaxUint32 {
		return fmt.Errorf("out of range: %w", errAadLen)
	}
	d.kv = append(d.kv, keyValuePair{
		keyLen:   keyLen,
		key:      string(key),
		valueLen: valueLen,
		value:    string(value),
	})
	return nil
}
