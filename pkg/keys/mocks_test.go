// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import "github.com/stretchr/testify/mock"

type MockEncrypter struct {
	mock.Mock
}

func (m *MockEncrypter) Decrypt(key, iv, ciphertext, tag, aadData []byte) (plaintext []byte, err error) {
	args := m.Called(key, iv, ciphertext, tag, aadData)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEncrypter) Encrypt(key, iv, plaintext, aadData []byte) (ciphertext, tag []byte, err error) {
	args := m.Called(key, iv, plaintext, aadData)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

type MockRandomGenerator struct {
	mock.Mock
}

func (m *MockRandomGenerator) CryptoRandomBytes(max int) ([]byte, error) {
	args := m.Called(max)
	return args.Get(0).([]byte), args.Error(1)
}

type MockWrapper struct {
	mock.Mock
}

func (m *MockWrapper) SerializeEncryptedDataKey(encryptedKey, tag, iv []byte) []byte {
	args := m.Called(encryptedKey, tag, iv)
	return args.Get(0).([]byte)
}

func (m *MockWrapper) DeserializeEncryptedDataKey(b []byte, iVLen int) (encryptedData, iv []byte) {
	args := m.Called(b, iVLen)
	return args.Get(0).([]byte), args.Get(1).([]byte)
}
