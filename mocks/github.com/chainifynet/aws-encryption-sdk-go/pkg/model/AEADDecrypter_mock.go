// Code generated by mockery. DO NOT EDIT.

//go:build mocks

package model

import mock "github.com/stretchr/testify/mock"

// MockAEADDecrypter is an autogenerated mock type for the AEADDecrypter type
type MockAEADDecrypter struct {
	mock.Mock
}

type MockAEADDecrypter_Expecter struct {
	mock *mock.Mock
}

func (_m *MockAEADDecrypter) EXPECT() *MockAEADDecrypter_Expecter {
	return &MockAEADDecrypter_Expecter{mock: &_m.Mock}
}

// Decrypt provides a mock function with given fields: key, iv, ciphertext, tag, aadData
func (_m *MockAEADDecrypter) Decrypt(key []byte, iv []byte, ciphertext []byte, tag []byte, aadData []byte) ([]byte, error) {
	ret := _m.Called(key, iv, ciphertext, tag, aadData)

	if len(ret) == 0 {
		panic("no return value specified for Decrypt")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)); ok {
		return rf(key, iv, ciphertext, tag, aadData)
	}
	if rf, ok := ret.Get(0).(func([]byte, []byte, []byte, []byte, []byte) []byte); ok {
		r0 = rf(key, iv, ciphertext, tag, aadData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, []byte, []byte, []byte, []byte) error); ok {
		r1 = rf(key, iv, ciphertext, tag, aadData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockAEADDecrypter_Decrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Decrypt'
type MockAEADDecrypter_Decrypt_Call struct {
	*mock.Call
}

// Decrypt is a helper method to define mock.On call
//   - key []byte
//   - iv []byte
//   - ciphertext []byte
//   - tag []byte
//   - aadData []byte
func (_e *MockAEADDecrypter_Expecter) Decrypt(key interface{}, iv interface{}, ciphertext interface{}, tag interface{}, aadData interface{}) *MockAEADDecrypter_Decrypt_Call {
	return &MockAEADDecrypter_Decrypt_Call{Call: _e.mock.On("Decrypt", key, iv, ciphertext, tag, aadData)}
}

func (_c *MockAEADDecrypter_Decrypt_Call) Run(run func(key []byte, iv []byte, ciphertext []byte, tag []byte, aadData []byte)) *MockAEADDecrypter_Decrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte), args[2].([]byte), args[3].([]byte), args[4].([]byte))
	})
	return _c
}

func (_c *MockAEADDecrypter_Decrypt_Call) Return(_a0 []byte, _a1 error) *MockAEADDecrypter_Decrypt_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockAEADDecrypter_Decrypt_Call) RunAndReturn(run func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) *MockAEADDecrypter_Decrypt_Call {
	_c.Call.Return(run)
	return _c
}

// ValidateHeaderAuth provides a mock function with given fields: derivedDataKey, headerAuthTag, headerBytes
func (_m *MockAEADDecrypter) ValidateHeaderAuth(derivedDataKey []byte, headerAuthTag []byte, headerBytes []byte) error {
	ret := _m.Called(derivedDataKey, headerAuthTag, headerBytes)

	if len(ret) == 0 {
		panic("no return value specified for ValidateHeaderAuth")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func([]byte, []byte, []byte) error); ok {
		r0 = rf(derivedDataKey, headerAuthTag, headerBytes)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAEADDecrypter_ValidateHeaderAuth_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ValidateHeaderAuth'
type MockAEADDecrypter_ValidateHeaderAuth_Call struct {
	*mock.Call
}

// ValidateHeaderAuth is a helper method to define mock.On call
//   - derivedDataKey []byte
//   - headerAuthTag []byte
//   - headerBytes []byte
func (_e *MockAEADDecrypter_Expecter) ValidateHeaderAuth(derivedDataKey interface{}, headerAuthTag interface{}, headerBytes interface{}) *MockAEADDecrypter_ValidateHeaderAuth_Call {
	return &MockAEADDecrypter_ValidateHeaderAuth_Call{Call: _e.mock.On("ValidateHeaderAuth", derivedDataKey, headerAuthTag, headerBytes)}
}

func (_c *MockAEADDecrypter_ValidateHeaderAuth_Call) Run(run func(derivedDataKey []byte, headerAuthTag []byte, headerBytes []byte)) *MockAEADDecrypter_ValidateHeaderAuth_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte), args[2].([]byte))
	})
	return _c
}

func (_c *MockAEADDecrypter_ValidateHeaderAuth_Call) Return(_a0 error) *MockAEADDecrypter_ValidateHeaderAuth_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAEADDecrypter_ValidateHeaderAuth_Call) RunAndReturn(run func([]byte, []byte, []byte) error) *MockAEADDecrypter_ValidateHeaderAuth_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockAEADDecrypter creates a new instance of MockAEADDecrypter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockAEADDecrypter(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockAEADDecrypter {
	mock := &MockAEADDecrypter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
