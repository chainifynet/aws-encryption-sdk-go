// Code generated by mockery. DO NOT EDIT.

//go:build mocks

package model

import mock "github.com/stretchr/testify/mock"

// MockAEADEncrypter is an autogenerated mock type for the AEADEncrypter type
type MockAEADEncrypter struct {
	mock.Mock
}

type MockAEADEncrypter_Expecter struct {
	mock *mock.Mock
}

func (_m *MockAEADEncrypter) EXPECT() *MockAEADEncrypter_Expecter {
	return &MockAEADEncrypter_Expecter{mock: &_m.Mock}
}

// ConstructIV provides a mock function with given fields: seqNum
func (_m *MockAEADEncrypter) ConstructIV(seqNum int) []byte {
	ret := _m.Called(seqNum)

	if len(ret) == 0 {
		panic("no return value specified for ConstructIV")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func(int) []byte); ok {
		r0 = rf(seqNum)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// MockAEADEncrypter_ConstructIV_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ConstructIV'
type MockAEADEncrypter_ConstructIV_Call struct {
	*mock.Call
}

// ConstructIV is a helper method to define mock.On call
//   - seqNum int
func (_e *MockAEADEncrypter_Expecter) ConstructIV(seqNum interface{}) *MockAEADEncrypter_ConstructIV_Call {
	return &MockAEADEncrypter_ConstructIV_Call{Call: _e.mock.On("ConstructIV", seqNum)}
}

func (_c *MockAEADEncrypter_ConstructIV_Call) Run(run func(seqNum int)) *MockAEADEncrypter_ConstructIV_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *MockAEADEncrypter_ConstructIV_Call) Return(_a0 []byte) *MockAEADEncrypter_ConstructIV_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAEADEncrypter_ConstructIV_Call) RunAndReturn(run func(int) []byte) *MockAEADEncrypter_ConstructIV_Call {
	_c.Call.Return(run)
	return _c
}

// Encrypt provides a mock function with given fields: key, iv, plaintext, aadData
func (_m *MockAEADEncrypter) Encrypt(key []byte, iv []byte, plaintext []byte, aadData []byte) ([]byte, []byte, error) {
	ret := _m.Called(key, iv, plaintext, aadData)

	if len(ret) == 0 {
		panic("no return value specified for Encrypt")
	}

	var r0 []byte
	var r1 []byte
	var r2 error
	if rf, ok := ret.Get(0).(func([]byte, []byte, []byte, []byte) ([]byte, []byte, error)); ok {
		return rf(key, iv, plaintext, aadData)
	}
	if rf, ok := ret.Get(0).(func([]byte, []byte, []byte, []byte) []byte); ok {
		r0 = rf(key, iv, plaintext, aadData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, []byte, []byte, []byte) []byte); ok {
		r1 = rf(key, iv, plaintext, aadData)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	if rf, ok := ret.Get(2).(func([]byte, []byte, []byte, []byte) error); ok {
		r2 = rf(key, iv, plaintext, aadData)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockAEADEncrypter_Encrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Encrypt'
type MockAEADEncrypter_Encrypt_Call struct {
	*mock.Call
}

// Encrypt is a helper method to define mock.On call
//   - key []byte
//   - iv []byte
//   - plaintext []byte
//   - aadData []byte
func (_e *MockAEADEncrypter_Expecter) Encrypt(key interface{}, iv interface{}, plaintext interface{}, aadData interface{}) *MockAEADEncrypter_Encrypt_Call {
	return &MockAEADEncrypter_Encrypt_Call{Call: _e.mock.On("Encrypt", key, iv, plaintext, aadData)}
}

func (_c *MockAEADEncrypter_Encrypt_Call) Run(run func(key []byte, iv []byte, plaintext []byte, aadData []byte)) *MockAEADEncrypter_Encrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte), args[2].([]byte), args[3].([]byte))
	})
	return _c
}

func (_c *MockAEADEncrypter_Encrypt_Call) Return(_a0 []byte, _a1 []byte, _a2 error) *MockAEADEncrypter_Encrypt_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockAEADEncrypter_Encrypt_Call) RunAndReturn(run func([]byte, []byte, []byte, []byte) ([]byte, []byte, error)) *MockAEADEncrypter_Encrypt_Call {
	_c.Call.Return(run)
	return _c
}

// GenerateHeaderAuth provides a mock function with given fields: derivedDataKey, headerBytes
func (_m *MockAEADEncrypter) GenerateHeaderAuth(derivedDataKey []byte, headerBytes []byte) ([]byte, []byte, error) {
	ret := _m.Called(derivedDataKey, headerBytes)

	if len(ret) == 0 {
		panic("no return value specified for GenerateHeaderAuth")
	}

	var r0 []byte
	var r1 []byte
	var r2 error
	if rf, ok := ret.Get(0).(func([]byte, []byte) ([]byte, []byte, error)); ok {
		return rf(derivedDataKey, headerBytes)
	}
	if rf, ok := ret.Get(0).(func([]byte, []byte) []byte); ok {
		r0 = rf(derivedDataKey, headerBytes)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, []byte) []byte); ok {
		r1 = rf(derivedDataKey, headerBytes)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	if rf, ok := ret.Get(2).(func([]byte, []byte) error); ok {
		r2 = rf(derivedDataKey, headerBytes)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockAEADEncrypter_GenerateHeaderAuth_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GenerateHeaderAuth'
type MockAEADEncrypter_GenerateHeaderAuth_Call struct {
	*mock.Call
}

// GenerateHeaderAuth is a helper method to define mock.On call
//   - derivedDataKey []byte
//   - headerBytes []byte
func (_e *MockAEADEncrypter_Expecter) GenerateHeaderAuth(derivedDataKey interface{}, headerBytes interface{}) *MockAEADEncrypter_GenerateHeaderAuth_Call {
	return &MockAEADEncrypter_GenerateHeaderAuth_Call{Call: _e.mock.On("GenerateHeaderAuth", derivedDataKey, headerBytes)}
}

func (_c *MockAEADEncrypter_GenerateHeaderAuth_Call) Run(run func(derivedDataKey []byte, headerBytes []byte)) *MockAEADEncrypter_GenerateHeaderAuth_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte))
	})
	return _c
}

func (_c *MockAEADEncrypter_GenerateHeaderAuth_Call) Return(_a0 []byte, _a1 []byte, _a2 error) *MockAEADEncrypter_GenerateHeaderAuth_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockAEADEncrypter_GenerateHeaderAuth_Call) RunAndReturn(run func([]byte, []byte) ([]byte, []byte, error)) *MockAEADEncrypter_GenerateHeaderAuth_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockAEADEncrypter creates a new instance of MockAEADEncrypter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockAEADEncrypter(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockAEADEncrypter {
	mock := &MockAEADEncrypter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
