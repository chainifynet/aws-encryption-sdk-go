// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package encryption

import mock "github.com/stretchr/testify/mock"

// MockEncrypter is an autogenerated mock type for the GcmBase type
type MockEncrypter struct {
	mock.Mock
}

type MockEncrypter_Expecter struct {
	mock *mock.Mock
}

func (_m *MockEncrypter) EXPECT() *MockEncrypter_Expecter {
	return &MockEncrypter_Expecter{mock: &_m.Mock}
}

// Decrypt provides a mock function with given fields: key, iv, ciphertext, tag, aadData
func (_m *MockEncrypter) Decrypt(key []byte, iv []byte, ciphertext []byte, tag []byte, aadData []byte) ([]byte, error) {
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

// MockEncrypter_Decrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Decrypt'
type MockEncrypter_Decrypt_Call struct {
	*mock.Call
}

// Decrypt is a helper method to define mock.On call
//   - key []byte
//   - iv []byte
//   - ciphertext []byte
//   - tag []byte
//   - aadData []byte
func (_e *MockEncrypter_Expecter) Decrypt(key interface{}, iv interface{}, ciphertext interface{}, tag interface{}, aadData interface{}) *MockEncrypter_Decrypt_Call {
	return &MockEncrypter_Decrypt_Call{Call: _e.mock.On("Decrypt", key, iv, ciphertext, tag, aadData)}
}

func (_c *MockEncrypter_Decrypt_Call) Run(run func(key []byte, iv []byte, ciphertext []byte, tag []byte, aadData []byte)) *MockEncrypter_Decrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte), args[2].([]byte), args[3].([]byte), args[4].([]byte))
	})
	return _c
}

func (_c *MockEncrypter_Decrypt_Call) Return(_a0 []byte, _a1 error) *MockEncrypter_Decrypt_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockEncrypter_Decrypt_Call) RunAndReturn(run func([]byte, []byte, []byte, []byte, []byte) ([]byte, error)) *MockEncrypter_Decrypt_Call {
	_c.Call.Return(run)
	return _c
}

// Encrypt provides a mock function with given fields: key, iv, plaintext, aadData
func (_m *MockEncrypter) Encrypt(key []byte, iv []byte, plaintext []byte, aadData []byte) ([]byte, []byte, error) {
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

// MockEncrypter_Encrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Encrypt'
type MockEncrypter_Encrypt_Call struct {
	*mock.Call
}

// Encrypt is a helper method to define mock.On call
//   - key []byte
//   - iv []byte
//   - plaintext []byte
//   - aadData []byte
func (_e *MockEncrypter_Expecter) Encrypt(key interface{}, iv interface{}, plaintext interface{}, aadData interface{}) *MockEncrypter_Encrypt_Call {
	return &MockEncrypter_Encrypt_Call{Call: _e.mock.On("Encrypt", key, iv, plaintext, aadData)}
}

func (_c *MockEncrypter_Encrypt_Call) Run(run func(key []byte, iv []byte, plaintext []byte, aadData []byte)) *MockEncrypter_Encrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].([]byte), args[2].([]byte), args[3].([]byte))
	})
	return _c
}

func (_c *MockEncrypter_Encrypt_Call) Return(_a0 []byte, _a1 []byte, _a2 error) *MockEncrypter_Encrypt_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockEncrypter_Encrypt_Call) RunAndReturn(run func([]byte, []byte, []byte, []byte) ([]byte, []byte, error)) *MockEncrypter_Encrypt_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockEncrypter creates a new instance of MockEncrypter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockEncrypter(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockEncrypter {
	mock := &MockEncrypter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
