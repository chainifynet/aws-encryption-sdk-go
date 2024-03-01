// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package model

import (
	model "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mock "github.com/stretchr/testify/mock"
)

// MockDataKey is an autogenerated mock type for the DataKeyI type
type MockDataKey struct {
	mock.Mock
}

type MockDataKey_Expecter struct {
	mock *mock.Mock
}

func (_m *MockDataKey) EXPECT() *MockDataKey_Expecter {
	return &MockDataKey_Expecter{mock: &_m.Mock}
}

// DataKey provides a mock function with given fields:
func (_m *MockDataKey) DataKey() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for DataKey")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// MockDataKey_DataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DataKey'
type MockDataKey_DataKey_Call struct {
	*mock.Call
}

// DataKey is a helper method to define mock.On call
func (_e *MockDataKey_Expecter) DataKey() *MockDataKey_DataKey_Call {
	return &MockDataKey_DataKey_Call{Call: _e.mock.On("DataKey")}
}

func (_c *MockDataKey_DataKey_Call) Run(run func()) *MockDataKey_DataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockDataKey_DataKey_Call) Return(_a0 []byte) *MockDataKey_DataKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDataKey_DataKey_Call) RunAndReturn(run func() []byte) *MockDataKey_DataKey_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptedDataKey provides a mock function with given fields:
func (_m *MockDataKey) EncryptedDataKey() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for EncryptedDataKey")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// MockDataKey_EncryptedDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptedDataKey'
type MockDataKey_EncryptedDataKey_Call struct {
	*mock.Call
}

// EncryptedDataKey is a helper method to define mock.On call
func (_e *MockDataKey_Expecter) EncryptedDataKey() *MockDataKey_EncryptedDataKey_Call {
	return &MockDataKey_EncryptedDataKey_Call{Call: _e.mock.On("EncryptedDataKey")}
}

func (_c *MockDataKey_EncryptedDataKey_Call) Run(run func()) *MockDataKey_EncryptedDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockDataKey_EncryptedDataKey_Call) Return(_a0 []byte) *MockDataKey_EncryptedDataKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDataKey_EncryptedDataKey_Call) RunAndReturn(run func() []byte) *MockDataKey_EncryptedDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// KeyID provides a mock function with given fields:
func (_m *MockDataKey) KeyID() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for KeyID")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockDataKey_KeyID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyID'
type MockDataKey_KeyID_Call struct {
	*mock.Call
}

// KeyID is a helper method to define mock.On call
func (_e *MockDataKey_Expecter) KeyID() *MockDataKey_KeyID_Call {
	return &MockDataKey_KeyID_Call{Call: _e.mock.On("KeyID")}
}

func (_c *MockDataKey_KeyID_Call) Run(run func()) *MockDataKey_KeyID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockDataKey_KeyID_Call) Return(_a0 string) *MockDataKey_KeyID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDataKey_KeyID_Call) RunAndReturn(run func() string) *MockDataKey_KeyID_Call {
	_c.Call.Return(run)
	return _c
}

// KeyProvider provides a mock function with given fields:
func (_m *MockDataKey) KeyProvider() model.KeyMeta {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for KeyProvider")
	}

	var r0 model.KeyMeta
	if rf, ok := ret.Get(0).(func() model.KeyMeta); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(model.KeyMeta)
	}

	return r0
}

// MockDataKey_KeyProvider_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyProvider'
type MockDataKey_KeyProvider_Call struct {
	*mock.Call
}

// KeyProvider is a helper method to define mock.On call
func (_e *MockDataKey_Expecter) KeyProvider() *MockDataKey_KeyProvider_Call {
	return &MockDataKey_KeyProvider_Call{Call: _e.mock.On("KeyProvider")}
}

func (_c *MockDataKey_KeyProvider_Call) Run(run func()) *MockDataKey_KeyProvider_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockDataKey_KeyProvider_Call) Return(_a0 model.KeyMeta) *MockDataKey_KeyProvider_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDataKey_KeyProvider_Call) RunAndReturn(run func() model.KeyMeta) *MockDataKey_KeyProvider_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockDataKey creates a new instance of MockDataKey. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockDataKey(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockDataKey {
	mock := &MockDataKey{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
