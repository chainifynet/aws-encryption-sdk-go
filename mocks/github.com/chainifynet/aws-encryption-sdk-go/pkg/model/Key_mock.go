// Code generated by mockery v2.49.1. DO NOT EDIT.

//go:build mocks

package model

import (
	model "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mock "github.com/stretchr/testify/mock"
)

// MockKey is an autogenerated mock type for the Key type
type MockKey struct {
	mock.Mock
}

type MockKey_Expecter struct {
	mock *mock.Mock
}

func (_m *MockKey) EXPECT() *MockKey_Expecter {
	return &MockKey_Expecter{mock: &_m.Mock}
}

// KeyID provides a mock function with given fields:
func (_m *MockKey) KeyID() string {
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

// MockKey_KeyID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyID'
type MockKey_KeyID_Call struct {
	*mock.Call
}

// KeyID is a helper method to define mock.On call
func (_e *MockKey_Expecter) KeyID() *MockKey_KeyID_Call {
	return &MockKey_KeyID_Call{Call: _e.mock.On("KeyID")}
}

func (_c *MockKey_KeyID_Call) Run(run func()) *MockKey_KeyID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockKey_KeyID_Call) Return(_a0 string) *MockKey_KeyID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKey_KeyID_Call) RunAndReturn(run func() string) *MockKey_KeyID_Call {
	_c.Call.Return(run)
	return _c
}

// KeyProvider provides a mock function with given fields:
func (_m *MockKey) KeyProvider() model.KeyMeta {
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

// MockKey_KeyProvider_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyProvider'
type MockKey_KeyProvider_Call struct {
	*mock.Call
}

// KeyProvider is a helper method to define mock.On call
func (_e *MockKey_Expecter) KeyProvider() *MockKey_KeyProvider_Call {
	return &MockKey_KeyProvider_Call{Call: _e.mock.On("KeyProvider")}
}

func (_c *MockKey_KeyProvider_Call) Run(run func()) *MockKey_KeyProvider_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockKey_KeyProvider_Call) Return(_a0 model.KeyMeta) *MockKey_KeyProvider_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKey_KeyProvider_Call) RunAndReturn(run func() model.KeyMeta) *MockKey_KeyProvider_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockKey creates a new instance of MockKey. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockKey(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockKey {
	mock := &MockKey{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
