// Code generated by mockery. DO NOT EDIT.

//go:build mocks

package format

import (
	suite "github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	mock "github.com/stretchr/testify/mock"
)

// MockMessageAAD is an autogenerated mock type for the MessageAAD type
type MockMessageAAD struct {
	mock.Mock
}

type MockMessageAAD_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMessageAAD) EXPECT() *MockMessageAAD_Expecter {
	return &MockMessageAAD_Expecter{mock: &_m.Mock}
}

// Bytes provides a mock function with given fields:
func (_m *MockMessageAAD) Bytes() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Bytes")
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

// MockMessageAAD_Bytes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bytes'
type MockMessageAAD_Bytes_Call struct {
	*mock.Call
}

// Bytes is a helper method to define mock.On call
func (_e *MockMessageAAD_Expecter) Bytes() *MockMessageAAD_Bytes_Call {
	return &MockMessageAAD_Bytes_Call{Call: _e.mock.On("Bytes")}
}

func (_c *MockMessageAAD_Bytes_Call) Run(run func()) *MockMessageAAD_Bytes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageAAD_Bytes_Call) Return(_a0 []byte) *MockMessageAAD_Bytes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageAAD_Bytes_Call) RunAndReturn(run func() []byte) *MockMessageAAD_Bytes_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptionContext provides a mock function with given fields:
func (_m *MockMessageAAD) EncryptionContext() suite.EncryptionContext {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for EncryptionContext")
	}

	var r0 suite.EncryptionContext
	if rf, ok := ret.Get(0).(func() suite.EncryptionContext); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(suite.EncryptionContext)
		}
	}

	return r0
}

// MockMessageAAD_EncryptionContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptionContext'
type MockMessageAAD_EncryptionContext_Call struct {
	*mock.Call
}

// EncryptionContext is a helper method to define mock.On call
func (_e *MockMessageAAD_Expecter) EncryptionContext() *MockMessageAAD_EncryptionContext_Call {
	return &MockMessageAAD_EncryptionContext_Call{Call: _e.mock.On("EncryptionContext")}
}

func (_c *MockMessageAAD_EncryptionContext_Call) Run(run func()) *MockMessageAAD_EncryptionContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageAAD_EncryptionContext_Call) Return(_a0 suite.EncryptionContext) *MockMessageAAD_EncryptionContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageAAD_EncryptionContext_Call) RunAndReturn(run func() suite.EncryptionContext) *MockMessageAAD_EncryptionContext_Call {
	_c.Call.Return(run)
	return _c
}

// Len provides a mock function with given fields:
func (_m *MockMessageAAD) Len() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Len")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockMessageAAD_Len_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Len'
type MockMessageAAD_Len_Call struct {
	*mock.Call
}

// Len is a helper method to define mock.On call
func (_e *MockMessageAAD_Expecter) Len() *MockMessageAAD_Len_Call {
	return &MockMessageAAD_Len_Call{Call: _e.mock.On("Len")}
}

func (_c *MockMessageAAD_Len_Call) Run(run func()) *MockMessageAAD_Len_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageAAD_Len_Call) Return(_a0 int) *MockMessageAAD_Len_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageAAD_Len_Call) RunAndReturn(run func() int) *MockMessageAAD_Len_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMessageAAD creates a new instance of MockMessageAAD. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMessageAAD(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMessageAAD {
	mock := &MockMessageAAD{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
