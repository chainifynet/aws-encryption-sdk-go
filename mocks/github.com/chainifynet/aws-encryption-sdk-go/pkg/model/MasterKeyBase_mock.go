// Code generated by mockery v2.38.0. DO NOT EDIT.

//go:build mocks

package model

import (
	model "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mock "github.com/stretchr/testify/mock"
)

// MockMasterKeyBase is an autogenerated mock type for the MasterKeyBase type
type MockMasterKeyBase struct {
	mock.Mock
}

type MockMasterKeyBase_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMasterKeyBase) EXPECT() *MockMasterKeyBase_Expecter {
	return &MockMasterKeyBase_Expecter{mock: &_m.Mock}
}

// KeyID provides a mock function with given fields:
func (_m *MockMasterKeyBase) KeyID() string {
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

// MockMasterKeyBase_KeyID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyID'
type MockMasterKeyBase_KeyID_Call struct {
	*mock.Call
}

// KeyID is a helper method to define mock.On call
func (_e *MockMasterKeyBase_Expecter) KeyID() *MockMasterKeyBase_KeyID_Call {
	return &MockMasterKeyBase_KeyID_Call{Call: _e.mock.On("KeyID")}
}

func (_c *MockMasterKeyBase_KeyID_Call) Run(run func()) *MockMasterKeyBase_KeyID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMasterKeyBase_KeyID_Call) Return(_a0 string) *MockMasterKeyBase_KeyID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMasterKeyBase_KeyID_Call) RunAndReturn(run func() string) *MockMasterKeyBase_KeyID_Call {
	_c.Call.Return(run)
	return _c
}

// Metadata provides a mock function with given fields:
func (_m *MockMasterKeyBase) Metadata() model.KeyMeta {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Metadata")
	}

	var r0 model.KeyMeta
	if rf, ok := ret.Get(0).(func() model.KeyMeta); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(model.KeyMeta)
	}

	return r0
}

// MockMasterKeyBase_Metadata_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Metadata'
type MockMasterKeyBase_Metadata_Call struct {
	*mock.Call
}

// Metadata is a helper method to define mock.On call
func (_e *MockMasterKeyBase_Expecter) Metadata() *MockMasterKeyBase_Metadata_Call {
	return &MockMasterKeyBase_Metadata_Call{Call: _e.mock.On("Metadata")}
}

func (_c *MockMasterKeyBase_Metadata_Call) Run(run func()) *MockMasterKeyBase_Metadata_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMasterKeyBase_Metadata_Call) Return(_a0 model.KeyMeta) *MockMasterKeyBase_Metadata_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMasterKeyBase_Metadata_Call) RunAndReturn(run func() model.KeyMeta) *MockMasterKeyBase_Metadata_Call {
	_c.Call.Return(run)
	return _c
}

// OwnsDataKey provides a mock function with given fields: key
func (_m *MockMasterKeyBase) OwnsDataKey(key model.Key) bool {
	ret := _m.Called(key)

	if len(ret) == 0 {
		panic("no return value specified for OwnsDataKey")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(model.Key) bool); ok {
		r0 = rf(key)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MockMasterKeyBase_OwnsDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OwnsDataKey'
type MockMasterKeyBase_OwnsDataKey_Call struct {
	*mock.Call
}

// OwnsDataKey is a helper method to define mock.On call
//   - key model.Key
func (_e *MockMasterKeyBase_Expecter) OwnsDataKey(key interface{}) *MockMasterKeyBase_OwnsDataKey_Call {
	return &MockMasterKeyBase_OwnsDataKey_Call{Call: _e.mock.On("OwnsDataKey", key)}
}

func (_c *MockMasterKeyBase_OwnsDataKey_Call) Run(run func(key model.Key)) *MockMasterKeyBase_OwnsDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(model.Key))
	})
	return _c
}

func (_c *MockMasterKeyBase_OwnsDataKey_Call) Return(_a0 bool) *MockMasterKeyBase_OwnsDataKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMasterKeyBase_OwnsDataKey_Call) RunAndReturn(run func(model.Key) bool) *MockMasterKeyBase_OwnsDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMasterKeyBase creates a new instance of MockMasterKeyBase. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMasterKeyBase(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMasterKeyBase {
	mock := &MockMasterKeyBase{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}