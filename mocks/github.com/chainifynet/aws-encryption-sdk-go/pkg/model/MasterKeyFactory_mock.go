// Code generated by mockery. DO NOT EDIT.

//go:build mocks

package model

import (
	model "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mock "github.com/stretchr/testify/mock"
)

// MockMasterKeyFactory is an autogenerated mock type for the MasterKeyFactory type
type MockMasterKeyFactory struct {
	mock.Mock
}

type MockMasterKeyFactory_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMasterKeyFactory) EXPECT() *MockMasterKeyFactory_Expecter {
	return &MockMasterKeyFactory_Expecter{mock: &_m.Mock}
}

// NewMasterKey provides a mock function with given fields: args
func (_m *MockMasterKeyFactory) NewMasterKey(args ...interface{}) (model.MasterKey, error) {
	var _ca []interface{}
	_ca = append(_ca, args...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for NewMasterKey")
	}

	var r0 model.MasterKey
	var r1 error
	if rf, ok := ret.Get(0).(func(...interface{}) (model.MasterKey, error)); ok {
		return rf(args...)
	}
	if rf, ok := ret.Get(0).(func(...interface{}) model.MasterKey); ok {
		r0 = rf(args...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(model.MasterKey)
		}
	}

	if rf, ok := ret.Get(1).(func(...interface{}) error); ok {
		r1 = rf(args...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockMasterKeyFactory_NewMasterKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NewMasterKey'
type MockMasterKeyFactory_NewMasterKey_Call struct {
	*mock.Call
}

// NewMasterKey is a helper method to define mock.On call
//   - args ...interface{}
func (_e *MockMasterKeyFactory_Expecter) NewMasterKey(args ...interface{}) *MockMasterKeyFactory_NewMasterKey_Call {
	return &MockMasterKeyFactory_NewMasterKey_Call{Call: _e.mock.On("NewMasterKey",
		append([]interface{}{}, args...)...)}
}

func (_c *MockMasterKeyFactory_NewMasterKey_Call) Run(run func(args ...interface{})) *MockMasterKeyFactory_NewMasterKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *MockMasterKeyFactory_NewMasterKey_Call) Return(_a0 model.MasterKey, _a1 error) *MockMasterKeyFactory_NewMasterKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockMasterKeyFactory_NewMasterKey_Call) RunAndReturn(run func(...interface{}) (model.MasterKey, error)) *MockMasterKeyFactory_NewMasterKey_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMasterKeyFactory creates a new instance of MockMasterKeyFactory. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMasterKeyFactory(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMasterKeyFactory {
	mock := &MockMasterKeyFactory{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
