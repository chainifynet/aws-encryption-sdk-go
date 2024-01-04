// Code generated by mockery v2.38.0. DO NOT EDIT.

//go:build mocks

package model

import (
	aws "github.com/aws/aws-sdk-go-v2/aws"
	kms "github.com/aws/aws-sdk-go-v2/service/kms"

	mock "github.com/stretchr/testify/mock"

	model "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// MockKMSClientFactory is an autogenerated mock type for the KMSClientFactory type
type MockKMSClientFactory struct {
	mock.Mock
}

type MockKMSClientFactory_Expecter struct {
	mock *mock.Mock
}

func (_m *MockKMSClientFactory) EXPECT() *MockKMSClientFactory_Expecter {
	return &MockKMSClientFactory_Expecter{mock: &_m.Mock}
}

// NewFromConfig provides a mock function with given fields: cfg, optFns
func (_m *MockKMSClientFactory) NewFromConfig(cfg aws.Config, optFns ...func(*kms.Options)) model.KMSClient {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, cfg)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for NewFromConfig")
	}

	var r0 model.KMSClient
	if rf, ok := ret.Get(0).(func(aws.Config, ...func(*kms.Options)) model.KMSClient); ok {
		r0 = rf(cfg, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(model.KMSClient)
		}
	}

	return r0
}

// MockKMSClientFactory_NewFromConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NewFromConfig'
type MockKMSClientFactory_NewFromConfig_Call struct {
	*mock.Call
}

// NewFromConfig is a helper method to define mock.On call
//   - cfg aws.Config
//   - optFns ...func(*kms.Options)
func (_e *MockKMSClientFactory_Expecter) NewFromConfig(cfg interface{}, optFns ...interface{}) *MockKMSClientFactory_NewFromConfig_Call {
	return &MockKMSClientFactory_NewFromConfig_Call{Call: _e.mock.On("NewFromConfig",
		append([]interface{}{cfg}, optFns...)...)}
}

func (_c *MockKMSClientFactory_NewFromConfig_Call) Run(run func(cfg aws.Config, optFns ...func(*kms.Options))) *MockKMSClientFactory_NewFromConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*kms.Options), len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(func(*kms.Options))
			}
		}
		run(args[0].(aws.Config), variadicArgs...)
	})
	return _c
}

func (_c *MockKMSClientFactory_NewFromConfig_Call) Return(_a0 model.KMSClient) *MockKMSClientFactory_NewFromConfig_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKMSClientFactory_NewFromConfig_Call) RunAndReturn(run func(aws.Config, ...func(*kms.Options)) model.KMSClient) *MockKMSClientFactory_NewFromConfig_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockKMSClientFactory creates a new instance of MockKMSClientFactory. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockKMSClientFactory(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockKMSClientFactory {
	mock := &MockKMSClientFactory{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}