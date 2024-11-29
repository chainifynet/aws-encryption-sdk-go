// Code generated by mockery v2.49.1. DO NOT EDIT.

//go:build mocks

package model

import (
	context "context"

	kms "github.com/aws/aws-sdk-go-v2/service/kms"
	mock "github.com/stretchr/testify/mock"
)

// MockKMSClient is an autogenerated mock type for the KMSClient type
type MockKMSClient struct {
	mock.Mock
}

type MockKMSClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockKMSClient) EXPECT() *MockKMSClient_Expecter {
	return &MockKMSClient_Expecter{mock: &_m.Mock}
}

// Decrypt provides a mock function with given fields: ctx, params, optFns
func (_m *MockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, params)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Decrypt")
	}

	var r0 *kms.DecryptOutput
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)); ok {
		return rf(ctx, params, optFns...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) *kms.DecryptOutput); ok {
		r0 = rf(ctx, params, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*kms.DecryptOutput)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) error); ok {
		r1 = rf(ctx, params, optFns...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKMSClient_Decrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Decrypt'
type MockKMSClient_Decrypt_Call struct {
	*mock.Call
}

// Decrypt is a helper method to define mock.On call
//   - ctx context.Context
//   - params *kms.DecryptInput
//   - optFns ...func(*kms.Options)
func (_e *MockKMSClient_Expecter) Decrypt(ctx interface{}, params interface{}, optFns ...interface{}) *MockKMSClient_Decrypt_Call {
	return &MockKMSClient_Decrypt_Call{Call: _e.mock.On("Decrypt",
		append([]interface{}{ctx, params}, optFns...)...)}
}

func (_c *MockKMSClient_Decrypt_Call) Run(run func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options))) *MockKMSClient_Decrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*kms.Options), len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(func(*kms.Options))
			}
		}
		run(args[0].(context.Context), args[1].(*kms.DecryptInput), variadicArgs...)
	})
	return _c
}

func (_c *MockKMSClient_Decrypt_Call) Return(_a0 *kms.DecryptOutput, _a1 error) *MockKMSClient_Decrypt_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKMSClient_Decrypt_Call) RunAndReturn(run func(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)) *MockKMSClient_Decrypt_Call {
	_c.Call.Return(run)
	return _c
}

// Encrypt provides a mock function with given fields: ctx, params, optFns
func (_m *MockKMSClient) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, params)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Encrypt")
	}

	var r0 *kms.EncryptOutput
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)); ok {
		return rf(ctx, params, optFns...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) *kms.EncryptOutput); ok {
		r0 = rf(ctx, params, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*kms.EncryptOutput)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) error); ok {
		r1 = rf(ctx, params, optFns...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKMSClient_Encrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Encrypt'
type MockKMSClient_Encrypt_Call struct {
	*mock.Call
}

// Encrypt is a helper method to define mock.On call
//   - ctx context.Context
//   - params *kms.EncryptInput
//   - optFns ...func(*kms.Options)
func (_e *MockKMSClient_Expecter) Encrypt(ctx interface{}, params interface{}, optFns ...interface{}) *MockKMSClient_Encrypt_Call {
	return &MockKMSClient_Encrypt_Call{Call: _e.mock.On("Encrypt",
		append([]interface{}{ctx, params}, optFns...)...)}
}

func (_c *MockKMSClient_Encrypt_Call) Run(run func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options))) *MockKMSClient_Encrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*kms.Options), len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(func(*kms.Options))
			}
		}
		run(args[0].(context.Context), args[1].(*kms.EncryptInput), variadicArgs...)
	})
	return _c
}

func (_c *MockKMSClient_Encrypt_Call) Return(_a0 *kms.EncryptOutput, _a1 error) *MockKMSClient_Encrypt_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKMSClient_Encrypt_Call) RunAndReturn(run func(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)) *MockKMSClient_Encrypt_Call {
	_c.Call.Return(run)
	return _c
}

// GenerateDataKey provides a mock function with given fields: ctx, params, optFns
func (_m *MockKMSClient) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, params)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for GenerateDataKey")
	}

	var r0 *kms.GenerateDataKeyOutput
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)); ok {
		return rf(ctx, params, optFns...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) *kms.GenerateDataKeyOutput); ok {
		r0 = rf(ctx, params, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*kms.GenerateDataKeyOutput)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) error); ok {
		r1 = rf(ctx, params, optFns...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKMSClient_GenerateDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GenerateDataKey'
type MockKMSClient_GenerateDataKey_Call struct {
	*mock.Call
}

// GenerateDataKey is a helper method to define mock.On call
//   - ctx context.Context
//   - params *kms.GenerateDataKeyInput
//   - optFns ...func(*kms.Options)
func (_e *MockKMSClient_Expecter) GenerateDataKey(ctx interface{}, params interface{}, optFns ...interface{}) *MockKMSClient_GenerateDataKey_Call {
	return &MockKMSClient_GenerateDataKey_Call{Call: _e.mock.On("GenerateDataKey",
		append([]interface{}{ctx, params}, optFns...)...)}
}

func (_c *MockKMSClient_GenerateDataKey_Call) Run(run func(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options))) *MockKMSClient_GenerateDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*kms.Options), len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(func(*kms.Options))
			}
		}
		run(args[0].(context.Context), args[1].(*kms.GenerateDataKeyInput), variadicArgs...)
	})
	return _c
}

func (_c *MockKMSClient_GenerateDataKey_Call) Return(_a0 *kms.GenerateDataKeyOutput, _a1 error) *MockKMSClient_GenerateDataKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKMSClient_GenerateDataKey_Call) RunAndReturn(run func(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)) *MockKMSClient_GenerateDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockKMSClient creates a new instance of MockKMSClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockKMSClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockKMSClient {
	mock := &MockKMSClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
