// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package model

import (
	context "context"

	format "github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	mock "github.com/stretchr/testify/mock"

	suite "github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// MockEncrypter is an autogenerated mock type for the EncryptionHandler type
type MockEncrypter struct {
	mock.Mock
}

type MockEncrypter_Expecter struct {
	mock *mock.Mock
}

func (_m *MockEncrypter) EXPECT() *MockEncrypter_Expecter {
	return &MockEncrypter_Expecter{mock: &_m.Mock}
}

// Encrypt provides a mock function with given fields: ctx, source, ec
func (_m *MockEncrypter) Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, format.MessageHeader, error) {
	ret := _m.Called(ctx, source, ec)

	if len(ret) == 0 {
		panic("no return value specified for Encrypt")
	}

	var r0 []byte
	var r1 format.MessageHeader
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, []byte, suite.EncryptionContext) ([]byte, format.MessageHeader, error)); ok {
		return rf(ctx, source, ec)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []byte, suite.EncryptionContext) []byte); ok {
		r0 = rf(ctx, source, ec)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []byte, suite.EncryptionContext) format.MessageHeader); ok {
		r1 = rf(ctx, source, ec)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(format.MessageHeader)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, []byte, suite.EncryptionContext) error); ok {
		r2 = rf(ctx, source, ec)
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
//   - ctx context.Context
//   - source []byte
//   - ec suite.EncryptionContext
func (_e *MockEncrypter_Expecter) Encrypt(ctx interface{}, source interface{}, ec interface{}) *MockEncrypter_Encrypt_Call {
	return &MockEncrypter_Encrypt_Call{Call: _e.mock.On("Encrypt", ctx, source, ec)}
}

func (_c *MockEncrypter_Encrypt_Call) Run(run func(ctx context.Context, source []byte, ec suite.EncryptionContext)) *MockEncrypter_Encrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]byte), args[2].(suite.EncryptionContext))
	})
	return _c
}

func (_c *MockEncrypter_Encrypt_Call) Return(_a0 []byte, _a1 format.MessageHeader, _a2 error) *MockEncrypter_Encrypt_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockEncrypter_Encrypt_Call) RunAndReturn(run func(context.Context, []byte, suite.EncryptionContext) ([]byte, format.MessageHeader, error)) *MockEncrypter_Encrypt_Call {
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