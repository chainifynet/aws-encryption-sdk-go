// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package model

import (
	context "context"

	format "github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	mock "github.com/stretchr/testify/mock"
)

// MockDecrypter is an autogenerated mock type for the DecryptionHandler type
type MockDecrypter struct {
	mock.Mock
}

type MockDecrypter_Expecter struct {
	mock *mock.Mock
}

func (_m *MockDecrypter) EXPECT() *MockDecrypter_Expecter {
	return &MockDecrypter_Expecter{mock: &_m.Mock}
}

// Decrypt provides a mock function with given fields: ctx, ciphertext
func (_m *MockDecrypter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, format.MessageHeader, error) {
	ret := _m.Called(ctx, ciphertext)

	if len(ret) == 0 {
		panic("no return value specified for Decrypt")
	}

	var r0 []byte
	var r1 format.MessageHeader
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, []byte) ([]byte, format.MessageHeader, error)); ok {
		return rf(ctx, ciphertext)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []byte) []byte); ok {
		r0 = rf(ctx, ciphertext)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []byte) format.MessageHeader); ok {
		r1 = rf(ctx, ciphertext)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(format.MessageHeader)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, []byte) error); ok {
		r2 = rf(ctx, ciphertext)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockDecrypter_Decrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Decrypt'
type MockDecrypter_Decrypt_Call struct {
	*mock.Call
}

// Decrypt is a helper method to define mock.On call
//   - ctx context.Context
//   - ciphertext []byte
func (_e *MockDecrypter_Expecter) Decrypt(ctx interface{}, ciphertext interface{}) *MockDecrypter_Decrypt_Call {
	return &MockDecrypter_Decrypt_Call{Call: _e.mock.On("Decrypt", ctx, ciphertext)}
}

func (_c *MockDecrypter_Decrypt_Call) Run(run func(ctx context.Context, ciphertext []byte)) *MockDecrypter_Decrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]byte))
	})
	return _c
}

func (_c *MockDecrypter_Decrypt_Call) Return(_a0 []byte, _a1 format.MessageHeader, _a2 error) *MockDecrypter_Decrypt_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockDecrypter_Decrypt_Call) RunAndReturn(run func(context.Context, []byte) ([]byte, format.MessageHeader, error)) *MockDecrypter_Decrypt_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockDecrypter creates a new instance of MockDecrypter. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockDecrypter(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockDecrypter {
	mock := &MockDecrypter{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}