// Code generated by mockery v2.49.1. DO NOT EDIT.

//go:build mocks

package model

import (
	context "context"

	model "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	mock "github.com/stretchr/testify/mock"

	suite "github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// MockMasterKey is an autogenerated mock type for the MasterKey type
type MockMasterKey struct {
	mock.Mock
}

type MockMasterKey_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMasterKey) EXPECT() *MockMasterKey_Expecter {
	return &MockMasterKey_Expecter{mock: &_m.Mock}
}

// DecryptDataKey provides a mock function with given fields: ctx, encryptedDataKey, alg, ec
func (_m *MockMasterKey) DecryptDataKey(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	ret := _m.Called(ctx, encryptedDataKey, alg, ec)

	if len(ret) == 0 {
		panic("no return value specified for DecryptDataKey")
	}

	var r0 model.DataKeyI
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, model.EncryptedDataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) (model.DataKeyI, error)); ok {
		return rf(ctx, encryptedDataKey, alg, ec)
	}
	if rf, ok := ret.Get(0).(func(context.Context, model.EncryptedDataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) model.DataKeyI); ok {
		r0 = rf(ctx, encryptedDataKey, alg, ec)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(model.DataKeyI)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, model.EncryptedDataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) error); ok {
		r1 = rf(ctx, encryptedDataKey, alg, ec)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockMasterKey_DecryptDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DecryptDataKey'
type MockMasterKey_DecryptDataKey_Call struct {
	*mock.Call
}

// DecryptDataKey is a helper method to define mock.On call
//   - ctx context.Context
//   - encryptedDataKey model.EncryptedDataKeyI
//   - alg *suite.AlgorithmSuite
//   - ec suite.EncryptionContext
func (_e *MockMasterKey_Expecter) DecryptDataKey(ctx interface{}, encryptedDataKey interface{}, alg interface{}, ec interface{}) *MockMasterKey_DecryptDataKey_Call {
	return &MockMasterKey_DecryptDataKey_Call{Call: _e.mock.On("DecryptDataKey", ctx, encryptedDataKey, alg, ec)}
}

func (_c *MockMasterKey_DecryptDataKey_Call) Run(run func(ctx context.Context, encryptedDataKey model.EncryptedDataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext)) *MockMasterKey_DecryptDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(model.EncryptedDataKeyI), args[2].(*suite.AlgorithmSuite), args[3].(suite.EncryptionContext))
	})
	return _c
}

func (_c *MockMasterKey_DecryptDataKey_Call) Return(_a0 model.DataKeyI, _a1 error) *MockMasterKey_DecryptDataKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockMasterKey_DecryptDataKey_Call) RunAndReturn(run func(context.Context, model.EncryptedDataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) (model.DataKeyI, error)) *MockMasterKey_DecryptDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptDataKey provides a mock function with given fields: ctx, dataKey, alg, ec
func (_m *MockMasterKey) EncryptDataKey(ctx context.Context, dataKey model.DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.EncryptedDataKeyI, error) {
	ret := _m.Called(ctx, dataKey, alg, ec)

	if len(ret) == 0 {
		panic("no return value specified for EncryptDataKey")
	}

	var r0 model.EncryptedDataKeyI
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, model.DataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) (model.EncryptedDataKeyI, error)); ok {
		return rf(ctx, dataKey, alg, ec)
	}
	if rf, ok := ret.Get(0).(func(context.Context, model.DataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) model.EncryptedDataKeyI); ok {
		r0 = rf(ctx, dataKey, alg, ec)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(model.EncryptedDataKeyI)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, model.DataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) error); ok {
		r1 = rf(ctx, dataKey, alg, ec)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockMasterKey_EncryptDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptDataKey'
type MockMasterKey_EncryptDataKey_Call struct {
	*mock.Call
}

// EncryptDataKey is a helper method to define mock.On call
//   - ctx context.Context
//   - dataKey model.DataKeyI
//   - alg *suite.AlgorithmSuite
//   - ec suite.EncryptionContext
func (_e *MockMasterKey_Expecter) EncryptDataKey(ctx interface{}, dataKey interface{}, alg interface{}, ec interface{}) *MockMasterKey_EncryptDataKey_Call {
	return &MockMasterKey_EncryptDataKey_Call{Call: _e.mock.On("EncryptDataKey", ctx, dataKey, alg, ec)}
}

func (_c *MockMasterKey_EncryptDataKey_Call) Run(run func(ctx context.Context, dataKey model.DataKeyI, alg *suite.AlgorithmSuite, ec suite.EncryptionContext)) *MockMasterKey_EncryptDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(model.DataKeyI), args[2].(*suite.AlgorithmSuite), args[3].(suite.EncryptionContext))
	})
	return _c
}

func (_c *MockMasterKey_EncryptDataKey_Call) Return(_a0 model.EncryptedDataKeyI, _a1 error) *MockMasterKey_EncryptDataKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockMasterKey_EncryptDataKey_Call) RunAndReturn(run func(context.Context, model.DataKeyI, *suite.AlgorithmSuite, suite.EncryptionContext) (model.EncryptedDataKeyI, error)) *MockMasterKey_EncryptDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// GenerateDataKey provides a mock function with given fields: ctx, alg, ec
func (_m *MockMasterKey) GenerateDataKey(ctx context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext) (model.DataKeyI, error) {
	ret := _m.Called(ctx, alg, ec)

	if len(ret) == 0 {
		panic("no return value specified for GenerateDataKey")
	}

	var r0 model.DataKeyI
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *suite.AlgorithmSuite, suite.EncryptionContext) (model.DataKeyI, error)); ok {
		return rf(ctx, alg, ec)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *suite.AlgorithmSuite, suite.EncryptionContext) model.DataKeyI); ok {
		r0 = rf(ctx, alg, ec)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(model.DataKeyI)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *suite.AlgorithmSuite, suite.EncryptionContext) error); ok {
		r1 = rf(ctx, alg, ec)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockMasterKey_GenerateDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GenerateDataKey'
type MockMasterKey_GenerateDataKey_Call struct {
	*mock.Call
}

// GenerateDataKey is a helper method to define mock.On call
//   - ctx context.Context
//   - alg *suite.AlgorithmSuite
//   - ec suite.EncryptionContext
func (_e *MockMasterKey_Expecter) GenerateDataKey(ctx interface{}, alg interface{}, ec interface{}) *MockMasterKey_GenerateDataKey_Call {
	return &MockMasterKey_GenerateDataKey_Call{Call: _e.mock.On("GenerateDataKey", ctx, alg, ec)}
}

func (_c *MockMasterKey_GenerateDataKey_Call) Run(run func(ctx context.Context, alg *suite.AlgorithmSuite, ec suite.EncryptionContext)) *MockMasterKey_GenerateDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*suite.AlgorithmSuite), args[2].(suite.EncryptionContext))
	})
	return _c
}

func (_c *MockMasterKey_GenerateDataKey_Call) Return(_a0 model.DataKeyI, _a1 error) *MockMasterKey_GenerateDataKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockMasterKey_GenerateDataKey_Call) RunAndReturn(run func(context.Context, *suite.AlgorithmSuite, suite.EncryptionContext) (model.DataKeyI, error)) *MockMasterKey_GenerateDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// KeyID provides a mock function with given fields:
func (_m *MockMasterKey) KeyID() string {
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

// MockMasterKey_KeyID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyID'
type MockMasterKey_KeyID_Call struct {
	*mock.Call
}

// KeyID is a helper method to define mock.On call
func (_e *MockMasterKey_Expecter) KeyID() *MockMasterKey_KeyID_Call {
	return &MockMasterKey_KeyID_Call{Call: _e.mock.On("KeyID")}
}

func (_c *MockMasterKey_KeyID_Call) Run(run func()) *MockMasterKey_KeyID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMasterKey_KeyID_Call) Return(_a0 string) *MockMasterKey_KeyID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMasterKey_KeyID_Call) RunAndReturn(run func() string) *MockMasterKey_KeyID_Call {
	_c.Call.Return(run)
	return _c
}

// Metadata provides a mock function with given fields:
func (_m *MockMasterKey) Metadata() model.KeyMeta {
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

// MockMasterKey_Metadata_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Metadata'
type MockMasterKey_Metadata_Call struct {
	*mock.Call
}

// Metadata is a helper method to define mock.On call
func (_e *MockMasterKey_Expecter) Metadata() *MockMasterKey_Metadata_Call {
	return &MockMasterKey_Metadata_Call{Call: _e.mock.On("Metadata")}
}

func (_c *MockMasterKey_Metadata_Call) Run(run func()) *MockMasterKey_Metadata_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMasterKey_Metadata_Call) Return(_a0 model.KeyMeta) *MockMasterKey_Metadata_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMasterKey_Metadata_Call) RunAndReturn(run func() model.KeyMeta) *MockMasterKey_Metadata_Call {
	_c.Call.Return(run)
	return _c
}

// OwnsDataKey provides a mock function with given fields: key
func (_m *MockMasterKey) OwnsDataKey(key model.Key) bool {
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

// MockMasterKey_OwnsDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'OwnsDataKey'
type MockMasterKey_OwnsDataKey_Call struct {
	*mock.Call
}

// OwnsDataKey is a helper method to define mock.On call
//   - key model.Key
func (_e *MockMasterKey_Expecter) OwnsDataKey(key interface{}) *MockMasterKey_OwnsDataKey_Call {
	return &MockMasterKey_OwnsDataKey_Call{Call: _e.mock.On("OwnsDataKey", key)}
}

func (_c *MockMasterKey_OwnsDataKey_Call) Run(run func(key model.Key)) *MockMasterKey_OwnsDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(model.Key))
	})
	return _c
}

func (_c *MockMasterKey_OwnsDataKey_Call) Return(_a0 bool) *MockMasterKey_OwnsDataKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMasterKey_OwnsDataKey_Call) RunAndReturn(run func(model.Key) bool) *MockMasterKey_OwnsDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMasterKey creates a new instance of MockMasterKey. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMasterKey(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMasterKey {
	mock := &MockMasterKey{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
