// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package signature

import (
	elliptic "crypto/elliptic"

	mock "github.com/stretchr/testify/mock"
)

// MockVerifier is an autogenerated mock type for the Verifier type
type MockVerifier struct {
	mock.Mock
}

type MockVerifier_Expecter struct {
	mock *mock.Mock
}

func (_m *MockVerifier) EXPECT() *MockVerifier_Expecter {
	return &MockVerifier_Expecter{mock: &_m.Mock}
}

// Curve provides a mock function with given fields:
func (_m *MockVerifier) Curve() elliptic.Curve {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Curve")
	}

	var r0 elliptic.Curve
	if rf, ok := ret.Get(0).(func() elliptic.Curve); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(elliptic.Curve)
		}
	}

	return r0
}

// MockVerifier_Curve_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Curve'
type MockVerifier_Curve_Call struct {
	*mock.Call
}

// Curve is a helper method to define mock.On call
func (_e *MockVerifier_Expecter) Curve() *MockVerifier_Curve_Call {
	return &MockVerifier_Curve_Call{Call: _e.mock.On("Curve")}
}

func (_c *MockVerifier_Curve_Call) Run(run func()) *MockVerifier_Curve_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockVerifier_Curve_Call) Return(_a0 elliptic.Curve) *MockVerifier_Curve_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockVerifier_Curve_Call) RunAndReturn(run func() elliptic.Curve) *MockVerifier_Curve_Call {
	_c.Call.Return(run)
	return _c
}

// LoadECCKey provides a mock function with given fields: data
func (_m *MockVerifier) LoadECCKey(data []byte) error {
	ret := _m.Called(data)

	if len(ret) == 0 {
		panic("no return value specified for LoadECCKey")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func([]byte) error); ok {
		r0 = rf(data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockVerifier_LoadECCKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LoadECCKey'
type MockVerifier_LoadECCKey_Call struct {
	*mock.Call
}

// LoadECCKey is a helper method to define mock.On call
//   - data []byte
func (_e *MockVerifier_Expecter) LoadECCKey(data interface{}) *MockVerifier_LoadECCKey_Call {
	return &MockVerifier_LoadECCKey_Call{Call: _e.mock.On("LoadECCKey", data)}
}

func (_c *MockVerifier_LoadECCKey_Call) Run(run func(data []byte)) *MockVerifier_LoadECCKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockVerifier_LoadECCKey_Call) Return(_a0 error) *MockVerifier_LoadECCKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockVerifier_LoadECCKey_Call) RunAndReturn(run func([]byte) error) *MockVerifier_LoadECCKey_Call {
	_c.Call.Return(run)
	return _c
}

// Sum provides a mock function with given fields:
func (_m *MockVerifier) Sum() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Sum")
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

// MockVerifier_Sum_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Sum'
type MockVerifier_Sum_Call struct {
	*mock.Call
}

// Sum is a helper method to define mock.On call
func (_e *MockVerifier_Expecter) Sum() *MockVerifier_Sum_Call {
	return &MockVerifier_Sum_Call{Call: _e.mock.On("Sum")}
}

func (_c *MockVerifier_Sum_Call) Run(run func()) *MockVerifier_Sum_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockVerifier_Sum_Call) Return(_a0 []byte) *MockVerifier_Sum_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockVerifier_Sum_Call) RunAndReturn(run func() []byte) *MockVerifier_Sum_Call {
	_c.Call.Return(run)
	return _c
}

// Verify provides a mock function with given fields: sig
func (_m *MockVerifier) Verify(sig []byte) error {
	ret := _m.Called(sig)

	if len(ret) == 0 {
		panic("no return value specified for Verify")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func([]byte) error); ok {
		r0 = rf(sig)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockVerifier_Verify_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Verify'
type MockVerifier_Verify_Call struct {
	*mock.Call
}

// Verify is a helper method to define mock.On call
//   - sig []byte
func (_e *MockVerifier_Expecter) Verify(sig interface{}) *MockVerifier_Verify_Call {
	return &MockVerifier_Verify_Call{Call: _e.mock.On("Verify", sig)}
}

func (_c *MockVerifier_Verify_Call) Run(run func(sig []byte)) *MockVerifier_Verify_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockVerifier_Verify_Call) Return(_a0 error) *MockVerifier_Verify_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockVerifier_Verify_Call) RunAndReturn(run func([]byte) error) *MockVerifier_Verify_Call {
	_c.Call.Return(run)
	return _c
}

// Write provides a mock function with given fields: p
func (_m *MockVerifier) Write(p []byte) (int, error) {
	ret := _m.Called(p)

	if len(ret) == 0 {
		panic("no return value specified for Write")
	}

	var r0 int
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) (int, error)); ok {
		return rf(p)
	}
	if rf, ok := ret.Get(0).(func([]byte) int); ok {
		r0 = rf(p)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(p)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockVerifier_Write_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Write'
type MockVerifier_Write_Call struct {
	*mock.Call
}

// Write is a helper method to define mock.On call
//   - p []byte
func (_e *MockVerifier_Expecter) Write(p interface{}) *MockVerifier_Write_Call {
	return &MockVerifier_Write_Call{Call: _e.mock.On("Write", p)}
}

func (_c *MockVerifier_Write_Call) Run(run func(p []byte)) *MockVerifier_Write_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockVerifier_Write_Call) Return(n int, err error) *MockVerifier_Write_Call {
	_c.Call.Return(n, err)
	return _c
}

func (_c *MockVerifier_Write_Call) RunAndReturn(run func([]byte) (int, error)) *MockVerifier_Write_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockVerifier creates a new instance of MockVerifier. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockVerifier(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockVerifier {
	mock := &MockVerifier{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
