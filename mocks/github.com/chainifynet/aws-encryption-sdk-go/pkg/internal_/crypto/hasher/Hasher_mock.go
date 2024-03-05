// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package hasher

import (
	elliptic "crypto/elliptic"

	mock "github.com/stretchr/testify/mock"
)

// MockHasher is an autogenerated mock type for the Hasher type
type MockHasher struct {
	mock.Mock
}

type MockHasher_Expecter struct {
	mock *mock.Mock
}

func (_m *MockHasher) EXPECT() *MockHasher_Expecter {
	return &MockHasher_Expecter{mock: &_m.Mock}
}

// Curve provides a mock function with given fields:
func (_m *MockHasher) Curve() elliptic.Curve {
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

// MockHasher_Curve_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Curve'
type MockHasher_Curve_Call struct {
	*mock.Call
}

// Curve is a helper method to define mock.On call
func (_e *MockHasher_Expecter) Curve() *MockHasher_Curve_Call {
	return &MockHasher_Curve_Call{Call: _e.mock.On("Curve")}
}

func (_c *MockHasher_Curve_Call) Run(run func()) *MockHasher_Curve_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockHasher_Curve_Call) Return(_a0 elliptic.Curve) *MockHasher_Curve_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHasher_Curve_Call) RunAndReturn(run func() elliptic.Curve) *MockHasher_Curve_Call {
	_c.Call.Return(run)
	return _c
}

// Sum provides a mock function with given fields:
func (_m *MockHasher) Sum() []byte {
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

// MockHasher_Sum_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Sum'
type MockHasher_Sum_Call struct {
	*mock.Call
}

// Sum is a helper method to define mock.On call
func (_e *MockHasher_Expecter) Sum() *MockHasher_Sum_Call {
	return &MockHasher_Sum_Call{Call: _e.mock.On("Sum")}
}

func (_c *MockHasher_Sum_Call) Run(run func()) *MockHasher_Sum_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockHasher_Sum_Call) Return(_a0 []byte) *MockHasher_Sum_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHasher_Sum_Call) RunAndReturn(run func() []byte) *MockHasher_Sum_Call {
	_c.Call.Return(run)
	return _c
}

// Write provides a mock function with given fields: p
func (_m *MockHasher) Write(p []byte) (int, error) {
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

// MockHasher_Write_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Write'
type MockHasher_Write_Call struct {
	*mock.Call
}

// Write is a helper method to define mock.On call
//   - p []byte
func (_e *MockHasher_Expecter) Write(p interface{}) *MockHasher_Write_Call {
	return &MockHasher_Write_Call{Call: _e.mock.On("Write", p)}
}

func (_c *MockHasher_Write_Call) Run(run func(p []byte)) *MockHasher_Write_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockHasher_Write_Call) Return(n int, err error) *MockHasher_Write_Call {
	_c.Call.Return(n, err)
	return _c
}

func (_c *MockHasher_Write_Call) RunAndReturn(run func([]byte) (int, error)) *MockHasher_Write_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockHasher creates a new instance of MockHasher. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockHasher(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockHasher {
	mock := &MockHasher{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}