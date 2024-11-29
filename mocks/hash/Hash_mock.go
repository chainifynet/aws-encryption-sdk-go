// Code generated by mockery v2.49.1. DO NOT EDIT.

//go:build mocks

package hash

import mock "github.com/stretchr/testify/mock"

// MockHash is an autogenerated mock type for the Hash type
type MockHash struct {
	mock.Mock
}

type MockHash_Expecter struct {
	mock *mock.Mock
}

func (_m *MockHash) EXPECT() *MockHash_Expecter {
	return &MockHash_Expecter{mock: &_m.Mock}
}

// BlockSize provides a mock function with given fields:
func (_m *MockHash) BlockSize() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for BlockSize")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockHash_BlockSize_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BlockSize'
type MockHash_BlockSize_Call struct {
	*mock.Call
}

// BlockSize is a helper method to define mock.On call
func (_e *MockHash_Expecter) BlockSize() *MockHash_BlockSize_Call {
	return &MockHash_BlockSize_Call{Call: _e.mock.On("BlockSize")}
}

func (_c *MockHash_BlockSize_Call) Run(run func()) *MockHash_BlockSize_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockHash_BlockSize_Call) Return(_a0 int) *MockHash_BlockSize_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHash_BlockSize_Call) RunAndReturn(run func() int) *MockHash_BlockSize_Call {
	_c.Call.Return(run)
	return _c
}

// Reset provides a mock function with given fields:
func (_m *MockHash) Reset() {
	_m.Called()
}

// MockHash_Reset_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Reset'
type MockHash_Reset_Call struct {
	*mock.Call
}

// Reset is a helper method to define mock.On call
func (_e *MockHash_Expecter) Reset() *MockHash_Reset_Call {
	return &MockHash_Reset_Call{Call: _e.mock.On("Reset")}
}

func (_c *MockHash_Reset_Call) Run(run func()) *MockHash_Reset_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockHash_Reset_Call) Return() *MockHash_Reset_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockHash_Reset_Call) RunAndReturn(run func()) *MockHash_Reset_Call {
	_c.Call.Return(run)
	return _c
}

// Size provides a mock function with given fields:
func (_m *MockHash) Size() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Size")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockHash_Size_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Size'
type MockHash_Size_Call struct {
	*mock.Call
}

// Size is a helper method to define mock.On call
func (_e *MockHash_Expecter) Size() *MockHash_Size_Call {
	return &MockHash_Size_Call{Call: _e.mock.On("Size")}
}

func (_c *MockHash_Size_Call) Run(run func()) *MockHash_Size_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockHash_Size_Call) Return(_a0 int) *MockHash_Size_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHash_Size_Call) RunAndReturn(run func() int) *MockHash_Size_Call {
	_c.Call.Return(run)
	return _c
}

// Sum provides a mock function with given fields: b
func (_m *MockHash) Sum(b []byte) []byte {
	ret := _m.Called(b)

	if len(ret) == 0 {
		panic("no return value specified for Sum")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func([]byte) []byte); ok {
		r0 = rf(b)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// MockHash_Sum_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Sum'
type MockHash_Sum_Call struct {
	*mock.Call
}

// Sum is a helper method to define mock.On call
//   - b []byte
func (_e *MockHash_Expecter) Sum(b interface{}) *MockHash_Sum_Call {
	return &MockHash_Sum_Call{Call: _e.mock.On("Sum", b)}
}

func (_c *MockHash_Sum_Call) Run(run func(b []byte)) *MockHash_Sum_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockHash_Sum_Call) Return(_a0 []byte) *MockHash_Sum_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockHash_Sum_Call) RunAndReturn(run func([]byte) []byte) *MockHash_Sum_Call {
	_c.Call.Return(run)
	return _c
}

// Write provides a mock function with given fields: p
func (_m *MockHash) Write(p []byte) (int, error) {
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

// MockHash_Write_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Write'
type MockHash_Write_Call struct {
	*mock.Call
}

// Write is a helper method to define mock.On call
//   - p []byte
func (_e *MockHash_Expecter) Write(p interface{}) *MockHash_Write_Call {
	return &MockHash_Write_Call{Call: _e.mock.On("Write", p)}
}

func (_c *MockHash_Write_Call) Run(run func(p []byte)) *MockHash_Write_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockHash_Write_Call) Return(n int, err error) *MockHash_Write_Call {
	_c.Call.Return(n, err)
	return _c
}

func (_c *MockHash_Write_Call) RunAndReturn(run func([]byte) (int, error)) *MockHash_Write_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockHash creates a new instance of MockHash. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockHash(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockHash {
	mock := &MockHash{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
