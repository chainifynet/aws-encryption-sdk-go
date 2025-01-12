// Code generated by mockery. DO NOT EDIT.

//go:build mocks

package model

import mock "github.com/stretchr/testify/mock"

// MockCacheHasher is an autogenerated mock type for the CacheHasher type
type MockCacheHasher struct {
	mock.Mock
}

type MockCacheHasher_Expecter struct {
	mock *mock.Mock
}

func (_m *MockCacheHasher) EXPECT() *MockCacheHasher_Expecter {
	return &MockCacheHasher_Expecter{mock: &_m.Mock}
}

// Compute provides a mock function with given fields:
func (_m *MockCacheHasher) Compute() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Compute")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockCacheHasher_Compute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Compute'
type MockCacheHasher_Compute_Call struct {
	*mock.Call
}

// Compute is a helper method to define mock.On call
func (_e *MockCacheHasher_Expecter) Compute() *MockCacheHasher_Compute_Call {
	return &MockCacheHasher_Compute_Call{Call: _e.mock.On("Compute")}
}

func (_c *MockCacheHasher_Compute_Call) Run(run func()) *MockCacheHasher_Compute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockCacheHasher_Compute_Call) Return(_a0 string) *MockCacheHasher_Compute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockCacheHasher_Compute_Call) RunAndReturn(run func() string) *MockCacheHasher_Compute_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: p
func (_m *MockCacheHasher) Update(p []byte) {
	_m.Called(p)
}

// MockCacheHasher_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type MockCacheHasher_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - p []byte
func (_e *MockCacheHasher_Expecter) Update(p interface{}) *MockCacheHasher_Update_Call {
	return &MockCacheHasher_Update_Call{Call: _e.mock.On("Update", p)}
}

func (_c *MockCacheHasher_Update_Call) Run(run func(p []byte)) *MockCacheHasher_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockCacheHasher_Update_Call) Return() *MockCacheHasher_Update_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockCacheHasher_Update_Call) RunAndReturn(run func([]byte)) *MockCacheHasher_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockCacheHasher creates a new instance of MockCacheHasher. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockCacheHasher(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockCacheHasher {
	mock := &MockCacheHasher{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
