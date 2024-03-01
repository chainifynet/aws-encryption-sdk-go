// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package format

import mock "github.com/stretchr/testify/mock"

// MockMessageEDK is an autogenerated mock type for the MessageEDK type
type MockMessageEDK struct {
	mock.Mock
}

type MockMessageEDK_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMessageEDK) EXPECT() *MockMessageEDK_Expecter {
	return &MockMessageEDK_Expecter{mock: &_m.Mock}
}

// Bytes provides a mock function with given fields:
func (_m *MockMessageEDK) Bytes() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Bytes")
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

// MockMessageEDK_Bytes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bytes'
type MockMessageEDK_Bytes_Call struct {
	*mock.Call
}

// Bytes is a helper method to define mock.On call
func (_e *MockMessageEDK_Expecter) Bytes() *MockMessageEDK_Bytes_Call {
	return &MockMessageEDK_Bytes_Call{Call: _e.mock.On("Bytes")}
}

func (_c *MockMessageEDK_Bytes_Call) Run(run func()) *MockMessageEDK_Bytes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageEDK_Bytes_Call) Return(_a0 []byte) *MockMessageEDK_Bytes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageEDK_Bytes_Call) RunAndReturn(run func() []byte) *MockMessageEDK_Bytes_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptedDataKey provides a mock function with given fields:
func (_m *MockMessageEDK) EncryptedDataKey() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for EncryptedDataKey")
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

// MockMessageEDK_EncryptedDataKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptedDataKey'
type MockMessageEDK_EncryptedDataKey_Call struct {
	*mock.Call
}

// EncryptedDataKey is a helper method to define mock.On call
func (_e *MockMessageEDK_Expecter) EncryptedDataKey() *MockMessageEDK_EncryptedDataKey_Call {
	return &MockMessageEDK_EncryptedDataKey_Call{Call: _e.mock.On("EncryptedDataKey")}
}

func (_c *MockMessageEDK_EncryptedDataKey_Call) Run(run func()) *MockMessageEDK_EncryptedDataKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageEDK_EncryptedDataKey_Call) Return(_a0 []byte) *MockMessageEDK_EncryptedDataKey_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageEDK_EncryptedDataKey_Call) RunAndReturn(run func() []byte) *MockMessageEDK_EncryptedDataKey_Call {
	_c.Call.Return(run)
	return _c
}

// Len provides a mock function with given fields:
func (_m *MockMessageEDK) Len() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Len")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockMessageEDK_Len_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Len'
type MockMessageEDK_Len_Call struct {
	*mock.Call
}

// Len is a helper method to define mock.On call
func (_e *MockMessageEDK_Expecter) Len() *MockMessageEDK_Len_Call {
	return &MockMessageEDK_Len_Call{Call: _e.mock.On("Len")}
}

func (_c *MockMessageEDK_Len_Call) Run(run func()) *MockMessageEDK_Len_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageEDK_Len_Call) Return(_a0 int) *MockMessageEDK_Len_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageEDK_Len_Call) RunAndReturn(run func() int) *MockMessageEDK_Len_Call {
	_c.Call.Return(run)
	return _c
}

// ProviderID provides a mock function with given fields:
func (_m *MockMessageEDK) ProviderID() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ProviderID")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockMessageEDK_ProviderID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ProviderID'
type MockMessageEDK_ProviderID_Call struct {
	*mock.Call
}

// ProviderID is a helper method to define mock.On call
func (_e *MockMessageEDK_Expecter) ProviderID() *MockMessageEDK_ProviderID_Call {
	return &MockMessageEDK_ProviderID_Call{Call: _e.mock.On("ProviderID")}
}

func (_c *MockMessageEDK_ProviderID_Call) Run(run func()) *MockMessageEDK_ProviderID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageEDK_ProviderID_Call) Return(_a0 string) *MockMessageEDK_ProviderID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageEDK_ProviderID_Call) RunAndReturn(run func() string) *MockMessageEDK_ProviderID_Call {
	_c.Call.Return(run)
	return _c
}

// ProviderInfo provides a mock function with given fields:
func (_m *MockMessageEDK) ProviderInfo() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ProviderInfo")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockMessageEDK_ProviderInfo_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ProviderInfo'
type MockMessageEDK_ProviderInfo_Call struct {
	*mock.Call
}

// ProviderInfo is a helper method to define mock.On call
func (_e *MockMessageEDK_Expecter) ProviderInfo() *MockMessageEDK_ProviderInfo_Call {
	return &MockMessageEDK_ProviderInfo_Call{Call: _e.mock.On("ProviderInfo")}
}

func (_c *MockMessageEDK_ProviderInfo_Call) Run(run func()) *MockMessageEDK_ProviderInfo_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageEDK_ProviderInfo_Call) Return(_a0 string) *MockMessageEDK_ProviderInfo_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageEDK_ProviderInfo_Call) RunAndReturn(run func() string) *MockMessageEDK_ProviderInfo_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMessageEDK creates a new instance of MockMessageEDK. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMessageEDK(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMessageEDK {
	mock := &MockMessageEDK{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
