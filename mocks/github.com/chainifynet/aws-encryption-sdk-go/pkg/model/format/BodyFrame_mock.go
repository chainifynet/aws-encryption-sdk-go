// Code generated by mockery v2.38.0. DO NOT EDIT.

//go:build mocks

package format

import mock "github.com/stretchr/testify/mock"

// MockBodyFrame is an autogenerated mock type for the BodyFrame type
type MockBodyFrame struct {
	mock.Mock
}

type MockBodyFrame_Expecter struct {
	mock *mock.Mock
}

func (_m *MockBodyFrame) EXPECT() *MockBodyFrame_Expecter {
	return &MockBodyFrame_Expecter{mock: &_m.Mock}
}

// AuthenticationTag provides a mock function with given fields:
func (_m *MockBodyFrame) AuthenticationTag() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AuthenticationTag")
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

// MockBodyFrame_AuthenticationTag_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AuthenticationTag'
type MockBodyFrame_AuthenticationTag_Call struct {
	*mock.Call
}

// AuthenticationTag is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) AuthenticationTag() *MockBodyFrame_AuthenticationTag_Call {
	return &MockBodyFrame_AuthenticationTag_Call{Call: _e.mock.On("AuthenticationTag")}
}

func (_c *MockBodyFrame_AuthenticationTag_Call) Run(run func()) *MockBodyFrame_AuthenticationTag_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_AuthenticationTag_Call) Return(_a0 []byte) *MockBodyFrame_AuthenticationTag_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_AuthenticationTag_Call) RunAndReturn(run func() []byte) *MockBodyFrame_AuthenticationTag_Call {
	_c.Call.Return(run)
	return _c
}

// Bytes provides a mock function with given fields:
func (_m *MockBodyFrame) Bytes() []byte {
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

// MockBodyFrame_Bytes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bytes'
type MockBodyFrame_Bytes_Call struct {
	*mock.Call
}

// Bytes is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) Bytes() *MockBodyFrame_Bytes_Call {
	return &MockBodyFrame_Bytes_Call{Call: _e.mock.On("Bytes")}
}

func (_c *MockBodyFrame_Bytes_Call) Run(run func()) *MockBodyFrame_Bytes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_Bytes_Call) Return(_a0 []byte) *MockBodyFrame_Bytes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_Bytes_Call) RunAndReturn(run func() []byte) *MockBodyFrame_Bytes_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptedContent provides a mock function with given fields:
func (_m *MockBodyFrame) EncryptedContent() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for EncryptedContent")
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

// MockBodyFrame_EncryptedContent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptedContent'
type MockBodyFrame_EncryptedContent_Call struct {
	*mock.Call
}

// EncryptedContent is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) EncryptedContent() *MockBodyFrame_EncryptedContent_Call {
	return &MockBodyFrame_EncryptedContent_Call{Call: _e.mock.On("EncryptedContent")}
}

func (_c *MockBodyFrame_EncryptedContent_Call) Run(run func()) *MockBodyFrame_EncryptedContent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_EncryptedContent_Call) Return(_a0 []byte) *MockBodyFrame_EncryptedContent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_EncryptedContent_Call) RunAndReturn(run func() []byte) *MockBodyFrame_EncryptedContent_Call {
	_c.Call.Return(run)
	return _c
}

// IV provides a mock function with given fields:
func (_m *MockBodyFrame) IV() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for IV")
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

// MockBodyFrame_IV_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IV'
type MockBodyFrame_IV_Call struct {
	*mock.Call
}

// IV is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) IV() *MockBodyFrame_IV_Call {
	return &MockBodyFrame_IV_Call{Call: _e.mock.On("IV")}
}

func (_c *MockBodyFrame_IV_Call) Run(run func()) *MockBodyFrame_IV_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_IV_Call) Return(_a0 []byte) *MockBodyFrame_IV_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_IV_Call) RunAndReturn(run func() []byte) *MockBodyFrame_IV_Call {
	_c.Call.Return(run)
	return _c
}

// IsFinal provides a mock function with given fields:
func (_m *MockBodyFrame) IsFinal() bool {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for IsFinal")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MockBodyFrame_IsFinal_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsFinal'
type MockBodyFrame_IsFinal_Call struct {
	*mock.Call
}

// IsFinal is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) IsFinal() *MockBodyFrame_IsFinal_Call {
	return &MockBodyFrame_IsFinal_Call{Call: _e.mock.On("IsFinal")}
}

func (_c *MockBodyFrame_IsFinal_Call) Run(run func()) *MockBodyFrame_IsFinal_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_IsFinal_Call) Return(_a0 bool) *MockBodyFrame_IsFinal_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_IsFinal_Call) RunAndReturn(run func() bool) *MockBodyFrame_IsFinal_Call {
	_c.Call.Return(run)
	return _c
}

// Len provides a mock function with given fields:
func (_m *MockBodyFrame) Len() int {
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

// MockBodyFrame_Len_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Len'
type MockBodyFrame_Len_Call struct {
	*mock.Call
}

// Len is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) Len() *MockBodyFrame_Len_Call {
	return &MockBodyFrame_Len_Call{Call: _e.mock.On("Len")}
}

func (_c *MockBodyFrame_Len_Call) Run(run func()) *MockBodyFrame_Len_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_Len_Call) Return(_a0 int) *MockBodyFrame_Len_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_Len_Call) RunAndReturn(run func() int) *MockBodyFrame_Len_Call {
	_c.Call.Return(run)
	return _c
}

// SequenceNumber provides a mock function with given fields:
func (_m *MockBodyFrame) SequenceNumber() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for SequenceNumber")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockBodyFrame_SequenceNumber_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SequenceNumber'
type MockBodyFrame_SequenceNumber_Call struct {
	*mock.Call
}

// SequenceNumber is a helper method to define mock.On call
func (_e *MockBodyFrame_Expecter) SequenceNumber() *MockBodyFrame_SequenceNumber_Call {
	return &MockBodyFrame_SequenceNumber_Call{Call: _e.mock.On("SequenceNumber")}
}

func (_c *MockBodyFrame_SequenceNumber_Call) Run(run func()) *MockBodyFrame_SequenceNumber_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockBodyFrame_SequenceNumber_Call) Return(_a0 int) *MockBodyFrame_SequenceNumber_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockBodyFrame_SequenceNumber_Call) RunAndReturn(run func() int) *MockBodyFrame_SequenceNumber_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockBodyFrame creates a new instance of MockBodyFrame. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockBodyFrame(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockBodyFrame {
	mock := &MockBodyFrame{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
