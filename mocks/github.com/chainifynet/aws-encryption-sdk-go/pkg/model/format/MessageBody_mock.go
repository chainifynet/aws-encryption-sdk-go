// Code generated by mockery v2.49.1. DO NOT EDIT.

//go:build mocks

package format

import (
	format "github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	mock "github.com/stretchr/testify/mock"
)

// MockMessageBody is an autogenerated mock type for the MessageBody type
type MockMessageBody struct {
	mock.Mock
}

type MockMessageBody_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMessageBody) EXPECT() *MockMessageBody_Expecter {
	return &MockMessageBody_Expecter{mock: &_m.Mock}
}

// AddFrame provides a mock function with given fields: final, seqNum, IV, contentLength, ciphertext, authTag
func (_m *MockMessageBody) AddFrame(final bool, seqNum int, IV []byte, contentLength int, ciphertext []byte, authTag []byte) error {
	ret := _m.Called(final, seqNum, IV, contentLength, ciphertext, authTag)

	if len(ret) == 0 {
		panic("no return value specified for AddFrame")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(bool, int, []byte, int, []byte, []byte) error); ok {
		r0 = rf(final, seqNum, IV, contentLength, ciphertext, authTag)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockMessageBody_AddFrame_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddFrame'
type MockMessageBody_AddFrame_Call struct {
	*mock.Call
}

// AddFrame is a helper method to define mock.On call
//   - final bool
//   - seqNum int
//   - IV []byte
//   - contentLength int
//   - ciphertext []byte
//   - authTag []byte
func (_e *MockMessageBody_Expecter) AddFrame(final interface{}, seqNum interface{}, IV interface{}, contentLength interface{}, ciphertext interface{}, authTag interface{}) *MockMessageBody_AddFrame_Call {
	return &MockMessageBody_AddFrame_Call{Call: _e.mock.On("AddFrame", final, seqNum, IV, contentLength, ciphertext, authTag)}
}

func (_c *MockMessageBody_AddFrame_Call) Run(run func(final bool, seqNum int, IV []byte, contentLength int, ciphertext []byte, authTag []byte)) *MockMessageBody_AddFrame_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(bool), args[1].(int), args[2].([]byte), args[3].(int), args[4].([]byte), args[5].([]byte))
	})
	return _c
}

func (_c *MockMessageBody_AddFrame_Call) Return(_a0 error) *MockMessageBody_AddFrame_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageBody_AddFrame_Call) RunAndReturn(run func(bool, int, []byte, int, []byte, []byte) error) *MockMessageBody_AddFrame_Call {
	_c.Call.Return(run)
	return _c
}

// Bytes provides a mock function with given fields:
func (_m *MockMessageBody) Bytes() []byte {
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

// MockMessageBody_Bytes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bytes'
type MockMessageBody_Bytes_Call struct {
	*mock.Call
}

// Bytes is a helper method to define mock.On call
func (_e *MockMessageBody_Expecter) Bytes() *MockMessageBody_Bytes_Call {
	return &MockMessageBody_Bytes_Call{Call: _e.mock.On("Bytes")}
}

func (_c *MockMessageBody_Bytes_Call) Run(run func()) *MockMessageBody_Bytes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageBody_Bytes_Call) Return(_a0 []byte) *MockMessageBody_Bytes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageBody_Bytes_Call) RunAndReturn(run func() []byte) *MockMessageBody_Bytes_Call {
	_c.Call.Return(run)
	return _c
}

// Frames provides a mock function with given fields:
func (_m *MockMessageBody) Frames() []format.BodyFrame {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Frames")
	}

	var r0 []format.BodyFrame
	if rf, ok := ret.Get(0).(func() []format.BodyFrame); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]format.BodyFrame)
		}
	}

	return r0
}

// MockMessageBody_Frames_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Frames'
type MockMessageBody_Frames_Call struct {
	*mock.Call
}

// Frames is a helper method to define mock.On call
func (_e *MockMessageBody_Expecter) Frames() *MockMessageBody_Frames_Call {
	return &MockMessageBody_Frames_Call{Call: _e.mock.On("Frames")}
}

func (_c *MockMessageBody_Frames_Call) Run(run func()) *MockMessageBody_Frames_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageBody_Frames_Call) Return(_a0 []format.BodyFrame) *MockMessageBody_Frames_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageBody_Frames_Call) RunAndReturn(run func() []format.BodyFrame) *MockMessageBody_Frames_Call {
	_c.Call.Return(run)
	return _c
}

// Len provides a mock function with given fields:
func (_m *MockMessageBody) Len() int {
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

// MockMessageBody_Len_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Len'
type MockMessageBody_Len_Call struct {
	*mock.Call
}

// Len is a helper method to define mock.On call
func (_e *MockMessageBody_Expecter) Len() *MockMessageBody_Len_Call {
	return &MockMessageBody_Len_Call{Call: _e.mock.On("Len")}
}

func (_c *MockMessageBody_Len_Call) Run(run func()) *MockMessageBody_Len_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageBody_Len_Call) Return(_a0 int) *MockMessageBody_Len_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageBody_Len_Call) RunAndReturn(run func() int) *MockMessageBody_Len_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMessageBody creates a new instance of MockMessageBody. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMessageBody(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMessageBody {
	mock := &MockMessageBody{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
