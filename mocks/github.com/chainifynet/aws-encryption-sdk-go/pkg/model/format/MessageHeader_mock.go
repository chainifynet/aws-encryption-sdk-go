// Code generated by mockery v2.42.0. DO NOT EDIT.

//go:build mocks

package format

import (
	format "github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	mock "github.com/stretchr/testify/mock"

	suite "github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// MockMessageHeader is an autogenerated mock type for the MessageHeader type
type MockMessageHeader struct {
	mock.Mock
}

type MockMessageHeader_Expecter struct {
	mock *mock.Mock
}

func (_m *MockMessageHeader) EXPECT() *MockMessageHeader_Expecter {
	return &MockMessageHeader_Expecter{mock: &_m.Mock}
}

// AADData provides a mock function with given fields:
func (_m *MockMessageHeader) AADData() format.MessageAAD {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AADData")
	}

	var r0 format.MessageAAD
	if rf, ok := ret.Get(0).(func() format.MessageAAD); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(format.MessageAAD)
		}
	}

	return r0
}

// MockMessageHeader_AADData_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AADData'
type MockMessageHeader_AADData_Call struct {
	*mock.Call
}

// AADData is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) AADData() *MockMessageHeader_AADData_Call {
	return &MockMessageHeader_AADData_Call{Call: _e.mock.On("AADData")}
}

func (_c *MockMessageHeader_AADData_Call) Run(run func()) *MockMessageHeader_AADData_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_AADData_Call) Return(_a0 format.MessageAAD) *MockMessageHeader_AADData_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_AADData_Call) RunAndReturn(run func() format.MessageAAD) *MockMessageHeader_AADData_Call {
	_c.Call.Return(run)
	return _c
}

// AADLength provides a mock function with given fields:
func (_m *MockMessageHeader) AADLength() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AADLength")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockMessageHeader_AADLength_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AADLength'
type MockMessageHeader_AADLength_Call struct {
	*mock.Call
}

// AADLength is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) AADLength() *MockMessageHeader_AADLength_Call {
	return &MockMessageHeader_AADLength_Call{Call: _e.mock.On("AADLength")}
}

func (_c *MockMessageHeader_AADLength_Call) Run(run func()) *MockMessageHeader_AADLength_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_AADLength_Call) Return(_a0 int) *MockMessageHeader_AADLength_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_AADLength_Call) RunAndReturn(run func() int) *MockMessageHeader_AADLength_Call {
	_c.Call.Return(run)
	return _c
}

// AlgorithmSuite provides a mock function with given fields:
func (_m *MockMessageHeader) AlgorithmSuite() *suite.AlgorithmSuite {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AlgorithmSuite")
	}

	var r0 *suite.AlgorithmSuite
	if rf, ok := ret.Get(0).(func() *suite.AlgorithmSuite); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*suite.AlgorithmSuite)
		}
	}

	return r0
}

// MockMessageHeader_AlgorithmSuite_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AlgorithmSuite'
type MockMessageHeader_AlgorithmSuite_Call struct {
	*mock.Call
}

// AlgorithmSuite is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) AlgorithmSuite() *MockMessageHeader_AlgorithmSuite_Call {
	return &MockMessageHeader_AlgorithmSuite_Call{Call: _e.mock.On("AlgorithmSuite")}
}

func (_c *MockMessageHeader_AlgorithmSuite_Call) Run(run func()) *MockMessageHeader_AlgorithmSuite_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_AlgorithmSuite_Call) Return(_a0 *suite.AlgorithmSuite) *MockMessageHeader_AlgorithmSuite_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_AlgorithmSuite_Call) RunAndReturn(run func() *suite.AlgorithmSuite) *MockMessageHeader_AlgorithmSuite_Call {
	_c.Call.Return(run)
	return _c
}

// AlgorithmSuiteData provides a mock function with given fields:
func (_m *MockMessageHeader) AlgorithmSuiteData() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AlgorithmSuiteData")
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

// MockMessageHeader_AlgorithmSuiteData_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AlgorithmSuiteData'
type MockMessageHeader_AlgorithmSuiteData_Call struct {
	*mock.Call
}

// AlgorithmSuiteData is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) AlgorithmSuiteData() *MockMessageHeader_AlgorithmSuiteData_Call {
	return &MockMessageHeader_AlgorithmSuiteData_Call{Call: _e.mock.On("AlgorithmSuiteData")}
}

func (_c *MockMessageHeader_AlgorithmSuiteData_Call) Run(run func()) *MockMessageHeader_AlgorithmSuiteData_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_AlgorithmSuiteData_Call) Return(_a0 []byte) *MockMessageHeader_AlgorithmSuiteData_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_AlgorithmSuiteData_Call) RunAndReturn(run func() []byte) *MockMessageHeader_AlgorithmSuiteData_Call {
	_c.Call.Return(run)
	return _c
}

// Bytes provides a mock function with given fields:
func (_m *MockMessageHeader) Bytes() []byte {
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

// MockMessageHeader_Bytes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bytes'
type MockMessageHeader_Bytes_Call struct {
	*mock.Call
}

// Bytes is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) Bytes() *MockMessageHeader_Bytes_Call {
	return &MockMessageHeader_Bytes_Call{Call: _e.mock.On("Bytes")}
}

func (_c *MockMessageHeader_Bytes_Call) Run(run func()) *MockMessageHeader_Bytes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_Bytes_Call) Return(_a0 []byte) *MockMessageHeader_Bytes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_Bytes_Call) RunAndReturn(run func() []byte) *MockMessageHeader_Bytes_Call {
	_c.Call.Return(run)
	return _c
}

// ContentType provides a mock function with given fields:
func (_m *MockMessageHeader) ContentType() suite.ContentType {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ContentType")
	}

	var r0 suite.ContentType
	if rf, ok := ret.Get(0).(func() suite.ContentType); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(suite.ContentType)
	}

	return r0
}

// MockMessageHeader_ContentType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ContentType'
type MockMessageHeader_ContentType_Call struct {
	*mock.Call
}

// ContentType is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) ContentType() *MockMessageHeader_ContentType_Call {
	return &MockMessageHeader_ContentType_Call{Call: _e.mock.On("ContentType")}
}

func (_c *MockMessageHeader_ContentType_Call) Run(run func()) *MockMessageHeader_ContentType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_ContentType_Call) Return(_a0 suite.ContentType) *MockMessageHeader_ContentType_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_ContentType_Call) RunAndReturn(run func() suite.ContentType) *MockMessageHeader_ContentType_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptedDataKeyCount provides a mock function with given fields:
func (_m *MockMessageHeader) EncryptedDataKeyCount() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for EncryptedDataKeyCount")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockMessageHeader_EncryptedDataKeyCount_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptedDataKeyCount'
type MockMessageHeader_EncryptedDataKeyCount_Call struct {
	*mock.Call
}

// EncryptedDataKeyCount is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) EncryptedDataKeyCount() *MockMessageHeader_EncryptedDataKeyCount_Call {
	return &MockMessageHeader_EncryptedDataKeyCount_Call{Call: _e.mock.On("EncryptedDataKeyCount")}
}

func (_c *MockMessageHeader_EncryptedDataKeyCount_Call) Run(run func()) *MockMessageHeader_EncryptedDataKeyCount_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_EncryptedDataKeyCount_Call) Return(_a0 int) *MockMessageHeader_EncryptedDataKeyCount_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_EncryptedDataKeyCount_Call) RunAndReturn(run func() int) *MockMessageHeader_EncryptedDataKeyCount_Call {
	_c.Call.Return(run)
	return _c
}

// EncryptedDataKeys provides a mock function with given fields:
func (_m *MockMessageHeader) EncryptedDataKeys() []format.MessageEDK {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for EncryptedDataKeys")
	}

	var r0 []format.MessageEDK
	if rf, ok := ret.Get(0).(func() []format.MessageEDK); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]format.MessageEDK)
		}
	}

	return r0
}

// MockMessageHeader_EncryptedDataKeys_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EncryptedDataKeys'
type MockMessageHeader_EncryptedDataKeys_Call struct {
	*mock.Call
}

// EncryptedDataKeys is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) EncryptedDataKeys() *MockMessageHeader_EncryptedDataKeys_Call {
	return &MockMessageHeader_EncryptedDataKeys_Call{Call: _e.mock.On("EncryptedDataKeys")}
}

func (_c *MockMessageHeader_EncryptedDataKeys_Call) Run(run func()) *MockMessageHeader_EncryptedDataKeys_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_EncryptedDataKeys_Call) Return(_a0 []format.MessageEDK) *MockMessageHeader_EncryptedDataKeys_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_EncryptedDataKeys_Call) RunAndReturn(run func() []format.MessageEDK) *MockMessageHeader_EncryptedDataKeys_Call {
	_c.Call.Return(run)
	return _c
}

// FrameLength provides a mock function with given fields:
func (_m *MockMessageHeader) FrameLength() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for FrameLength")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockMessageHeader_FrameLength_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FrameLength'
type MockMessageHeader_FrameLength_Call struct {
	*mock.Call
}

// FrameLength is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) FrameLength() *MockMessageHeader_FrameLength_Call {
	return &MockMessageHeader_FrameLength_Call{Call: _e.mock.On("FrameLength")}
}

func (_c *MockMessageHeader_FrameLength_Call) Run(run func()) *MockMessageHeader_FrameLength_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_FrameLength_Call) Return(_a0 int) *MockMessageHeader_FrameLength_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_FrameLength_Call) RunAndReturn(run func() int) *MockMessageHeader_FrameLength_Call {
	_c.Call.Return(run)
	return _c
}

// IVLength provides a mock function with given fields:
func (_m *MockMessageHeader) IVLength() int {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for IVLength")
	}

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// MockMessageHeader_IVLength_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IVLength'
type MockMessageHeader_IVLength_Call struct {
	*mock.Call
}

// IVLength is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) IVLength() *MockMessageHeader_IVLength_Call {
	return &MockMessageHeader_IVLength_Call{Call: _e.mock.On("IVLength")}
}

func (_c *MockMessageHeader_IVLength_Call) Run(run func()) *MockMessageHeader_IVLength_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_IVLength_Call) Return(_a0 int) *MockMessageHeader_IVLength_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_IVLength_Call) RunAndReturn(run func() int) *MockMessageHeader_IVLength_Call {
	_c.Call.Return(run)
	return _c
}

// Len provides a mock function with given fields:
func (_m *MockMessageHeader) Len() int {
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

// MockMessageHeader_Len_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Len'
type MockMessageHeader_Len_Call struct {
	*mock.Call
}

// Len is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) Len() *MockMessageHeader_Len_Call {
	return &MockMessageHeader_Len_Call{Call: _e.mock.On("Len")}
}

func (_c *MockMessageHeader_Len_Call) Run(run func()) *MockMessageHeader_Len_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_Len_Call) Return(_a0 int) *MockMessageHeader_Len_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_Len_Call) RunAndReturn(run func() int) *MockMessageHeader_Len_Call {
	_c.Call.Return(run)
	return _c
}

// MessageID provides a mock function with given fields:
func (_m *MockMessageHeader) MessageID() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MessageID")
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

// MockMessageHeader_MessageID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MessageID'
type MockMessageHeader_MessageID_Call struct {
	*mock.Call
}

// MessageID is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) MessageID() *MockMessageHeader_MessageID_Call {
	return &MockMessageHeader_MessageID_Call{Call: _e.mock.On("MessageID")}
}

func (_c *MockMessageHeader_MessageID_Call) Run(run func()) *MockMessageHeader_MessageID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_MessageID_Call) Return(_a0 []byte) *MockMessageHeader_MessageID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_MessageID_Call) RunAndReturn(run func() []byte) *MockMessageHeader_MessageID_Call {
	_c.Call.Return(run)
	return _c
}

// Reserved provides a mock function with given fields:
func (_m *MockMessageHeader) Reserved() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Reserved")
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

// MockMessageHeader_Reserved_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Reserved'
type MockMessageHeader_Reserved_Call struct {
	*mock.Call
}

// Reserved is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) Reserved() *MockMessageHeader_Reserved_Call {
	return &MockMessageHeader_Reserved_Call{Call: _e.mock.On("Reserved")}
}

func (_c *MockMessageHeader_Reserved_Call) Run(run func()) *MockMessageHeader_Reserved_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_Reserved_Call) Return(_a0 []byte) *MockMessageHeader_Reserved_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_Reserved_Call) RunAndReturn(run func() []byte) *MockMessageHeader_Reserved_Call {
	_c.Call.Return(run)
	return _c
}

// Type provides a mock function with given fields:
func (_m *MockMessageHeader) Type() format.MessageType {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Type")
	}

	var r0 format.MessageType
	if rf, ok := ret.Get(0).(func() format.MessageType); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(format.MessageType)
	}

	return r0
}

// MockMessageHeader_Type_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Type'
type MockMessageHeader_Type_Call struct {
	*mock.Call
}

// Type is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) Type() *MockMessageHeader_Type_Call {
	return &MockMessageHeader_Type_Call{Call: _e.mock.On("Type")}
}

func (_c *MockMessageHeader_Type_Call) Run(run func()) *MockMessageHeader_Type_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_Type_Call) Return(_a0 format.MessageType) *MockMessageHeader_Type_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_Type_Call) RunAndReturn(run func() format.MessageType) *MockMessageHeader_Type_Call {
	_c.Call.Return(run)
	return _c
}

// Version provides a mock function with given fields:
func (_m *MockMessageHeader) Version() suite.MessageFormatVersion {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Version")
	}

	var r0 suite.MessageFormatVersion
	if rf, ok := ret.Get(0).(func() suite.MessageFormatVersion); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(suite.MessageFormatVersion)
	}

	return r0
}

// MockMessageHeader_Version_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Version'
type MockMessageHeader_Version_Call struct {
	*mock.Call
}

// Version is a helper method to define mock.On call
func (_e *MockMessageHeader_Expecter) Version() *MockMessageHeader_Version_Call {
	return &MockMessageHeader_Version_Call{Call: _e.mock.On("Version")}
}

func (_c *MockMessageHeader_Version_Call) Run(run func()) *MockMessageHeader_Version_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockMessageHeader_Version_Call) Return(_a0 suite.MessageFormatVersion) *MockMessageHeader_Version_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockMessageHeader_Version_Call) RunAndReturn(run func() suite.MessageFormatVersion) *MockMessageHeader_Version_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockMessageHeader creates a new instance of MockMessageHeader. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockMessageHeader(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockMessageHeader {
	mock := &MockMessageHeader{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
