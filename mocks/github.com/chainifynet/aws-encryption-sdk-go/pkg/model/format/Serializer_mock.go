// Code generated by mockery v2.38.0. DO NOT EDIT.

//go:build mocks

package format

import (
	format "github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	mock "github.com/stretchr/testify/mock"

	suite "github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// MockSerializer is an autogenerated mock type for the Serializer type
type MockSerializer struct {
	mock.Mock
}

type MockSerializer_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSerializer) EXPECT() *MockSerializer_Expecter {
	return &MockSerializer_Expecter{mock: &_m.Mock}
}

// SerializeBody provides a mock function with given fields: alg, frameLength
func (_m *MockSerializer) SerializeBody(alg *suite.AlgorithmSuite, frameLength int) (format.MessageBody, error) {
	ret := _m.Called(alg, frameLength)

	if len(ret) == 0 {
		panic("no return value specified for SerializeBody")
	}

	var r0 format.MessageBody
	var r1 error
	if rf, ok := ret.Get(0).(func(*suite.AlgorithmSuite, int) (format.MessageBody, error)); ok {
		return rf(alg, frameLength)
	}
	if rf, ok := ret.Get(0).(func(*suite.AlgorithmSuite, int) format.MessageBody); ok {
		r0 = rf(alg, frameLength)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(format.MessageBody)
		}
	}

	if rf, ok := ret.Get(1).(func(*suite.AlgorithmSuite, int) error); ok {
		r1 = rf(alg, frameLength)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSerializer_SerializeBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SerializeBody'
type MockSerializer_SerializeBody_Call struct {
	*mock.Call
}

// SerializeBody is a helper method to define mock.On call
//   - alg *suite.AlgorithmSuite
//   - frameLength int
func (_e *MockSerializer_Expecter) SerializeBody(alg interface{}, frameLength interface{}) *MockSerializer_SerializeBody_Call {
	return &MockSerializer_SerializeBody_Call{Call: _e.mock.On("SerializeBody", alg, frameLength)}
}

func (_c *MockSerializer_SerializeBody_Call) Run(run func(alg *suite.AlgorithmSuite, frameLength int)) *MockSerializer_SerializeBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*suite.AlgorithmSuite), args[1].(int))
	})
	return _c
}

func (_c *MockSerializer_SerializeBody_Call) Return(_a0 format.MessageBody, _a1 error) *MockSerializer_SerializeBody_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSerializer_SerializeBody_Call) RunAndReturn(run func(*suite.AlgorithmSuite, int) (format.MessageBody, error)) *MockSerializer_SerializeBody_Call {
	_c.Call.Return(run)
	return _c
}

// SerializeFooter provides a mock function with given fields: alg, signature
func (_m *MockSerializer) SerializeFooter(alg *suite.AlgorithmSuite, signature []byte) (format.MessageFooter, error) {
	ret := _m.Called(alg, signature)

	if len(ret) == 0 {
		panic("no return value specified for SerializeFooter")
	}

	var r0 format.MessageFooter
	var r1 error
	if rf, ok := ret.Get(0).(func(*suite.AlgorithmSuite, []byte) (format.MessageFooter, error)); ok {
		return rf(alg, signature)
	}
	if rf, ok := ret.Get(0).(func(*suite.AlgorithmSuite, []byte) format.MessageFooter); ok {
		r0 = rf(alg, signature)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(format.MessageFooter)
		}
	}

	if rf, ok := ret.Get(1).(func(*suite.AlgorithmSuite, []byte) error); ok {
		r1 = rf(alg, signature)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSerializer_SerializeFooter_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SerializeFooter'
type MockSerializer_SerializeFooter_Call struct {
	*mock.Call
}

// SerializeFooter is a helper method to define mock.On call
//   - alg *suite.AlgorithmSuite
//   - signature []byte
func (_e *MockSerializer_Expecter) SerializeFooter(alg interface{}, signature interface{}) *MockSerializer_SerializeFooter_Call {
	return &MockSerializer_SerializeFooter_Call{Call: _e.mock.On("SerializeFooter", alg, signature)}
}

func (_c *MockSerializer_SerializeFooter_Call) Run(run func(alg *suite.AlgorithmSuite, signature []byte)) *MockSerializer_SerializeFooter_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*suite.AlgorithmSuite), args[1].([]byte))
	})
	return _c
}

func (_c *MockSerializer_SerializeFooter_Call) Return(_a0 format.MessageFooter, _a1 error) *MockSerializer_SerializeFooter_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSerializer_SerializeFooter_Call) RunAndReturn(run func(*suite.AlgorithmSuite, []byte) (format.MessageFooter, error)) *MockSerializer_SerializeFooter_Call {
	_c.Call.Return(run)
	return _c
}

// SerializeHeader provides a mock function with given fields: p
func (_m *MockSerializer) SerializeHeader(p format.HeaderParams) (format.MessageHeader, error) {
	ret := _m.Called(p)

	if len(ret) == 0 {
		panic("no return value specified for SerializeHeader")
	}

	var r0 format.MessageHeader
	var r1 error
	if rf, ok := ret.Get(0).(func(format.HeaderParams) (format.MessageHeader, error)); ok {
		return rf(p)
	}
	if rf, ok := ret.Get(0).(func(format.HeaderParams) format.MessageHeader); ok {
		r0 = rf(p)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(format.MessageHeader)
		}
	}

	if rf, ok := ret.Get(1).(func(format.HeaderParams) error); ok {
		r1 = rf(p)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSerializer_SerializeHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SerializeHeader'
type MockSerializer_SerializeHeader_Call struct {
	*mock.Call
}

// SerializeHeader is a helper method to define mock.On call
//   - p format.HeaderParams
func (_e *MockSerializer_Expecter) SerializeHeader(p interface{}) *MockSerializer_SerializeHeader_Call {
	return &MockSerializer_SerializeHeader_Call{Call: _e.mock.On("SerializeHeader", p)}
}

func (_c *MockSerializer_SerializeHeader_Call) Run(run func(p format.HeaderParams)) *MockSerializer_SerializeHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(format.HeaderParams))
	})
	return _c
}

func (_c *MockSerializer_SerializeHeader_Call) Return(_a0 format.MessageHeader, _a1 error) *MockSerializer_SerializeHeader_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSerializer_SerializeHeader_Call) RunAndReturn(run func(format.HeaderParams) (format.MessageHeader, error)) *MockSerializer_SerializeHeader_Call {
	_c.Call.Return(run)
	return _c
}

// SerializeHeaderAuth provides a mock function with given fields: v, iv, authData
func (_m *MockSerializer) SerializeHeaderAuth(v suite.MessageFormatVersion, iv []byte, authData []byte) (format.MessageHeaderAuth, error) {
	ret := _m.Called(v, iv, authData)

	if len(ret) == 0 {
		panic("no return value specified for SerializeHeaderAuth")
	}

	var r0 format.MessageHeaderAuth
	var r1 error
	if rf, ok := ret.Get(0).(func(suite.MessageFormatVersion, []byte, []byte) (format.MessageHeaderAuth, error)); ok {
		return rf(v, iv, authData)
	}
	if rf, ok := ret.Get(0).(func(suite.MessageFormatVersion, []byte, []byte) format.MessageHeaderAuth); ok {
		r0 = rf(v, iv, authData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(format.MessageHeaderAuth)
		}
	}

	if rf, ok := ret.Get(1).(func(suite.MessageFormatVersion, []byte, []byte) error); ok {
		r1 = rf(v, iv, authData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSerializer_SerializeHeaderAuth_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SerializeHeaderAuth'
type MockSerializer_SerializeHeaderAuth_Call struct {
	*mock.Call
}

// SerializeHeaderAuth is a helper method to define mock.On call
//   - v suite.MessageFormatVersion
//   - iv []byte
//   - authData []byte
func (_e *MockSerializer_Expecter) SerializeHeaderAuth(v interface{}, iv interface{}, authData interface{}) *MockSerializer_SerializeHeaderAuth_Call {
	return &MockSerializer_SerializeHeaderAuth_Call{Call: _e.mock.On("SerializeHeaderAuth", v, iv, authData)}
}

func (_c *MockSerializer_SerializeHeaderAuth_Call) Run(run func(v suite.MessageFormatVersion, iv []byte, authData []byte)) *MockSerializer_SerializeHeaderAuth_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(suite.MessageFormatVersion), args[1].([]byte), args[2].([]byte))
	})
	return _c
}

func (_c *MockSerializer_SerializeHeaderAuth_Call) Return(_a0 format.MessageHeaderAuth, _a1 error) *MockSerializer_SerializeHeaderAuth_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSerializer_SerializeHeaderAuth_Call) RunAndReturn(run func(suite.MessageFormatVersion, []byte, []byte) (format.MessageHeaderAuth, error)) *MockSerializer_SerializeHeaderAuth_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSerializer creates a new instance of MockSerializer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSerializer(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSerializer {
	mock := &MockSerializer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
