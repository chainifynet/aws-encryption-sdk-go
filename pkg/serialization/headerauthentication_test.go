// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func Test_NewHeaderAuth(t *testing.T) {
	type args struct {
		version  suite.MessageFormatVersion
		authData []byte
		iv       []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *headerAuth
		wantErr bool
	}{
		{"auth_Nil_Header", args{suite.V2, nil, nil}, &headerAuth{suite.V2, nil, nil}, true},
		{"auth_Nil_Header_2", args{suite.V2, []uint8(nil), nil}, &headerAuth{suite.V2, nil, nil}, true},
		{"auth_With_ShortHeader", args{suite.V2, []byte{0x01}, nil}, &headerAuth{suite.V2, []byte{0x01}, nil}, true},
		{"auth_Header_Valid_0", args{suite.V2, []byte("validkeyvalidkey"), nil}, &headerAuth{suite.V2, []byte("validkeyvalidkey"), nil}, false},
		{"auth_large_header", args{suite.V2, []byte("largeHeaderDatalargeHeaderDatalargeHeaderData"), nil}, &headerAuth{suite.V2, []byte{0x6c, 0x61, 0x72, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61}, nil}, true},
		{"auth_header_valid_1", args{suite.V2, []byte("validkeyvalidkey"), nil}, &headerAuth{suite.V2, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}, nil}, false},
		{"auth_header_valid_2", args{suite.V2, []byte("VALIDKEYVALIDKEY"), nil}, &headerAuth{suite.V2, []byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}, nil}, false},
		{"auth_header_V1_valid", args{suite.V1, []byte("validkeyvalidkey"), make([]byte, 12)}, &headerAuth{suite.V1, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}, make([]byte, 12)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHeaderAuth(tt.args.version, tt.args.iv, tt.args.authData)
			if err != nil && tt.wantErr {
				assert.Errorf(t, err, "NewHeaderAuth(%#v) error = %v, wantErr %v", tt.args.authData, err, tt.wantErr)
				return
			}
			assert.NoErrorf(t, err, "NewHeaderAuth(%#v) error = %v, wantErr %v", tt.args.authData, err, tt.wantErr)
			assert.Equalf(t, tt.want, got, "NewHeaderAuth() got = %#v, want %#v", got, tt.args.authData)
		})
	}
}

func Test_headerAuth_AuthData(t *testing.T) {
	type fields struct {
		version            suite.MessageFormatVersion
		authenticationData []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"auth_header_valid_1", fields{suite.V2, []byte("validkeyvalidkey")}, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}},
		{"auth_header_valid_2", fields{suite.V2, []byte("VALIDKEYVALIDKEY")}, []byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}},
		{"auth_header_V1_valid", fields{suite.V1, []byte("VALIDKEYVALIDKEY")}, []byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				version:            tt.fields.version,
				authenticationData: tt.fields.authenticationData,
			}
			assert.Equalf(t, tt.want, ha.AuthData(), "AuthData()")
		})
	}
}

func Test_headerAuth_Len(t *testing.T) {
	type fields struct {
		version            suite.MessageFormatVersion
		authenticationData []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{"auth_header_valid_1", fields{suite.V2, []byte("validkeyvalidkey")}, 16},
		{"auth_header_valid_2", fields{suite.V2, []byte("VALIDKEYVALIDKEY")}, 16},
		{"auth_header_invalid_nil", fields{suite.V2, nil}, 16},
		{"auth_header_invalid_1byte", fields{suite.V2, []byte{0x01}}, 16},
		{"auth_header_v1", fields{suite.V1, []byte("validkeyvalidkey")}, 28},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				version:            tt.fields.version,
				authenticationData: tt.fields.authenticationData,
			}
			assert.Equalf(t, tt.want, ha.Len(), "Len()")
		})
	}
}

func Test_headerAuth_Bytes(t *testing.T) {
	type fields struct {
		version            suite.MessageFormatVersion
		authenticationData []byte
		iv                 []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"auth_header_valid_1", fields{suite.V2, []byte("validkeyvalidkey"), nil}, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}},
		{"auth_header_valid_2", fields{suite.V2, []byte("VALIDKEYVALIDKEY"), nil}, []byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}},
		{"auth_header_invalid_size_1", fields{suite.V2, []byte("invalid"), nil}, []byte{0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64}},
		{"auth_header_invalid_size_2", fields{suite.V2, []byte("123"), nil}, []byte{0x31, 0x32, 0x33}},
		{"auth_header_invalid_nil", fields{suite.V2, nil, nil}, []byte{}},
		{"auth_header_V1_valid", fields{suite.V1, []byte("validkeyvalidkey"), make([]byte, 12)}, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				version:            tt.fields.version,
				authenticationData: tt.fields.authenticationData,
				iv:                 tt.fields.iv,
			}
			got := ha.Bytes()
			gotCap := cap(got)
			assert.Equalf(t, ha.Len(), gotCap, "Bytes() cap = %v, wantCap = %v", gotCap, ha.Len())
			assert.Equalf(t, tt.want, got, "Bytes()")
		})
	}
}

func Test_deserializeHeaderAuth(t *testing.T) {
	type args struct {
		v   suite.MessageFormatVersion
		buf *bytes.Buffer
	}
	type wants struct {
		want        *headerAuth
		bufLen      int
		bufCap      int
		bufLenAfter int
		bufCapAfter int
	}
	tests := []struct {
		name    string
		args    args
		wants   wants
		wantErr bool
	}{
		{"empty_buffer", args{suite.V2, bytes.NewBuffer(nil)}, wants{&headerAuth{suite.V2, nil, nil}, 0, 0, 0, 0}, true},
		{"invalid_length_buffer", args{suite.V2, bytes.NewBuffer([]byte("123"))}, wants{&headerAuth{suite.V2, nil, nil}, 3, 3, 3, 3}, true},
		{"exact_size_buffer", args{suite.V2, bytes.NewBuffer([]byte("validkeyvalidkey"))}, wants{&headerAuth{suite.V2, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}, nil}, 16, 16, 0, 16}, false},
		{"much_bigger_buffer", args{suite.V2, bytes.NewBuffer([]byte("validkeyvalidkey123"))}, wants{&headerAuth{suite.V2, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}, nil}, 19, 19, 3, 19}, false},
		{"exact_size_buffer_V1", args{suite.V1, bytes.NewBuffer([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79})}, wants{&headerAuth{suite.V1, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}, make([]byte, 12)}, 28, 28, 0, 28}, false},
		{"invalid_length_buffer_V1", args{suite.V1, bytes.NewBuffer([]byte("123"))}, wants{&headerAuth{suite.V1, nil, nil}, 3, 3, 3, 3}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deserializeHeaderAuth(tt.args.v, tt.args.buf)
			assert.Equalf(t, tt.wants.bufLenAfter, tt.args.buf.Len(), "deserializeHeaderAuth() must read exactly number of bytes, buf.Len() = %v, want %v", tt.args.buf.Len(), tt.wants.bufLenAfter)
			assert.Equalf(t, tt.wants.bufCapAfter, tt.args.buf.Cap(), "deserializeHeaderAuth() must not resize buffer, buf.Cap() = %v, want %v", tt.args.buf.Cap(), tt.wants.bufCapAfter)
			assert.Equalf(t, tt.wants.bufCap, tt.args.buf.Cap(), "deserializeHeaderAuth() must not resize buffer, buf.Cap() = %v, want %v", tt.args.buf.Cap(), tt.wants.bufCap)
			if err != nil && tt.wantErr {
				assert.Errorf(t, err, "deserializeHeaderAuth(%#v) error = %v, wantErr %v", tt.args.buf, err, tt.wantErr)
				return
			}
			assert.NoErrorf(t, err, "deserializeHeaderAuth(%#v) error = %v, wantErr %v", tt.args.buf, err, tt.wantErr)
			assert.Equalf(t, tt.wants.want, got, "deserializeHeaderAuth(%#v)", tt.args.buf)
		})
	}
}

func Test_headerAuth_IV(t *testing.T) {
	type fields struct {
		version            suite.MessageFormatVersion
		authenticationData []byte
		iv                 []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"auth_header_V1", fields{suite.V1, []byte("validkeyvalidkey"), make([]byte, 12)}, make([]byte, 12)},
		{"auth_header_V2", fields{suite.V2, []byte("validkeyvalidkey"), nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				version:            tt.fields.version,
				authenticationData: tt.fields.authenticationData,
				iv:                 tt.fields.iv,
			}
			assert.Equalf(t, tt.want, ha.IV(), "IV()")
		})
	}
}
