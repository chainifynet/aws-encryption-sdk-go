// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_mha_New(t *testing.T) {
	type args struct {
		authData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *headerAuth
		wantErr bool
	}{
		{"auth_Nil_Header", args{nil}, &headerAuth{nil}, true},
		{"auth_Nil_Header_2", args{[]uint8(nil)}, &headerAuth{nil}, true},
		{"auth_With_ShortHeader", args{[]byte{0x01}}, &headerAuth{[]byte{0x01}}, true},
		{"auth_Header_Valid_0", args{[]byte("validkeyvalidkey")}, &headerAuth{[]byte("validkeyvalidkey")}, false},
		{"auth_large_header", args{[]byte("largeHeaderDatalargeHeaderDatalargeHeaderData")}, &headerAuth{[]byte{0x6c, 0x61, 0x72, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61}}, true},
		{"auth_header_valid_1", args{[]byte("validkeyvalidkey")}, &headerAuth{[]byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}}, false},
		{"auth_header_valid_2", args{[]byte("VALIDKEYVALIDKEY")}, &headerAuth{[]byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mha{}
			got, err := h.New(tt.args.authData)
			if err != nil && tt.wantErr {
				assert.Errorf(t, err, "New(%#v) error = %v, wantErr %v", tt.args.authData, err, tt.wantErr)
				return
			}
			assert.NoErrorf(t, err, "New(%#v) error = %v, wantErr %v", tt.args.authData, err, tt.wantErr)
			assert.Equalf(t, tt.want, got, "New() got = %#v, want %#v", got, tt.args.authData)
		})
	}
}

func Test_headerAuth_AuthData(t *testing.T) {
	type fields struct {
		authenticationData []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"auth_header_valid_1", fields{[]byte("validkeyvalidkey")}, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}},
		{"auth_header_valid_2", fields{[]byte("VALIDKEYVALIDKEY")}, []byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				authenticationData: tt.fields.authenticationData,
			}
			assert.Equalf(t, tt.want, ha.AuthData(), "AuthData()")
		})
	}
}

func Test_headerAuth_Len(t *testing.T) {
	type fields struct {
		authenticationData []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{"auth_header_valid_1", fields{[]byte("validkeyvalidkey")}, 16},
		{"auth_header_valid_2", fields{[]byte("VALIDKEYVALIDKEY")}, 16},
		{"auth_header_invalid_nil", fields{nil}, 16},
		{"auth_header_invalid_1byte", fields{[]byte{0x01}}, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				authenticationData: tt.fields.authenticationData,
			}
			assert.Equalf(t, tt.want, ha.Len(), "Len()")
		})
	}
}

func Test_headerAuth_Serialize(t *testing.T) {
	type fields struct {
		authenticationData []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"auth_header_valid_1", fields{[]byte("validkeyvalidkey")}, []byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}},
		{"auth_header_valid_2", fields{[]byte("VALIDKEYVALIDKEY")}, []byte{0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x4b, 0x45, 0x59}},
		{"auth_header_invalid_size_1", fields{[]byte("invalid")}, []byte{0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64}},
		{"auth_header_invalid_size_2", fields{[]byte("123")}, []byte{0x31, 0x32, 0x33}},
		{"auth_header_invalid_nil", fields{nil}, []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ha := headerAuth{
				authenticationData: tt.fields.authenticationData,
			}
			got := ha.Serialize()
			gotCap := cap(got)
			assert.Equalf(t, ha.Len(), gotCap, "Serialize() cap = %v, wantCap = %v", gotCap, ha.Len())
			assert.Equalf(t, tt.want, got, "Serialize()")
		})
	}
}

func Test_mha_Deserialize(t *testing.T) {
	type args struct {
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
		{"empty_buffer", args{bytes.NewBuffer(nil)}, wants{&headerAuth{nil}, 0, 0, 0, 0}, true},
		{"invalid_length_buffer", args{bytes.NewBuffer([]byte("123"))}, wants{&headerAuth{nil}, 3, 3, 3, 3}, true},
		{"exact_size_buffer", args{bytes.NewBuffer([]byte("validkeyvalidkey"))}, wants{&headerAuth{[]byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}}, 16, 16, 0, 16}, false},
		{"much_bigger_buffer", args{bytes.NewBuffer([]byte("validkeyvalidkey123"))}, wants{&headerAuth{[]byte{0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x6b, 0x65, 0x79}}, 19, 19, 3, 19}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := mha{}
			got, err := h.Deserialize(tt.args.buf)
			assert.Equalf(t, tt.wants.bufLenAfter, tt.args.buf.Len(), "Deserialize() must read exactly number of bytes, buf.Len() = %v, want %v", tt.args.buf.Len(), tt.wants.bufLenAfter)
			assert.Equalf(t, tt.wants.bufCapAfter, tt.args.buf.Cap(), "Deserialize() must not resize buffer, buf.Cap() = %v, want %v", tt.args.buf.Cap(), tt.wants.bufCapAfter)
			assert.Equalf(t, tt.wants.bufCap, tt.args.buf.Cap(), "Deserialize() must not resize buffer, buf.Cap() = %v, want %v", tt.args.buf.Cap(), tt.wants.bufCap)
			if err != nil && tt.wantErr {
				assert.Errorf(t, err, "Deserialize(%#v) error = %v, wantErr %v", tt.args.buf, err, tt.wantErr)
				return
			}
			assert.NoErrorf(t, err, "Deserialize(%#v) error = %v, wantErr %v", tt.args.buf, err, tt.wantErr)
			assert.Equalf(t, tt.wants.want, got, "Deserialize(%#v)", tt.args.buf)
		})
	}
}
