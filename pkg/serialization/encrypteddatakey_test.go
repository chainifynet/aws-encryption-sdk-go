// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_edk_validateMinMaxEDKs(t *testing.T) {
	type fields struct {
		ProviderID providerIdentity
		LenFields  int
	}
	type args struct {
		keys int
		max  int
	}
	edkMock := fields{
		ProviderID: awsKmsProviderID,
		LenFields:  EDK.LenFields,
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantErrFunc assert.ErrorAssertionFunc
		wantErr     error
	}{
		{"valid", edkMock, args{1, 1}, assert.NoError, nil},
		{"valid", edkMock, args{1, 2}, assert.NoError, nil},
		{"valid", edkMock, args{2, 2}, assert.NoError, nil},
		{"invalid", edkMock, args{3, 2}, assert.Error, ErrMaxEncryptedDataKeys},
		{"invalid", edkMock, args{10, 5}, assert.Error, ErrMaxEncryptedDataKeys},
		{"invalid", edkMock, args{1, 0}, assert.Error, ErrMaxEncryptedDataKeys},
		{"invalid", edkMock, args{0, 1}, assert.Error, ErrMinEncryptedDataKeys},
		{"invalid", edkMock, args{0, 0}, assert.Error, ErrMinEncryptedDataKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := edk{
				ProviderID: tt.fields.ProviderID,
				LenFields:  tt.fields.LenFields,
			}
			err := e.validateMinMaxEDKs(tt.args.keys, tt.args.max)
			tt.wantErrFunc(t, err, fmt.Sprintf("validateMinMaxEDKs(%v, %v)", tt.args.keys, tt.args.max))
			if err != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func Test_edk_new(t *testing.T) {
	type fields struct {
		ProviderID providerIdentity
		LenFields  int
	}
	edkMock := fields{
		ProviderID: awsKmsProviderID,
		LenFields:  EDK.LenFields,
	}
	type args struct {
		providerID           providerIdentity
		providerInfo         string
		encryptedDataKeyData []byte
	}
	key1Mock := args{"aws-kms", "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320", []byte{0x1, 0x2, 0x1, 0x0, 0x78, 0xbc, 0x28, 0x8c, 0x86, 0xd0, 0x80, 0xa8, 0x5d, 0xd, 0x60, 0x4e, 0xe6, 0xce, 0x2b, 0x44, 0xb8, 0x2b, 0xd9, 0xcc, 0xe, 0x8, 0x4a, 0x48, 0x3f, 0x27, 0xc9, 0x83, 0xca, 0x67, 0x3e, 0xa2, 0x4d, 0x1, 0x40, 0x46, 0xd4, 0xb9, 0x50, 0x9c, 0xb1, 0x77, 0x84, 0xd7, 0x9a, 0x8b, 0x10, 0x43, 0x6c, 0x6f, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x33, 0xfd, 0x17, 0x50, 0x6, 0xf2, 0x1, 0x5e, 0x99, 0x80, 0xd7, 0x8, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x10, 0x6, 0x28, 0xb, 0x57, 0x4d, 0x46, 0x7a, 0x18, 0x6d, 0x4c, 0x95, 0x3, 0x6e, 0xf0, 0xe2, 0x24, 0x16, 0x4b, 0x92, 0xb2, 0x0, 0x4e, 0x52, 0xd7, 0x3a, 0x37, 0xf3, 0xf, 0x58, 0x9f, 0x38, 0x82, 0x6a, 0xa3, 0xad, 0xf2, 0xf7, 0x8b, 0xf5, 0x88, 0x5f, 0xf3, 0x96, 0x63, 0x6d, 0xc3, 0x2d, 0xf2, 0xb8, 0xfa, 0xf4, 0x5f, 0xda, 0x0, 0x7c, 0xa3, 0xdd, 0xa8}}
	key2Mock := args{"aws-kms", "arn:aws:kms:eu-west-1:123454678901:key/e070dfa5-bf44-488d-afad-4d57c5c8f3c5", []byte{0x1, 0x2, 0x2, 0x0, 0x78, 0x34, 0x28, 0xaa, 0x31, 0x8a, 0xbd, 0x1b, 0x42, 0x22, 0x29, 0xae, 0x7, 0x25, 0xf8, 0x29, 0x5f, 0x17, 0xdb, 0x91, 0x25, 0xb7, 0xa4, 0x3e, 0x79, 0xf0, 0x86, 0xb9, 0x40, 0xd3, 0xdd, 0x2, 0x91, 0x1, 0x0, 0xd4, 0x58, 0xfe, 0x9a, 0xc8, 0x5f, 0x4d, 0xd, 0x7c, 0xd9, 0x97, 0x24, 0x9f, 0xf1, 0xc0, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x37, 0x93, 0x75, 0x61, 0x2b, 0x43, 0xd, 0x7a, 0x5b, 0x15, 0x32, 0xb8, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x9c, 0xdc, 0x38, 0x6b, 0x70, 0xc2, 0xac, 0x97, 0x3e, 0x5a, 0x9f, 0xba, 0xa9, 0xf8, 0x2b, 0x94, 0xdf, 0x64, 0xf1, 0x32, 0xc7, 0xaa, 0x57, 0x31, 0xe8, 0x5a, 0x22, 0x40, 0xd, 0xe2, 0xb7, 0x8f, 0x37, 0x59, 0x60, 0x1e, 0xe9, 0x28, 0x2e, 0x26, 0xe5, 0xbd, 0xc4, 0xae, 0x53, 0xb3, 0x41, 0x8e, 0xd4, 0xfd, 0x9a, 0x1c, 0x95, 0xcd, 0x56, 0x38, 0xa2, 0xb0, 0x4a}}

	edk1Mock := &encryptedDataKey{
		providerIDLen:       7,
		ProviderID:          key1Mock.providerID,
		providerInfoLen:     75,
		ProviderInfo:        key1Mock.providerInfo,
		encryptedDataKeyLen: 184,
		encryptedDataKey:    key1Mock.encryptedDataKeyData,
	}
	edk2Mock := &encryptedDataKey{
		providerIDLen:       7,
		ProviderID:          key2Mock.providerID,
		providerInfoLen:     75,
		ProviderInfo:        key2Mock.providerInfo,
		encryptedDataKeyLen: 184,
		encryptedDataKey:    key2Mock.encryptedDataKeyData,
	}

	tests := []struct {
		name      string
		fields    fields
		args      args
		want      *encryptedDataKey
		wantErr   assert.ErrorAssertionFunc
		wantLen   int
		wantBytes []byte
	}{
		{"valid_key1", edkMock, key1Mock, edk1Mock, assert.NoError, 272, []byte{0x0, 0x7, 0x61, 0x77, 0x73, 0x2d, 0x6b, 0x6d, 0x73, 0x0, 0x4b, 0x61, 0x72, 0x6e, 0x3a, 0x61, 0x77, 0x73, 0x3a, 0x6b, 0x6d, 0x73, 0x3a, 0x65, 0x75, 0x2d, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x31, 0x3a, 0x31, 0x32, 0x33, 0x34, 0x35, 0x34, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x3a, 0x6b, 0x65, 0x79, 0x2f, 0x38, 0x30, 0x62, 0x64, 0x32, 0x66, 0x61, 0x63, 0x2d, 0x63, 0x30, 0x37, 0x64, 0x2d, 0x34, 0x33, 0x38, 0x61, 0x2d, 0x38, 0x33, 0x37, 0x65, 0x2d, 0x33, 0x36, 0x65, 0x31, 0x39, 0x62, 0x64, 0x34, 0x64, 0x33, 0x32, 0x30, 0x0, 0xb8, 0x1, 0x2, 0x1, 0x0, 0x78, 0xbc, 0x28, 0x8c, 0x86, 0xd0, 0x80, 0xa8, 0x5d, 0xd, 0x60, 0x4e, 0xe6, 0xce, 0x2b, 0x44, 0xb8, 0x2b, 0xd9, 0xcc, 0xe, 0x8, 0x4a, 0x48, 0x3f, 0x27, 0xc9, 0x83, 0xca, 0x67, 0x3e, 0xa2, 0x4d, 0x1, 0x40, 0x46, 0xd4, 0xb9, 0x50, 0x9c, 0xb1, 0x77, 0x84, 0xd7, 0x9a, 0x8b, 0x10, 0x43, 0x6c, 0x6f, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x33, 0xfd, 0x17, 0x50, 0x6, 0xf2, 0x1, 0x5e, 0x99, 0x80, 0xd7, 0x8, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x10, 0x6, 0x28, 0xb, 0x57, 0x4d, 0x46, 0x7a, 0x18, 0x6d, 0x4c, 0x95, 0x3, 0x6e, 0xf0, 0xe2, 0x24, 0x16, 0x4b, 0x92, 0xb2, 0x0, 0x4e, 0x52, 0xd7, 0x3a, 0x37, 0xf3, 0xf, 0x58, 0x9f, 0x38, 0x82, 0x6a, 0xa3, 0xad, 0xf2, 0xf7, 0x8b, 0xf5, 0x88, 0x5f, 0xf3, 0x96, 0x63, 0x6d, 0xc3, 0x2d, 0xf2, 0xb8, 0xfa, 0xf4, 0x5f, 0xda, 0x0, 0x7c, 0xa3, 0xdd, 0xa8}},
		{"valid_key2", edkMock, key2Mock, edk2Mock, assert.NoError, 272, []byte{0x0, 0x7, 0x61, 0x77, 0x73, 0x2d, 0x6b, 0x6d, 0x73, 0x0, 0x4b, 0x61, 0x72, 0x6e, 0x3a, 0x61, 0x77, 0x73, 0x3a, 0x6b, 0x6d, 0x73, 0x3a, 0x65, 0x75, 0x2d, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x31, 0x3a, 0x31, 0x32, 0x33, 0x34, 0x35, 0x34, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x3a, 0x6b, 0x65, 0x79, 0x2f, 0x65, 0x30, 0x37, 0x30, 0x64, 0x66, 0x61, 0x35, 0x2d, 0x62, 0x66, 0x34, 0x34, 0x2d, 0x34, 0x38, 0x38, 0x64, 0x2d, 0x61, 0x66, 0x61, 0x64, 0x2d, 0x34, 0x64, 0x35, 0x37, 0x63, 0x35, 0x63, 0x38, 0x66, 0x33, 0x63, 0x35, 0x0, 0xb8, 0x1, 0x2, 0x2, 0x0, 0x78, 0x34, 0x28, 0xaa, 0x31, 0x8a, 0xbd, 0x1b, 0x42, 0x22, 0x29, 0xae, 0x7, 0x25, 0xf8, 0x29, 0x5f, 0x17, 0xdb, 0x91, 0x25, 0xb7, 0xa4, 0x3e, 0x79, 0xf0, 0x86, 0xb9, 0x40, 0xd3, 0xdd, 0x2, 0x91, 0x1, 0x0, 0xd4, 0x58, 0xfe, 0x9a, 0xc8, 0x5f, 0x4d, 0xd, 0x7c, 0xd9, 0x97, 0x24, 0x9f, 0xf1, 0xc0, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x37, 0x93, 0x75, 0x61, 0x2b, 0x43, 0xd, 0x7a, 0x5b, 0x15, 0x32, 0xb8, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x9c, 0xdc, 0x38, 0x6b, 0x70, 0xc2, 0xac, 0x97, 0x3e, 0x5a, 0x9f, 0xba, 0xa9, 0xf8, 0x2b, 0x94, 0xdf, 0x64, 0xf1, 0x32, 0xc7, 0xaa, 0x57, 0x31, 0xe8, 0x5a, 0x22, 0x40, 0xd, 0xe2, 0xb7, 0x8f, 0x37, 0x59, 0x60, 0x1e, 0xe9, 0x28, 0x2e, 0x26, 0xe5, 0xbd, 0xc4, 0xae, 0x53, 0xb3, 0x41, 0x8e, 0xd4, 0xfd, 0x9a, 0x1c, 0x95, 0xcd, 0x56, 0x38, 0xa2, 0xb0, 0x4a}},
		{"invalid_provider_id", edkMock, args{"aws-kms-invalid", "wrong", bytes.Repeat([]byte{0x0}, 100)}, nil, assert.Error, 0, []byte{0x0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := edk{
				ProviderID: tt.fields.ProviderID,
				LenFields:  tt.fields.LenFields,
			}
			got, err := e.new(tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
			if !tt.wantErr(t, err, fmt.Sprintf("new(%v, %v, %#v)", tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)) {
				return
			}
			assert.Equalf(t, tt.want, got, "new(%v, %v, %#v)", tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
			if tt.wantLen != 0 {
				assert.Equalf(t, tt.wantBytes, got.bytes(), "bytes() (%v, %v, %#v)", tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
				assert.Equalf(t, tt.wantLen, got.len(), "len() (%v, %v, %#v)", tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
				buf := bytes.NewBuffer(got.bytes())
				got2, err2 := e.fromBuffer(buf)
				assert.NoErrorf(t, err2, "fromBuffer() error = %v, (%v, %v, %#v)", err2, tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
				assert.Equalf(t, tt.want, got2, "fromBuffer() (%v, %v, %#v)", tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
				assert.Equalf(t, got, got2, "fromBuffer() (%v, %v, %#v)", tt.args.providerID, tt.args.providerInfo, tt.args.encryptedDataKeyData)
				assert.Equalf(t, 0, buf.Len(), "buffer must have 0")
			}
		})
	}
}
