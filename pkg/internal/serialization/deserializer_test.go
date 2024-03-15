// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewDeserializer(t *testing.T) {
	tests := []struct {
		name string
		want format.Deserializer
	}{
		{
			name: "New Deserializer",
			want: &Deserializer{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDeserializer()
			assert.Equalf(t, tt.want, got, "NewDeserializer()")
			assert.IsType(t, tt.want, got)
		})
	}
}

func TestDeserializer_DeserializeHeader(t *testing.T) {
	edk1Mock, _ := newEDK(awsKmsProviderID, "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320", []byte{0x1, 0x2, 0x1, 0x0, 0x78, 0xbc, 0x28, 0x8c, 0x86, 0xd0, 0x80, 0xa8, 0x5d, 0xd, 0x60, 0x4e, 0xe6, 0xce, 0x2b, 0x44, 0xb8, 0x2b, 0xd9, 0xcc, 0xe, 0x8, 0x4a, 0x48, 0x3f, 0x27, 0xc9, 0x83, 0xca, 0x67, 0x3e, 0xa2, 0x4d, 0x1, 0x93, 0xb8, 0xe7, 0x67, 0x85, 0x90, 0xf6, 0x34, 0x1, 0x53, 0xc2, 0x23, 0x11, 0x9e, 0xc4, 0xb3, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x40, 0x44, 0x5c, 0xc0, 0x2a, 0x7b, 0x82, 0xdb, 0x21, 0x33, 0x7e, 0x59, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x8a, 0xce, 0xe2, 0x3f, 0xee, 0x84, 0x25, 0x1a, 0x8e, 0xc6, 0xa8, 0x3d, 0x26, 0x80, 0x48, 0x1d, 0x53, 0x45, 0x65, 0x35, 0xf, 0x6d, 0x8b, 0xed, 0x5c, 0xd4, 0x10, 0xda, 0xf6, 0xf1, 0x55, 0x22, 0xd1, 0x35, 0xe9, 0x4e, 0xc0, 0xc5, 0x2a, 0xa9, 0x5b, 0xa3, 0x3, 0xec, 0x21, 0x80, 0x97, 0x76, 0x6e, 0xb0, 0xa1, 0xcd, 0xce, 0xe7, 0x29, 0xcc, 0x16, 0xc, 0xfc})
	edk2Mock, _ := newEDK(awsKmsProviderID, "arn:aws:kms:eu-west-1:123454678901:key/e070dfa5-bf44-488d-afad-4d57c5c8f3c5", []byte{0x1, 0x2, 0x2, 0x0, 0x78, 0x34, 0x28, 0xaa, 0x31, 0x8a, 0xbd, 0x1b, 0x42, 0x22, 0x29, 0xae, 0x7, 0x25, 0xf8, 0x29, 0x5f, 0x17, 0xdb, 0x91, 0x25, 0xb7, 0xa4, 0x3e, 0x79, 0xf0, 0x86, 0xb9, 0x40, 0xd3, 0xdd, 0x2, 0x91, 0x1, 0x92, 0xe5, 0x3f, 0x75, 0x27, 0xc9, 0x2d, 0x7b, 0x3f, 0xc2, 0x74, 0xe3, 0x2e, 0xcb, 0x3e, 0xb2, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x9, 0x46, 0x6, 0x3c, 0xe9, 0x7c, 0xf3, 0x80, 0xeb, 0x8b, 0x3a, 0x89, 0x2, 0x1, 0x10, 0x80, 0x3b, 0xd2, 0x9a, 0xfd, 0x12, 0xa1, 0x55, 0xd2, 0x5e, 0x1, 0x31, 0x9a, 0x6, 0x42, 0xd0, 0xa, 0xec, 0xa9, 0xed, 0xc3, 0x94, 0xa2, 0x43, 0x8d, 0xd1, 0x25, 0xce, 0x4a, 0x3c, 0x83, 0xdd, 0x15, 0x2d, 0x1, 0xa7, 0x1e, 0x20, 0x3, 0x6d, 0xa2, 0x4f, 0x3, 0x92, 0xb8, 0xe9, 0x88, 0xc7, 0x88, 0x74, 0x78, 0x1d, 0xfc, 0x9d, 0x52, 0x56, 0x27, 0x2c, 0xe, 0x13, 0xf8})

	messageID := []byte{0xf6, 0xd9, 0x0, 0x98, 0xba, 0xfb, 0x87, 0xc8, 0xe9, 0x79, 0xae, 0x71, 0xa5, 0x71, 0x10, 0x2d, 0xe5, 0x14, 0x45, 0x85, 0xd3, 0xde, 0xc4, 0xc3, 0x89, 0xcc, 0xdd, 0x23, 0xa5, 0x9e, 0xf, 0x96}
	algorithmSuiteData := []byte{0x52, 0xdf, 0xed, 0x4c, 0x0, 0xb4, 0xd7, 0x95, 0x2f, 0xa8, 0x3c, 0x81, 0xdb, 0xee, 0xbe, 0x7f, 0x55, 0x9d, 0x48, 0x3e, 0x27, 0xd4, 0x18, 0xb6, 0x94, 0x49, 0xfb, 0xb8, 0xa6, 0x60, 0xdc, 0xe2}

	aadMock1, _ := newAAD(map[string]string{"aws-crypto-public-key": "AyeV6x6xnVRv18vTtytzSID5DqpH6ejeNmGbU93PC/quQUnai2AgzTNLzJQglsZF2A==", "keyId": "4a5c8ebf-f7d0-4d09-88c3-5edb48539163", "orgId": "org-uuid-test", "someId": "someId-uuid-test"})

	mh1Mock := &messageHeaderV2{
		messageHeader: messageHeader{
			version:               suite.V2,
			algorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			messageID:             messageID,
			aadLen:                188,
			authenticatedData:     aadMock1,
			encryptedDataKeyCount: 2,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock, edk2Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		algorithmSuiteData: algorithmSuiteData,
	}
	type args struct {
		buf    *bytes.Buffer
		maxEDK int
	}
	tests := []struct {
		name     string
		args     args
		want     format.MessageHeader
		wantAuth format.MessageHeaderAuth
		wantErr  bool
	}{
		{
			name: "Nil Buffer",
			args: args{
				buf:    nil,
				maxEDK: 1,
			},
			want:     nil,
			wantAuth: nil,
			wantErr:  true,
		},
		{
			name: "Max EDK exceeded",
			args: args{
				buf:    bytes.NewBuffer(mh1Mock.Bytes()),
				maxEDK: 1,
			},
			want:     nil,
			wantAuth: nil,
			wantErr:  true,
		},
		{
			name: "Header Auth Error",
			args: args{
				buf: bytes.NewBuffer(concatSlices(
					mh1Mock.Bytes(),
					[]byte("invalid"),
				)),
				maxEDK: 2,
			},
			want:     nil,
			wantAuth: nil,
			wantErr:  true,
		},
		{
			name: "Valid Deserialize",
			args: args{
				buf: bytes.NewBuffer(concatSlices(
					mh1Mock.Bytes(),
					[]byte("validkeyvalidkey"),
				)),
				maxEDK: 2,
			},
			want: mh1Mock,
			wantAuth: &headerAuth{
				version:            suite.V2,
				authenticationData: []byte("validkeyvalidkey"),
				iv:                 nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Deserializer{}
			got, gotAuth, err := d.DeserializeHeader(tt.args.buf, tt.args.maxEDK)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				assert.Nil(t, gotAuth)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
				assert.Equal(t, tt.wantAuth, gotAuth)
				assert.IsType(t, &messageHeaderV2{}, got)
				assert.IsType(t, &headerAuth{}, gotAuth)
			}
		})
	}
}

func TestDeserializer_DeserializeBody(t *testing.T) {
	type args struct {
		buf      *bytes.Buffer
		alg      *suite.AlgorithmSuite
		frameLen int
	}
	tests := []struct {
		name    string
		args    args
		want    format.MessageBody
		wantErr bool
	}{
		{
			name: "Nil Buffer",
			args: args{
				buf:      nil,
				alg:      suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				frameLen: 1024,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Body Deserialize",
			args: args{
				buf:      bytes.NewBuffer([]byte{0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x0, 0x0, 0x0, 0x1, 0x4, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5}),
				alg:      suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				frameLen: 16,
			},
			want: &body{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				frameLength:    16,
				sequenceNumber: 2,
				frames: append(
					[]format.BodyFrame{},
					&frame{
						isFinal:           true,
						sequenceNumber:    1,
						iV:                []uint8{0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3},
						contentLength:     1,
						encryptedContent:  []uint8{0x04},
						authenticationTag: []uint8{0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5},
					},
				),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Deserializer{}
			got, err := d.DeserializeBody(tt.args.buf, tt.args.alg, tt.args.frameLen)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
				assert.IsType(t, &body{}, got)
			}
		})
	}
}

func TestDeserializer_DeserializeFooter(t *testing.T) {
	type args struct {
		buf *bytes.Buffer
		alg *suite.AlgorithmSuite
	}
	tests := []struct {
		name    string
		args    args
		want    format.MessageFooter
		wantErr bool
	}{
		{
			name: "Nil Buffer",
			args: args{
				buf: nil,
				alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Footer Deserialize",
			args: args{
				buf: bytes.NewBuffer(concatSlices([]byte{0x0, 0x67}, make([]byte, 103))),
				alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			},
			want: &footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				signLen:        103,
				signature:      make([]byte, 103),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Deserializer{}
			got, err := d.DeserializeFooter(tt.args.buf, tt.args.alg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
				assert.IsType(t, &footer{}, got)
			}
		})
	}
}