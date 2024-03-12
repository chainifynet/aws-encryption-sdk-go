// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewSerializer(t *testing.T) {
	tests := []struct {
		name string
		want format.Serializer
	}{
		{
			name: "New Deserializer",
			want: &Serializer{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSerializer()
			assert.Equalf(t, tt.want, got, "NewSerializer()")
			assert.IsType(t, tt.want, got)
		})
	}
}

func TestSerializer_SerializeHeader(t *testing.T) {
	aadMock1, _ := newAAD(nil)
	tests := []struct {
		name    string
		p       format.HeaderParams
		want    format.MessageHeader
		wantErr bool
	}{
		{
			name:    "Nil Algorithm",
			p:       format.HeaderParams{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Serialize",
			p: format.HeaderParams{
				AlgorithmSuite:     suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				MessageID:          make([]byte, 32),
				EncryptedDataKeys:  make([]format.MessageEDK, 1),
				ContentType:        suite.FramedContent,
				FrameLength:        4096,
				AlgorithmSuiteData: make([]byte, 32),
			},
			want: &messageHeaderV2{
				messageHeader: messageHeader{
					version:               suite.V2,
					algorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
					messageID:             make([]byte, 32),
					aadLen:                0,
					authenticatedData:     aadMock1,
					encryptedDataKeyCount: 1,
					encryptedDataKeys:     make([]format.MessageEDK, 1),
					contentType:           suite.FramedContent,
					frameLength:           4096,
				},
				algorithmSuiteData: make([]byte, 32),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Serializer{}
			got, err := s.SerializeHeader(tt.p)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
				assert.IsType(t, &messageHeaderV2{}, got)
			}
		})
	}
}

func TestSerializer_SerializeHeaderAuth(t *testing.T) {
	type args struct {
		v        suite.MessageFormatVersion
		iv       []byte
		authData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    format.MessageHeaderAuth
		wantErr bool
	}{
		{
			name:    "Invalid AuthData",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Serialize",
			args: args{
				v:        suite.V2,
				iv:       nil,
				authData: make([]byte, 16),
			},
			want: &headerAuth{
				version:            suite.V2,
				iv:                 nil,
				authenticationData: make([]byte, 16),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Serializer{}
			got, err := s.SerializeHeaderAuth(tt.args.v, tt.args.iv, tt.args.authData)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
				assert.IsType(t, &headerAuth{}, got)
			}
		})
	}
}

func TestSerializer_SerializeBody(t *testing.T) {
	type args struct {
		alg         *suite.AlgorithmSuite
		frameLength int
	}
	tests := []struct {
		name    string
		args    args
		want    format.MessageBody
		wantErr bool
	}{
		{
			name:    "Nil Algorithm",
			args:    args{},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Serialize",
			args: args{
				alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				frameLength: 4096,
			},
			want: &body{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				frameLength:    4096,
				frames:         make([]format.BodyFrame, 0),
				sequenceNumber: 1,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Serializer{}
			got, err := s.SerializeBody(tt.args.alg, tt.args.frameLength)
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

func TestSerializer_SerializeFooter(t *testing.T) {
	type args struct {
		alg       *suite.AlgorithmSuite
		signature []byte
	}
	tests := []struct {
		name    string
		args    args
		want    format.MessageFooter
		wantErr bool
	}{
		{
			name: "Invalid Signature",
			args: args{
				alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Valid Serialize",
			args: args{
				alg:       suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				signature: make([]byte, 103),
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
			s := &Serializer{}
			got, err := s.SerializeFooter(tt.args.alg, tt.args.signature)
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
