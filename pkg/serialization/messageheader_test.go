// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func Test_emh_New(t *testing.T) {
	type args struct {
		p MessageHeaderParams
	}
	edk1Mock, _ := EDK.new(awsKmsProviderID, "test", []byte("test"))

	mh1Mock := &MessageHeader{
		AlgorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		MessageID:             []byte("MessageID12MessageID12MessageID1"),
		aadLen:                0,
		AADData:               nil,
		EncryptedDataKeyCount: 1,
		EncryptedDataKeys:     []encryptedDataKey{*edk1Mock},
		contentType:           suite.FramedContent,
		FrameLength:           1024,
		AlgorithmSuiteData:    []byte("Algorithm12Algorithm12Algorithm1"),
	}
	mh2Mock := &MessageHeader{
		AlgorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		MessageID:             []byte("MessageID12MessageID12MessageID1"),
		aadLen:                0,
		AADData:               AAD.NewAAD(),
		EncryptedDataKeyCount: 1,
		EncryptedDataKeys:     []encryptedDataKey{*edk1Mock},
		contentType:           suite.FramedContent,
		FrameLength:           1024,
		AlgorithmSuiteData:    []byte("Algorithm12Algorithm12Algorithm1"),
	}
	mh3Mock := &MessageHeader{
		AlgorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		MessageID:             []byte("MessageID12MessageID12MessageID1"),
		aadLen:                17, // Key-Value Pair Count: 1 = 2 bytes (count) + 2 bytes keyLen + 4 bytes key (test) + 2 bytes valueLen + 7 bytes value (testing)
		AADData:               AAD.NewAADWithEncryptionContext(map[string]string{"test": "testing"}),
		EncryptedDataKeyCount: 1,
		EncryptedDataKeys:     []encryptedDataKey{*edk1Mock},
		contentType:           suite.FramedContent,
		FrameLength:           1024,
		AlgorithmSuiteData:    []byte("Algorithm12Algorithm12Algorithm1"),
	}

	tests := []struct {
		name           string
		args           args
		want           *MessageHeader
		wantFromBuffer *MessageHeader
		wantErr        bool
	}{
		{"nilAlgorithmSuite", args{MessageHeaderParams{nil, []byte("test"), nil, nil, suite.NonFramedContent, 10, []byte("test")}}, nil, nil, true},
		{"invalidMessageID", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, nil, nil, nil, suite.NonFramedContent, 10, []byte("test")}}, nil, nil, true},
		{"invalidMessageID", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("test"), nil, nil, suite.NonFramedContent, 10, []byte("test")}}, nil, nil, true},
		{"invalidEncryptedDataKeys", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), nil, nil, suite.NonFramedContent, 10, []byte("test")}}, nil, nil, true},
		{"invalidAlgorithmSuiteDataLen", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), nil, []encryptedDataKey{*edk1Mock}, suite.NonFramedContent, 10, []byte("test")}}, nil, nil, true},
		{"invalidFrameLength", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAAD(), []encryptedDataKey{*edk1Mock}, suite.NonFramedContent, 10, []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidFrameLength", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAAD(), []encryptedDataKey{*edk1Mock}, suite.NonFramedContent, 4294967296, []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidContentType", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAAD(), []encryptedDataKey{*edk1Mock}, suite.ContentType(3), 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidContentType", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAAD(), []encryptedDataKey{*edk1Mock}, suite.ContentType(0), 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidContentType", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAAD(), []encryptedDataKey{*edk1Mock}, suite.NonFramedContent, 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"valid", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), nil, []encryptedDataKey{*edk1Mock}, suite.FramedContent, 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, mh1Mock, nil, false},
		{"valid", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), nil, []encryptedDataKey{*edk1Mock}, suite.FramedContent, 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, mh1Mock, mh1Mock, false},
		{"valid", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAAD(), []encryptedDataKey{*edk1Mock}, suite.FramedContent, 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, mh2Mock, mh1Mock, false},
		{"valid", args{MessageHeaderParams{suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte("MessageID12MessageID12MessageID1"), AAD.NewAADWithEncryptionContext(map[string]string{"test": "testing"}), []encryptedDataKey{*edk1Mock}, suite.FramedContent, 1024, []byte("Algorithm12Algorithm12Algorithm1")}}, mh3Mock, mh3Mock, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := emh{}
			got, err := mh.New(tt.args.p)
			if err != nil && tt.wantErr {
				assert.Errorf(t, err, "New(%#v) error = %v, wantErr %v", tt.args.p, err, tt.wantErr)
				return
			}
			logger.L().Trace().
				Str("bytes", logger.FmtBytes(got.Bytes())).
				Int("len", got.Len()).
				Msg("got")
			assert.NoErrorf(t, err, "New(%#v) error = %v, wantErr %v", tt.args.p, err, tt.wantErr)
			assert.Equalf(t, tt.want, got, "New(%#v)", tt.args.p)
			if tt.wantFromBuffer != nil {
				gotBytes := got.Bytes()
				buf := bytes.NewBuffer(gotBytes)
				bufLen := buf.Len()
				got2, err2 := mh.fromBuffer(buf)
				assert.NoErrorf(t, err2, "fromBuffer(%#v) error = %v, wantErr %v", gotBytes, err2, tt.wantErr)
				assert.Equalf(t, tt.wantFromBuffer, got2, "fromBuffer(%#v)", gotBytes)
				assert.Equal(t, gotBytes, got2.Bytes())
				assert.Equal(t, got.Bytes(), got2.Bytes())
				assert.Equal(t, got.Len(), got2.Len())
				assert.Equal(t, 0, buf.Len())
				assert.Equal(t, bufLen, got.Len())
				assert.Equal(t, bufLen, buf.Cap())
			}
		})
	}
}

func Test_emh_fromBuffer(t *testing.T) {
	type args struct {
		buf *bytes.Buffer
	}
	edk1Mock, _ := EDK.new(awsKmsProviderID, "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320", []byte{0x1, 0x2, 0x1, 0x0, 0x78, 0xbc, 0x28, 0x8c, 0x86, 0xd0, 0x80, 0xa8, 0x5d, 0xd, 0x60, 0x4e, 0xe6, 0xce, 0x2b, 0x44, 0xb8, 0x2b, 0xd9, 0xcc, 0xe, 0x8, 0x4a, 0x48, 0x3f, 0x27, 0xc9, 0x83, 0xca, 0x67, 0x3e, 0xa2, 0x4d, 0x1, 0x93, 0xb8, 0xe7, 0x67, 0x85, 0x90, 0xf6, 0x34, 0x1, 0x53, 0xc2, 0x23, 0x11, 0x9e, 0xc4, 0xb3, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x40, 0x44, 0x5c, 0xc0, 0x2a, 0x7b, 0x82, 0xdb, 0x21, 0x33, 0x7e, 0x59, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x8a, 0xce, 0xe2, 0x3f, 0xee, 0x84, 0x25, 0x1a, 0x8e, 0xc6, 0xa8, 0x3d, 0x26, 0x80, 0x48, 0x1d, 0x53, 0x45, 0x65, 0x35, 0xf, 0x6d, 0x8b, 0xed, 0x5c, 0xd4, 0x10, 0xda, 0xf6, 0xf1, 0x55, 0x22, 0xd1, 0x35, 0xe9, 0x4e, 0xc0, 0xc5, 0x2a, 0xa9, 0x5b, 0xa3, 0x3, 0xec, 0x21, 0x80, 0x97, 0x76, 0x6e, 0xb0, 0xa1, 0xcd, 0xce, 0xe7, 0x29, 0xcc, 0x16, 0xc, 0xfc})
	edk2Mock, _ := EDK.new(awsKmsProviderID, "arn:aws:kms:eu-west-1:123454678901:key/e070dfa5-bf44-488d-afad-4d57c5c8f3c5", []byte{0x1, 0x2, 0x2, 0x0, 0x78, 0x34, 0x28, 0xaa, 0x31, 0x8a, 0xbd, 0x1b, 0x42, 0x22, 0x29, 0xae, 0x7, 0x25, 0xf8, 0x29, 0x5f, 0x17, 0xdb, 0x91, 0x25, 0xb7, 0xa4, 0x3e, 0x79, 0xf0, 0x86, 0xb9, 0x40, 0xd3, 0xdd, 0x2, 0x91, 0x1, 0x92, 0xe5, 0x3f, 0x75, 0x27, 0xc9, 0x2d, 0x7b, 0x3f, 0xc2, 0x74, 0xe3, 0x2e, 0xcb, 0x3e, 0xb2, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x9, 0x46, 0x6, 0x3c, 0xe9, 0x7c, 0xf3, 0x80, 0xeb, 0x8b, 0x3a, 0x89, 0x2, 0x1, 0x10, 0x80, 0x3b, 0xd2, 0x9a, 0xfd, 0x12, 0xa1, 0x55, 0xd2, 0x5e, 0x1, 0x31, 0x9a, 0x6, 0x42, 0xd0, 0xa, 0xec, 0xa9, 0xed, 0xc3, 0x94, 0xa2, 0x43, 0x8d, 0xd1, 0x25, 0xce, 0x4a, 0x3c, 0x83, 0xdd, 0x15, 0x2d, 0x1, 0xa7, 0x1e, 0x20, 0x3, 0x6d, 0xa2, 0x4f, 0x3, 0x92, 0xb8, 0xe9, 0x88, 0xc7, 0x88, 0x74, 0x78, 0x1d, 0xfc, 0x9d, 0x52, 0x56, 0x27, 0x2c, 0xe, 0x13, 0xf8})

	messageFormatVersion := []byte{0x2}
	algorithmID := []byte{0x5, 0x78}
	messageID := []byte{0xf6, 0xd9, 0x0, 0x98, 0xba, 0xfb, 0x87, 0xc8, 0xe9, 0x79, 0xae, 0x71, 0xa5, 0x71, 0x10, 0x2d, 0xe5, 0x14, 0x45, 0x85, 0xd3, 0xde, 0xc4, 0xc3, 0x89, 0xcc, 0xdd, 0x23, 0xa5, 0x9e, 0xf, 0x96}
	aadLen := []byte{0x0, 0xbc}
	aadDataBytes := []byte{0x0, 0x4, 0x0, 0x15, 0x61, 0x77, 0x73, 0x2d, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x0, 0x44, 0x41, 0x79, 0x65, 0x56, 0x36, 0x78, 0x36, 0x78, 0x6e, 0x56, 0x52, 0x76, 0x31, 0x38, 0x76, 0x54, 0x74, 0x79, 0x74, 0x7a, 0x53, 0x49, 0x44, 0x35, 0x44, 0x71, 0x70, 0x48, 0x36, 0x65, 0x6a, 0x65, 0x4e, 0x6d, 0x47, 0x62, 0x55, 0x39, 0x33, 0x50, 0x43, 0x2f, 0x71, 0x75, 0x51, 0x55, 0x6e, 0x61, 0x69, 0x32, 0x41, 0x67, 0x7a, 0x54, 0x4e, 0x4c, 0x7a, 0x4a, 0x51, 0x67, 0x6c, 0x73, 0x5a, 0x46, 0x32, 0x41, 0x3d, 0x3d, 0x0, 0x5, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x0, 0x24, 0x34, 0x61, 0x35, 0x63, 0x38, 0x65, 0x62, 0x66, 0x2d, 0x66, 0x37, 0x64, 0x30, 0x2d, 0x34, 0x64, 0x30, 0x39, 0x2d, 0x38, 0x38, 0x63, 0x33, 0x2d, 0x35, 0x65, 0x64, 0x62, 0x34, 0x38, 0x35, 0x33, 0x39, 0x31, 0x36, 0x33, 0x0, 0x5, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x0, 0xd, 0x6f, 0x72, 0x67, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x0, 0x6, 0x73, 0x6f, 0x6d, 0x65, 0x49, 0x64, 0x0, 0x10, 0x73, 0x6f, 0x6d, 0x65, 0x49, 0x64, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x74, 0x65, 0x73, 0x74}
	edkCount := []byte{0x0, 0x2}
	// edk1 bytes and edk2 bytes from mocks
	contentType := []byte{0x2}
	frameLength := []byte{0x0, 0x0, 0x4, 0x0}
	algorithmSuiteData := []byte{0x52, 0xdf, 0xed, 0x4c, 0x0, 0xb4, 0xd7, 0x95, 0x2f, 0xa8, 0x3c, 0x81, 0xdb, 0xee, 0xbe, 0x7f, 0x55, 0x9d, 0x48, 0x3e, 0x27, 0xd4, 0x18, 0xb6, 0x94, 0x49, 0xfb, 0xb8, 0xa6, 0x60, 0xdc, 0xe2}

	mh1Mock := &MessageHeader{
		AlgorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
		MessageID:             messageID,
		aadLen:                188,
		AADData:               AAD.NewAADWithEncryptionContext(map[string]string{"aws-crypto-public-key": "AyeV6x6xnVRv18vTtytzSID5DqpH6ejeNmGbU93PC/quQUnai2AgzTNLzJQglsZF2A==", "keyId": "4a5c8ebf-f7d0-4d09-88c3-5edb48539163", "orgId": "org-uuid-test", "someId": "someId-uuid-test"}),
		EncryptedDataKeyCount: 2,
		EncryptedDataKeys:     []encryptedDataKey{*edk1Mock, *edk2Mock},
		contentType:           suite.FramedContent,
		FrameLength:           1024,
		AlgorithmSuiteData:    algorithmSuiteData,
	}
	//argsBuf := new(bytes.Buffer)
	concatSlices := func(slices ...[]byte) []byte {
		var result []byte
		for _, slice := range slices {
			result = append(result, slice...)
		}
		return result
	}

	tests := []struct {
		name    string
		args    args
		want    *MessageHeader
		wantErr assert.ErrorAssertionFunc
	}{
		{"nilBuffer", args{nil}, nil, assert.Error},
		{"emptyBuffer", args{bytes.NewBuffer(nil)}, nil, assert.Error},
		{"emptyBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x02}, 76))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x02}, 77))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x01}, 77))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x00}, 77))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x05, 0x78}, 77))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x78, 0x05}, 77))}, nil, assert.Error},

		{"incompleteBuffer", args{bytes.NewBuffer(messageFormatVersion)}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.bytes()))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.bytes(), edk2Mock.bytes()))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.bytes(), edk2Mock.bytes(), contentType))}, nil, assert.Error},
		{"incompleteBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.bytes(), edk2Mock.bytes(), contentType, frameLength))}, nil, assert.Error},
		{"validBuffer", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.bytes(), edk2Mock.bytes(), contentType, frameLength, algorithmSuiteData))}, mh1Mock, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := emh{}
			got, err := mh.fromBuffer(tt.args.buf)
			if !tt.wantErr(t, err, fmt.Sprintf("fromBuffer(%#v)", tt.args.buf)) {
				return
			}
			assert.Equalf(t, tt.want, got, "fromBuffer(%#v)", tt.args.buf)
			if tt.want != nil {
				assert.Equal(t, tt.want.Bytes(), got.Bytes())
				assert.Equal(t, tt.want.Len(), got.Len())
			}
		})
	}
}
