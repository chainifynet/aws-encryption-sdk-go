// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewHeader(t *testing.T) {
	type args struct {
		p format.HeaderParams
	}

	edk1Mock, _ := newEDK(awsKmsProviderID, "test", []byte("test"))
	aadMock1, _ := newAAD(nil)
	aadMock2, _ := newAAD(map[string]string{"test": "testing"})

	mh1Mock := &messageHeaderV2{
		messageHeader: messageHeader{
			version:               suite.V2,
			algorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			messageID:             []byte("MessageID12MessageID12MessageID1"),
			aadLen:                0,
			authenticatedData:     aadMock1,
			encryptedDataKeyCount: 1,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		algorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1"),
	}

	mh2Mock := &messageHeaderV2{
		messageHeader: messageHeader{
			version:               suite.V2,
			algorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			messageID:             []byte("MessageID12MessageID12MessageID1"),
			aadLen:                0,
			authenticatedData:     aadMock1,
			encryptedDataKeyCount: 1,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		algorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1"),
	}

	mh3Mock := &messageHeaderV2{
		messageHeader: messageHeader{
			version:               suite.V2,
			algorithmSuite:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			messageID:             []byte("MessageID12MessageID12MessageID1"),
			aadLen:                17, // Key-Value Pair Count: 1 = 2 bytes (count) + 2 bytes keyLen + 4 bytes key (test) + 2 bytes valueLen + 7 bytes value (testing)
			authenticatedData:     aadMock2,
			encryptedDataKeyCount: 1,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		algorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1"),
	}

	mh1MockV1 := &messageHeaderV1{
		messageHeader: messageHeader{
			version:               suite.V1,
			algorithmSuite:        suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			messageID:             []byte("MessageMessage16"),
			aadLen:                0,
			authenticatedData:     aadMock1,
			encryptedDataKeyCount: 1,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		messageType: format.CustomerAEData,
		reserved:    reservedField,
		ivLen:       12,
	}

	mh3MockV1 := &messageHeaderV1{
		messageHeader: messageHeader{
			version:               suite.V1,
			algorithmSuite:        suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			messageID:             []byte("MessageMessage16"),
			aadLen:                17,
			authenticatedData:     aadMock2,
			encryptedDataKeyCount: 1,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		messageType: format.CustomerAEData,
		reserved:    reservedField,
		ivLen:       12,
	}

	tests := []struct {
		name           string
		args           args
		want           format.MessageHeader
		wantFromBuffer format.MessageHeader
		wantErr        bool
	}{
		{"nilAlgorithmSuite", args{format.HeaderParams{MessageID: []byte("test"), ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"unsupportedAlgorithm", args{format.HeaderParams{AlgorithmSuite: &suite.AlgorithmSuite{AlgorithmID: 0x0050}, ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"invalidMessageID", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"invalidMessageID", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("test"), ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"invalidMessageID_V1", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256, MessageID: []byte("testtesttestt15"), ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"invalidEncryptedDataKeys", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"invalidAlgorithmSuiteDataLen", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},
		{"invalidAlgorithmSuiteDataLen_V1", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256, MessageID: []byte("MessageMessage16"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("test")}}, nil, nil, true},

		{"invalidEncryptionContext", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptionContext: map[string]string{"test": ""}, EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},

		{"invalidFrameLength", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.NonFramedContent, FrameLength: 10, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidContentType", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.ContentType(3), FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidContentType", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.ContentType(0), FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"invalidContentType", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.NonFramedContent, FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, nil, nil, true},
		{"valid", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, mh1Mock, nil, false},
		{"valid", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, mh1Mock, mh1Mock, false},
		{"valid", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptionContext: map[string]string{}, EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, mh2Mock, mh1Mock, false},
		{"valid", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, MessageID: []byte("MessageID12MessageID12MessageID1"), EncryptionContext: map[string]string{"test": "testing"}, EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024, AlgorithmSuiteData: []byte("Algorithm12Algorithm12Algorithm1")}}, mh3Mock, mh3Mock, false},
		{"valid_V1", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256, MessageID: []byte("MessageMessage16"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024}}, mh1MockV1, nil, false},
		{"valid_V1", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256, MessageID: []byte("MessageMessage16"), EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024}}, mh1MockV1, mh1MockV1, false},
		{"valid_V1", args{format.HeaderParams{AlgorithmSuite: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256, MessageID: []byte("MessageMessage16"), EncryptionContext: map[string]string{"test": "testing"}, EncryptedDataKeys: []format.MessageEDK{edk1Mock}, ContentType: suite.FramedContent, FrameLength: 1024}}, mh3MockV1, mh3MockV1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newHeader(tt.args.p)
			if err != nil && tt.wantErr {
				assert.Errorf(t, err, "newHeader(%#v) error = %v, wantErr %v", tt.args.p, err, tt.wantErr)
				return
			}
			assert.NoErrorf(t, err, "newHeader(%#v) error = %v, wantErr %v", tt.args.p, err, tt.wantErr)
			assert.Equalf(t, tt.want, got, "newHeader(%#v)", tt.args.p)

			assert.Equal(t, tt.want.Version(), got.Version())
			assert.Equal(t, tt.want.AlgorithmSuite(), got.AlgorithmSuite())
			assert.Equal(t, tt.want.MessageID(), got.MessageID())
			assert.Equal(t, tt.want.AADLength(), got.AADLength())
			assert.Equal(t, tt.want.AADData(), got.AADData())
			assert.Equal(t, tt.want.EncryptedDataKeyCount(), got.EncryptedDataKeyCount())
			assert.Equal(t, tt.want.EncryptedDataKeys(), got.EncryptedDataKeys())
			assert.Equal(t, tt.want.ContentType(), got.ContentType())
			assert.Equal(t, tt.want.FrameLength(), got.FrameLength())
			assert.Equal(t, tt.want.Type(), got.Type())
			assert.Equal(t, tt.want.Reserved(), got.Reserved())
			assert.Equal(t, tt.want.IVLength(), got.IVLength())
			assert.Equal(t, tt.want.AlgorithmSuiteData(), got.AlgorithmSuiteData())

			if tt.wantFromBuffer != nil {
				gotBytes := got.Bytes()
				buf := bytes.NewBuffer(gotBytes)
				bufLen := buf.Len()
				got2, err2 := deserializeHeader(buf)
				assert.NoErrorf(t, err2, "deserializeHeader(%#v) error = %v, wantErr %v", gotBytes, err2, tt.wantErr)
				assert.Equalf(t, tt.wantFromBuffer, got2, "deserializeHeader(%#v)", gotBytes)
				assert.Equal(t, gotBytes, got2.Bytes())
				assert.Equal(t, got.Bytes(), got2.Bytes())
				assert.Equal(t, got.Len(), got2.Len())
				assert.Equal(t, 0, buf.Len())
				assert.Equal(t, bufLen, got.Len())
				assert.Equal(t, bufLen, buf.Cap())

				assert.Equal(t, tt.wantFromBuffer.Version(), got2.Version())
				assert.Equal(t, tt.wantFromBuffer.AlgorithmSuite(), got2.AlgorithmSuite())
				assert.Equal(t, tt.wantFromBuffer.MessageID(), got2.MessageID())
				assert.Equal(t, tt.wantFromBuffer.AADLength(), got2.AADLength())
				assert.Equal(t, tt.wantFromBuffer.AADData(), got2.AADData())
				assert.Equal(t, tt.wantFromBuffer.EncryptedDataKeyCount(), got2.EncryptedDataKeyCount())
				assert.Equal(t, tt.wantFromBuffer.EncryptedDataKeys(), got2.EncryptedDataKeys())
				assert.Equal(t, tt.wantFromBuffer.ContentType(), got2.ContentType())
				assert.Equal(t, tt.wantFromBuffer.FrameLength(), got2.FrameLength())
				assert.Equal(t, tt.wantFromBuffer.Type(), got2.Type())
				assert.Equal(t, tt.wantFromBuffer.Reserved(), got2.Reserved())
				assert.Equal(t, tt.wantFromBuffer.IVLength(), got2.IVLength())
				assert.Equal(t, tt.wantFromBuffer.AlgorithmSuiteData(), got2.AlgorithmSuiteData())

			}
		})
	}
}

func concatSlices(slices ...[]byte) []byte {
	var result []byte
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}

func Test_deserializeHeader(t *testing.T) {
	type args struct {
		buf *bytes.Buffer
	}

	edk1Mock, _ := newEDK(awsKmsProviderID, "arn:aws:kms:eu-west-1:123454678901:key/80bd2fac-c07d-438a-837e-36e19bd4d320", []byte{0x1, 0x2, 0x1, 0x0, 0x78, 0xbc, 0x28, 0x8c, 0x86, 0xd0, 0x80, 0xa8, 0x5d, 0xd, 0x60, 0x4e, 0xe6, 0xce, 0x2b, 0x44, 0xb8, 0x2b, 0xd9, 0xcc, 0xe, 0x8, 0x4a, 0x48, 0x3f, 0x27, 0xc9, 0x83, 0xca, 0x67, 0x3e, 0xa2, 0x4d, 0x1, 0x93, 0xb8, 0xe7, 0x67, 0x85, 0x90, 0xf6, 0x34, 0x1, 0x53, 0xc2, 0x23, 0x11, 0x9e, 0xc4, 0xb3, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x40, 0x44, 0x5c, 0xc0, 0x2a, 0x7b, 0x82, 0xdb, 0x21, 0x33, 0x7e, 0x59, 0x2, 0x1, 0x10, 0x80, 0x3b, 0x8a, 0xce, 0xe2, 0x3f, 0xee, 0x84, 0x25, 0x1a, 0x8e, 0xc6, 0xa8, 0x3d, 0x26, 0x80, 0x48, 0x1d, 0x53, 0x45, 0x65, 0x35, 0xf, 0x6d, 0x8b, 0xed, 0x5c, 0xd4, 0x10, 0xda, 0xf6, 0xf1, 0x55, 0x22, 0xd1, 0x35, 0xe9, 0x4e, 0xc0, 0xc5, 0x2a, 0xa9, 0x5b, 0xa3, 0x3, 0xec, 0x21, 0x80, 0x97, 0x76, 0x6e, 0xb0, 0xa1, 0xcd, 0xce, 0xe7, 0x29, 0xcc, 0x16, 0xc, 0xfc})
	edk2Mock, _ := newEDK(awsKmsProviderID, "arn:aws:kms:eu-west-1:123454678901:key/e070dfa5-bf44-488d-afad-4d57c5c8f3c5", []byte{0x1, 0x2, 0x2, 0x0, 0x78, 0x34, 0x28, 0xaa, 0x31, 0x8a, 0xbd, 0x1b, 0x42, 0x22, 0x29, 0xae, 0x7, 0x25, 0xf8, 0x29, 0x5f, 0x17, 0xdb, 0x91, 0x25, 0xb7, 0xa4, 0x3e, 0x79, 0xf0, 0x86, 0xb9, 0x40, 0xd3, 0xdd, 0x2, 0x91, 0x1, 0x92, 0xe5, 0x3f, 0x75, 0x27, 0xc9, 0x2d, 0x7b, 0x3f, 0xc2, 0x74, 0xe3, 0x2e, 0xcb, 0x3e, 0xb2, 0x0, 0x0, 0x0, 0x7e, 0x30, 0x7c, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x6, 0xa0, 0x6f, 0x30, 0x6d, 0x2, 0x1, 0x0, 0x30, 0x68, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x7, 0x1, 0x30, 0x1e, 0x6, 0x9, 0x60, 0x86, 0x48, 0x1, 0x65, 0x3, 0x4, 0x1, 0x2e, 0x30, 0x11, 0x4, 0xc, 0x9, 0x46, 0x6, 0x3c, 0xe9, 0x7c, 0xf3, 0x80, 0xeb, 0x8b, 0x3a, 0x89, 0x2, 0x1, 0x10, 0x80, 0x3b, 0xd2, 0x9a, 0xfd, 0x12, 0xa1, 0x55, 0xd2, 0x5e, 0x1, 0x31, 0x9a, 0x6, 0x42, 0xd0, 0xa, 0xec, 0xa9, 0xed, 0xc3, 0x94, 0xa2, 0x43, 0x8d, 0xd1, 0x25, 0xce, 0x4a, 0x3c, 0x83, 0xdd, 0x15, 0x2d, 0x1, 0xa7, 0x1e, 0x20, 0x3, 0x6d, 0xa2, 0x4f, 0x3, 0x92, 0xb8, 0xe9, 0x88, 0xc7, 0x88, 0x74, 0x78, 0x1d, 0xfc, 0x9d, 0x52, 0x56, 0x27, 0x2c, 0xe, 0x13, 0xf8})

	aadMock1, _ := newAAD(map[string]string{"aws-crypto-public-key": "AyeV6x6xnVRv18vTtytzSID5DqpH6ejeNmGbU93PC/quQUnai2AgzTNLzJQglsZF2A==", "keyId": "4a5c8ebf-f7d0-4d09-88c3-5edb48539163", "orgId": "org-uuid-test", "someId": "someId-uuid-test"})

	messageFormatVersionV1 := []byte{0x1}
	messageFormatVersion := []byte{0x2}
	messageType := []byte{0x80} // V1
	algorithmIDV1 := []byte{0x1, 0x78}
	algorithmID := []byte{0x5, 0x78}
	messageID := []byte{0xf6, 0xd9, 0x0, 0x98, 0xba, 0xfb, 0x87, 0xc8, 0xe9, 0x79, 0xae, 0x71, 0xa5, 0x71, 0x10, 0x2d, 0xe5, 0x14, 0x45, 0x85, 0xd3, 0xde, 0xc4, 0xc3, 0x89, 0xcc, 0xdd, 0x23, 0xa5, 0x9e, 0xf, 0x96}
	messageIDV1 := []byte{0xf6, 0xd9, 0x0, 0x98, 0xba, 0xfb, 0x87, 0xc8, 0xe9, 0x79, 0xae, 0x71, 0xa5, 0x71, 0x10, 0x2d}
	aadLen := []byte{0x0, 0xbc} // 188
	aadDataBytes := []byte{0x0, 0x4, 0x0, 0x15, 0x61, 0x77, 0x73, 0x2d, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x0, 0x44, 0x41, 0x79, 0x65, 0x56, 0x36, 0x78, 0x36, 0x78, 0x6e, 0x56, 0x52, 0x76, 0x31, 0x38, 0x76, 0x54, 0x74, 0x79, 0x74, 0x7a, 0x53, 0x49, 0x44, 0x35, 0x44, 0x71, 0x70, 0x48, 0x36, 0x65, 0x6a, 0x65, 0x4e, 0x6d, 0x47, 0x62, 0x55, 0x39, 0x33, 0x50, 0x43, 0x2f, 0x71, 0x75, 0x51, 0x55, 0x6e, 0x61, 0x69, 0x32, 0x41, 0x67, 0x7a, 0x54, 0x4e, 0x4c, 0x7a, 0x4a, 0x51, 0x67, 0x6c, 0x73, 0x5a, 0x46, 0x32, 0x41, 0x3d, 0x3d, 0x0, 0x5, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x0, 0x24, 0x34, 0x61, 0x35, 0x63, 0x38, 0x65, 0x62, 0x66, 0x2d, 0x66, 0x37, 0x64, 0x30, 0x2d, 0x34, 0x64, 0x30, 0x39, 0x2d, 0x38, 0x38, 0x63, 0x33, 0x2d, 0x35, 0x65, 0x64, 0x62, 0x34, 0x38, 0x35, 0x33, 0x39, 0x31, 0x36, 0x33, 0x0, 0x5, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x0, 0xd, 0x6f, 0x72, 0x67, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x0, 0x6, 0x73, 0x6f, 0x6d, 0x65, 0x49, 0x64, 0x0, 0x10, 0x73, 0x6f, 0x6d, 0x65, 0x49, 0x64, 0x2d, 0x75, 0x75, 0x69, 0x64, 0x2d, 0x74, 0x65, 0x73, 0x74}
	edkCount := []byte{0x0, 0x2}
	// edk1 bytes and edk2 bytes from mocks
	contentType := []byte{0x2}
	frameLength := []byte{0x0, 0x0, 0x4, 0x0} // 1024
	algorithmSuiteData := []byte{0x52, 0xdf, 0xed, 0x4c, 0x0, 0xb4, 0xd7, 0x95, 0x2f, 0xa8, 0x3c, 0x81, 0xdb, 0xee, 0xbe, 0x7f, 0x55, 0x9d, 0x48, 0x3e, 0x27, 0xd4, 0x18, 0xb6, 0x94, 0x49, 0xfb, 0xb8, 0xa6, 0x60, 0xdc, 0xe2}

	reservedV1 := []uint8{0x00, 0x00, 0x00, 0x00}
	ivLen := []byte{0x0c} // 12

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

	mh1MockV1 := &messageHeaderV1{
		messageHeader: messageHeader{
			version:               suite.V1,
			algorithmSuite:        suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			messageID:             messageIDV1,
			aadLen:                188,
			authenticatedData:     aadMock1,
			encryptedDataKeyCount: 2,
			encryptedDataKeys:     []format.MessageEDK{edk1Mock, edk2Mock},
			contentType:           suite.FramedContent,
			frameLength:           1024,
		},
		messageType: format.CustomerAEData,
		reserved:    reservedV1,
		ivLen:       12,
	}

	tests := []struct {
		name    string
		args    args
		want    format.MessageHeader
		wantErr assert.ErrorAssertionFunc
	}{
		{"nilBuffer", args{nil}, nil, assert.Error},
		{"emptyBuffer", args{bytes.NewBuffer(nil)}, nil, assert.Error},
		{"emptyBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x02}, 54))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x02}, 55))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x01}, 55))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x00}, 55))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x05, 0x78}, 55))}, nil, assert.Error},
		{"invalidBuffer", args{bytes.NewBuffer(bytes.Repeat([]byte{0x78, 0x05}, 55))}, nil, assert.Error},

		{"incompleteBuffer_V1", args{bytes.NewBuffer(messageFormatVersionV1)}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(messageFormatVersion)}, nil, assert.Error},
		{"incompleteBuffer_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID))}, nil, assert.Error},

		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, make([]byte, 16)))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes))}, nil, assert.Error},
		{"incompleteBuffer_aadData_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, []byte{0x00, 0x04}, []byte{0x00, 0x04, 0x00, 0x02}))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount))}, nil, assert.Error},
		{"incompleteBuffer_zero_EDK_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, []byte{0x0, 0x0}))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes()))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes()))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType))}, nil, assert.Error},
		{"invalidContentType_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), []byte{0x1}))}, nil, assert.Error},
		{"incompleteBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, frameLength))}, nil, assert.Error},
		{"invalidFrameLength_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, []byte{0x00, 0x00, 0x03, 0xff}))}, nil, assert.Error}, // 1023 frame
		{"incompatibleVersion_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, frameLength))}, nil, assert.Error},
		{"incompatibleVersion_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmIDV1, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, frameLength))}, nil, assert.Error},
		{"validBuffer_V2", args{bytes.NewBuffer(concatSlices(messageFormatVersion, algorithmID, messageID, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, frameLength, algorithmSuiteData))}, mh1Mock, assert.NoError},

		{"incompleteBuffer_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1, messageIDV1, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType))}, nil, assert.Error},
		{"incompleteBuffer_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1, messageIDV1, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, reservedV1))}, nil, assert.Error},
		{"invalidReservedData_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1, messageIDV1, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, []byte{0x00, 0x00, 0x32, 0x00}))}, nil, assert.Error},
		{"incompleteBuffer_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1, messageIDV1, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, reservedV1, ivLen))}, nil, assert.Error},
		{"invalidIVLength_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1, messageIDV1, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, reservedV1, []byte{0x0f}))}, nil, assert.Error}, // ivLen 15
		{"validBuffer_V1", args{bytes.NewBuffer(concatSlices(messageFormatVersionV1, messageType, algorithmIDV1, messageIDV1, aadLen, aadDataBytes, edkCount, edk1Mock.Bytes(), edk2Mock.Bytes(), contentType, reservedV1, ivLen, frameLength))}, mh1MockV1, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deserializeHeader(tt.args.buf)
			if !tt.wantErr(t, err, fmt.Sprintf("deserializeHeader(%v)", tt.args.buf)) {
				return
			}
			assert.Equalf(t, tt.want, got, "deserializeHeader(%v)", tt.args.buf)
			if tt.want != nil {
				assert.Equal(t, tt.want.Bytes(), got.Bytes())
				assert.Equal(t, tt.want.Len(), got.Len())
				assert.Equal(t, tt.want.Version(), got.Version())
				assert.Equal(t, tt.want.AlgorithmSuite(), got.AlgorithmSuite())
				assert.Equal(t, tt.want.MessageID(), got.MessageID())
				assert.Equal(t, tt.want.AADLength(), got.AADLength())
				assert.Equal(t, tt.want.AADData(), got.AADData())
				assert.Equal(t, tt.want.EncryptedDataKeyCount(), got.EncryptedDataKeyCount())
				assert.Equal(t, tt.want.EncryptedDataKeys(), got.EncryptedDataKeys())
				assert.Equal(t, tt.want.ContentType(), got.ContentType())
				assert.Equal(t, tt.want.FrameLength(), got.FrameLength())
				assert.Equal(t, tt.want.Type(), got.Type())
				assert.Equal(t, tt.want.Reserved(), got.Reserved())
				assert.Equal(t, tt.want.IVLength(), got.IVLength())
				assert.Equal(t, tt.want.AlgorithmSuiteData(), got.AlgorithmSuiteData())
			}
		})
	}
}

func TestWriteAAD(t *testing.T) {
	tests := []struct {
		name          string
		aadLen        int
		mockBytes     []byte
		want          []byte
		wantBytesCall bool
		wantLenCall   bool
	}{
		{"Empty Buffer and Blank AAD", 0, nil, []byte{}, false, false},
		{"Empty Buffer and AADLen not zero", 5, nil, []byte{}, false, true},
		{"Filled Buffer and AADLen zero", 0, []byte("mockaad"), []byte{}, false, false},
		{"Filled Buffer and AADLen not zero", 5, []byte("mockaad"), []byte("mockaad"), true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockData := mocks.NewMockMessageAAD(t)
			if tt.wantLenCall {
				mockData.EXPECT().Len().Return(len(tt.mockBytes)).Once()
			}
			if tt.wantBytesCall {
				mockData.EXPECT().Bytes().Return(tt.mockBytes).Once()
			}
			buf := &[]byte{}
			writeAAD(buf, tt.aadLen, mockData)
			assert.Equal(t, tt.want, *buf, "Buffers should be equal")
		})
	}
}
