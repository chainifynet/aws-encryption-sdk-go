// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

var (
	errHeaderInvalidVersion = errors.New("invalid version, expected format version 2")
	errHeaderDeserialize    = errors.New("header deserialization error")
)

const (
	minimumHeaderBufferLen = int(77)
)

// All AES-GCM algorithm suites have a 12-byte initialization vector and a 16-byte AES-GCM authentication tag.
// reference https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/IV-reference.html

var EncryptedMessageHeader emh //nolint:gochecknoglobals

type emh struct{}

type MessageHeader struct {
	// 											// 1, comes from AlgorithmSuite, message version, supported only version 2, always present as 0x02.
	AlgorithmSuite        *suite.AlgorithmSuite // 2, AlgorithmID in AlgorithmSuite, supported only 0x0578 (1400) and 0x0478 (1144), always present. Reference (https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html)
	MessageID             []byte                // 32, MessageID (random 256-bit value). Always present. Algorithm suites with key commitment (algorithm ID 04xx and 05xx) for the extract step (HKDF with SHA-512) used as salt.
	aadLen                int                   // 2, aadLen is AAD Length (When the encryption context is empty, the value of the AAD Length field is 0), length AADData in bytes not including aadLen
	AADData               *aadData              // AADData is AAD Key-Value Pair (AADData) data (Key-Value Pair Count + []keyValuePair data). Bytes varies, aadLen = N bytes of AADData. present if aadLen > 0.
	EncryptedDataKeyCount int                   // 2, EncryptedDataKeyCount is count of EncryptedDataKeys below, always present.
	EncryptedDataKeys     []encryptedDataKey    // EncryptedDataKeys varies
	contentType           suite.ContentType     // 2, contentType is 0x01 Non-Framed or 0x02 Framed content
	FrameLength           int                   // 4, FrameLength is the length of each frame of framed data. It is a 4-byte value interpreted as a 32-bit unsigned integer that specifies the number of bytes in each frame. When the data is non-framed, that is, when the value of the contentType field is 0x01, this value must be 0.
	AlgorithmSuiteData    []byte                // 32 bytes, AlgorithmSuiteData
}

type MessageHeaderParams struct {
	AlgorithmSuite     *suite.AlgorithmSuite
	MessageID          []byte
	AADData            *aadData
	EncryptedDataKeys  []encryptedDataKey
	ContentType        suite.ContentType
	FrameLength        int
	AlgorithmSuiteData []byte
}

func (mh emh) New(p MessageHeaderParams) (*MessageHeader, error) {
	if p.AlgorithmSuite == nil {
		return nil, fmt.Errorf("invalid AlgorithmSuite: %v", p.AlgorithmSuite)
	}
	_, err := suite.Algorithm.ByID(p.AlgorithmSuite.AlgorithmID)
	if err != nil {
		return nil, fmt.Errorf("unsupported AlgorithmID: %w", err)
	}
	if len(p.MessageID) != p.AlgorithmSuite.MessageIDLen() {
		return nil, fmt.Errorf("invalid MessageID length")
	}
	if len(p.EncryptedDataKeys) == 0 {
		return nil, fmt.Errorf("no dataKeys for messageHeader")
	}
	if len(p.AlgorithmSuiteData) != p.AlgorithmSuite.AlgorithmSuiteDataLen() {
		return nil, fmt.Errorf("invalid AlgorithmSuiteData length")
	}
	aadLen := 0
	if p.AADData != nil {
		aadLen = p.AADData.Len()
		//return nil, fmt.Errorf("invalid AADData: %v", p.AADData)
	}
	if p.FrameLength < suite.MinFrameSize || p.FrameLength > suite.MaxFrameSize {
		return nil, fmt.Errorf("%v frame length out of range", p.FrameLength)
	}
	if p.ContentType != suite.FramedContent {
		return nil, fmt.Errorf("ContentType %v not supported", p.ContentType)
	}

	return &MessageHeader{
		AlgorithmSuite:        p.AlgorithmSuite,
		MessageID:             p.MessageID,
		aadLen:                aadLen,
		AADData:               p.AADData,
		EncryptedDataKeyCount: len(p.EncryptedDataKeys),
		EncryptedDataKeys:     p.EncryptedDataKeys,
		contentType:           p.ContentType,
		FrameLength:           p.FrameLength,
		AlgorithmSuiteData:    p.AlgorithmSuiteData,
	}, nil
}

//go:cover ignore
func (mh MessageHeader) String() string {
	return fmt.Sprintf("%#v", mh)
}

func (mh MessageHeader) Len() int {
	edkLen := 0
	for _, key := range mh.EncryptedDataKeys {
		edkLen += key.len()
	}

	// 1 + 32 + 2 + 2 + 101 + 2 + 272 + 1 + 4 + 32
	return singleFieldBytes + // MessageHeader version of AlgorithmSuite
		len(mh.AlgorithmSuite.IDBytes()) + // AlgorithmID of AlgorithmSuite
		len(mh.MessageID) +
		lenFieldBytes + // MessageHeader.aadLen field itself
		mh.aadLen + // which is AADData.Len(), 0 if aadLen == 0
		countFieldBytes + // MessageHeader.EncryptedDataKeyCount
		edkLen +
		singleFieldBytes + // MessageHeader.contentType
		len(conv.FromInt.Uint32BigEndian(mh.FrameLength)) + // MessageHeader.FrameLength
		len(mh.AlgorithmSuiteData)
}

func (mh MessageHeader) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, mh.Len())
	buf = append(buf, uint8(mh.AlgorithmSuite.MessageFormatVersion)) // 1, MessageFormatVersion of AlgorithmSuite
	buf = append(buf, mh.AlgorithmSuite.IDBytes()...)                // 2, AlgorithmID of AlgorithmSuite
	buf = append(buf, mh.MessageID...)                               // 32
	buf = append(buf, conv.FromInt.Uint16BigEndian(mh.aadLen)...)    // 2
	if mh.aadLen > 0 && mh.AADData != nil {
		buf = append(buf, mh.AADData.Bytes()...) // 2(count) + 25 + 29 + 45 = 101
	}
	buf = append(buf, conv.FromInt.Uint16BigEndian(mh.EncryptedDataKeyCount)...) // 2
	for _, key := range mh.EncryptedDataKeys {
		buf = append(buf, key.bytes()...) // 272
	}
	buf = append(buf, uint8(mh.contentType))                           // 1
	buf = append(buf, conv.FromInt.Uint32BigEndian(mh.FrameLength)...) // 4
	buf = append(buf, mh.AlgorithmSuiteData...)                        // 32
	return buf
}

func (mh emh) fromBuffer(buf *bytes.Buffer) (*MessageHeader, error) {
	if buf == nil {
		return nil, fmt.Errorf("empty buffer: %w", errHeaderDeserialize)
	}
	if buf.Len() < minimumHeaderBufferLen {
		return nil, fmt.Errorf("buffer too small: %w", errHeaderDeserialize)
	}

	version := fieldReader.ReadSingleField(buf)

	algorithmID := buf.Next(algorithmIDFieldBytes) // AlgorithmID is 2 bytes, uint16

	// validate AlgorithmID is supported
	algorithmSuite, err := suite.Algorithm.FromBytes(algorithmID)
	if err != nil {
		return nil, err
	}

	// validate message version is the same as AlgorithmSuite MessageFormatVersion
	if int(version) != algorithmSuite.MessageFormatVersion {
		return nil, fmt.Errorf("%v message version not equal to Algorithm defined: %w", version, errHeaderInvalidVersion)
	}

	messageID := buf.Next(algorithmSuite.MessageIDLen())

	// here we ignore error since 0 is valid value for aadLen even with error
	// the rest will be handled by AADData.fromBuffer
	aadLen, _ := fieldReader.ReadLenField(buf)
	var aadData *aadData
	if aadLen > 0 {
		aadData = AAD.FromBuffer(buf)
	}

	// TODO support limit encrypted data keys feature when decrypt
	// TODO andrew done in encryptionsdk/serialization/deserialize.go:16
	//encryptedDataKeyCount, encryptedDataKeys, err := EDK.fromBufferWithCount(buf)
	_, encryptedDataKeys, err := EDK.fromBufferWithCount(buf)
	if err != nil {
		return nil, fmt.Errorf("header EDK: %w", err)
	}

	if buf.Len() < singleFieldBytes {
		return nil, fmt.Errorf("empty buffer, cant read contentType: %w", errHeaderDeserialize)
	}
	contentType := fieldReader.ReadSingleField(buf)
	if suite.ContentType(contentType) != suite.FramedContent {
		return nil, fmt.Errorf("ContentType %v not supported: %w", contentType, errHeaderDeserialize)
	}

	frameLength, err := fieldReader.ReadFrameField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant read frameLength, %w", errHeaderDeserialize)
	}
	// validate min(128) and max(maxUint32) frame len
	if frameLength < suite.MinFrameSize || frameLength > suite.MaxFrameSize {
		return nil, fmt.Errorf("%v frame length out of range: %w", frameLength, errHeaderDeserialize)
	}

	if buf.Len() < algorithmSuite.AlgorithmSuiteDataLen() {
		return nil, fmt.Errorf("empty buffer, cant read algorithmSuiteData, %w", errHeaderDeserialize)
	}
	// should be 32
	algorithmSuiteData := buf.Next(algorithmSuite.AlgorithmSuiteDataLen())

	log.Trace().MsgFunc(logger.FmtHex("AlgorithmSuiteData", algorithmSuiteData))

	return mh.New(MessageHeaderParams{
		MessageID:          messageID,
		AlgorithmSuite:     algorithmSuite,
		AADData:            aadData,
		EncryptedDataKeys:  encryptedDataKeys,
		ContentType:        suite.ContentType(contentType),
		FrameLength:        frameLength,
		AlgorithmSuiteData: algorithmSuiteData,
	})
}
