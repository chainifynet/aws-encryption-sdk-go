// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

var (
	errHeaderInvalidVersion = errors.New("invalid version, expected format version 2")
	errHeaderDeserialize    = errors.New("header deserialization error")
)

var (
	//nolint:gochecknoglobals
	reservedField = []uint8{0x00, 0x00, 0x00, 0x00} // 4, MessageHeader Reserved field. The value is encoded as the 4 bytes 00 00 00 00 in hexadecimal notation.
)

const (
	minimumHeaderBufferLen = int(18)
)

// All AES-GCM algorithm suites have a 12-byte initialization vector and a 16-byte AES-GCM authentication tag.
// reference https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/IV-reference.html

type messageHeader struct {
	version               suite.MessageFormatVersion // 1, comes from AlgorithmSuite, message version, always present.
	algorithmSuite        *suite.AlgorithmSuite      // 2, AlgorithmID in AlgorithmSuite, supported only 0x0578 (1400) and 0x0478 (1144), always present. Reference (https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html)
	messageID             []byte                     // 16 or 32, messageID (random 256-bit value). Always present. Algorithm suites with key commitment (algorithm ID 04xx and 05xx) for the extract step (HKDF with SHA-512) used as salt.
	aadLen                int                        // 2, aadLen is AAD Length (When the encryption context is empty, the value of the AAD Length field is 0), length AADData in bytes not including aadLen
	authenticatedData     format.MessageAAD          // authenticatedData is aadData Key-Value Pair (AADData) data (Key-Value Pair Count + []keyValuePair data). Bytes varies, aadLen = N bytes of AADData. present if aadLen > 0.
	encryptedDataKeyCount int                        // 2, EncryptedDataKeyCount is count of EncryptedDataKeys below, always present.
	encryptedDataKeys     []format.MessageEDK        // EncryptedDataKeys varies
	contentType           suite.ContentType          // 1, contentType is 0x01 Non-Framed or 0x02 Framed content
	frameLength           int                        // 4, frameLength is the length of each frame of framed data. It is a 4-byte value interpreted as a 32-bit unsigned integer that specifies the number of bytes in each frame. When the data is non-framed, that is, when the value of the contentType field is 0x01, this value must be 0.
}

type messageHeaderV1 struct {
	messageHeader
	messageType suite.MessageType // 1, format.MessageType, present only in V1
	reserved    []byte            // 4, reserved, present only in V1, always 0x00,0x00,0x00,0x00
	ivLen       int               // 1, length of IV, present only in V1, always 12
}

type messageHeaderV2 struct {
	messageHeader
	algorithmSuiteData []byte // 32 bytes, algorithmSuiteData aka commitmentKey, present only in V2
}

func newHeader(p format.HeaderParams) (format.MessageHeader, error) {
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

	authenticatedData, err := newAAD(p.EncryptionContext)
	if err != nil {
		return nil, fmt.Errorf("AADData: %w", err)
	}

	if err := suite.ValidateFrameLength(p.FrameLength); err != nil {
		return nil, fmt.Errorf("%v frame length out of range", p.FrameLength)
	}
	if err := suite.ValidateContentType(p.ContentType); err != nil {
		return nil, fmt.Errorf("contentType: %w", err)
	}

	header := messageHeader{
		version:               p.AlgorithmSuite.MessageFormatVersion,
		algorithmSuite:        p.AlgorithmSuite,
		messageID:             p.MessageID,
		aadLen:                authenticatedData.Len(),
		authenticatedData:     authenticatedData,
		encryptedDataKeyCount: len(p.EncryptedDataKeys),
		encryptedDataKeys:     p.EncryptedDataKeys,
		contentType:           p.ContentType,
		frameLength:           p.FrameLength,
	}

	if p.AlgorithmSuite.MessageFormatVersion == suite.V2 {
		return &messageHeaderV2{
			messageHeader:      header,
			algorithmSuiteData: p.AlgorithmSuiteData,
		}, nil
	}

	return &messageHeaderV1{
		messageHeader: header,
		messageType:   suite.CustomerAEData,
		reserved:      reservedField,
		ivLen:         p.AlgorithmSuite.EncryptionSuite.IVLen,
	}, nil
}

func deserializeHeader(buf *bytes.Buffer) (format.MessageHeader, error) { //nolint:cyclop,gocognit
	if buf == nil {
		return nil, fmt.Errorf("empty buffer: %w", errHeaderDeserialize)
	}
	if buf.Len() < minimumHeaderBufferLen {
		return nil, fmt.Errorf("buffer too small: %w", errHeaderDeserialize)
	}

	version := fieldReader.ReadSingleField(buf)

	if err := suite.ValidateMessageVersion(version); err != nil {
		return nil, fmt.Errorf("invalid version %v: %w", version, errHeaderDeserialize)
	}

	messageVersion := suite.MessageFormatVersion(version)

	if messageVersion == suite.V1 {
		messageType := fieldReader.ReadSingleField(buf)
		if suite.MessageType(messageType) != suite.CustomerAEData {
			return nil, fmt.Errorf("invalid messageType %v not supported: %w", messageType, errHeaderDeserialize)
		}
	}

	algorithmID := buf.Next(algorithmIDFieldBytes) // AlgorithmID is 2 bytes, uint16

	// validate AlgorithmID is supported
	algorithmSuite, err := suite.Algorithm.FromBytes(algorithmID)
	if err != nil {
		return nil, err
	}

	// validate message version is the same as AlgorithmSuite MessageFormatVersion
	if messageVersion != algorithmSuite.MessageFormatVersion {
		return nil, fmt.Errorf("%v message version not equal to Algorithm defined: %w", version, errHeaderInvalidVersion)
	}

	if buf.Len() < algorithmSuite.MessageIDLen() {
		return nil, fmt.Errorf("empty buffer, cant read messageID: %w", errHeaderDeserialize)
	}
	messageID := buf.Next(algorithmSuite.MessageIDLen())

	// here we ignore error since 0 is valid value for aadLen even with error
	// the rest will be handled by AADData.fromBuffer
	aadLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("empty buffer, cant read aadLen: %w", errHeaderDeserialize)
	}
	var encryptionContext suite.EncryptionContext
	if aadLen > 0 {
		if buf.Len() < aadLen {
			return nil, fmt.Errorf("empty buffer, cant read aadData: %w", errHeaderDeserialize)
		}
		messageAADData, err := deserializeAAD(buf)
		if err != nil {
			return nil, fmt.Errorf("AADData: %w", err)
		}
		encryptionContext = messageAADData.EncryptionContext()
	}

	_, encryptedDataKeys, err := EDK.fromBufferWithCount(buf)
	if err != nil {
		return nil, fmt.Errorf("header EDK: %w", err)
	}

	if buf.Len() < singleFieldBytes {
		return nil, fmt.Errorf("empty buffer, cant read contentType: %w", errHeaderDeserialize)
	}
	contentType := suite.ContentType(fieldReader.ReadSingleField(buf))
	if err := suite.ValidateContentType(contentType); err != nil {
		return nil, fmt.Errorf("ContentType %v not supported: %w", contentType, errHeaderDeserialize)
	}

	if messageVersion == suite.V1 {
		if buf.Len() < len(reservedField) {
			return nil, fmt.Errorf("empty buffer, cant read reservedField, %w", errHeaderDeserialize)
		}
		reserved := buf.Next(len(reservedField))
		if !bytes.Equal(reserved, reservedField) {
			return nil, fmt.Errorf("invalid reservedField, %w", errHeaderDeserialize)
		}

		if buf.Len() < singleFieldBytes {
			return nil, fmt.Errorf("empty buffer, cant read ivLen: %w", errHeaderDeserialize)
		}

		ivLen := fieldReader.ReadSingleField(buf)
		if int(ivLen) != algorithmSuite.EncryptionSuite.IVLen {
			return nil, fmt.Errorf("ivLen %v not supported: %w", ivLen, errHeaderDeserialize)
		}
	}

	frameLength, err := fieldReader.ReadFrameField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant read frameLength, %w", errHeaderDeserialize)
	}
	if err := suite.ValidateFrameLength(frameLength); err != nil {
		return nil, fmt.Errorf("%v frame length out of range: %w", frameLength, errHeaderDeserialize)
	}

	var algorithmSuiteData []byte
	if messageVersion == suite.V2 {
		if buf.Len() < algorithmSuite.AlgorithmSuiteDataLen() {
			return nil, fmt.Errorf("empty buffer, cant read algorithmSuiteData, %w", errHeaderDeserialize)
		}
		// should be 32, only for V2
		algorithmSuiteData = buf.Next(algorithmSuite.AlgorithmSuiteDataLen())
	}

	return newHeader(format.HeaderParams{
		AlgorithmSuite:     algorithmSuite,
		MessageID:          messageID,
		EncryptionContext:  encryptionContext,
		EncryptedDataKeys:  encryptedDataKeys,
		ContentType:        contentType,
		FrameLength:        frameLength,
		AlgorithmSuiteData: algorithmSuiteData,
	})
}

func (h *messageHeaderV1) Len() int {
	edkLen := 0
	for _, key := range h.encryptedDataKeys {
		edkLen += key.Len()
	}

	// 1 + 1 + 2 + 16 + 2 + 2 + 101 + 2 + 272 + 1 + 4 + 1 + 4
	return singleFieldBytes + // 1 MessageHeader version of AlgorithmSuite
		singleFieldBytes + // 1 MessageHeader type
		len(h.algorithmSuite.IDBytes()) + // 2 AlgorithmID of AlgorithmSuite
		len(h.messageID) + // 16 MessageID is 16 bytes for V1
		lenFieldBytes + // MessageHeader.aadLen field itself
		h.aadLen + // which is AADData.Len(), 0 if aadLen == 0
		countFieldBytes + // 2, MessageHeader.EncryptedDataKeyCount
		edkLen + // EncryptedDataKeys len
		singleFieldBytes + // 1, MessageHeader.contentType
		len(reservedField) + // 4, MessageHeader.Reserved
		singleFieldBytes + // 1, MessageHeader.IvLen
		len(conv.FromInt.Uint32BigEndian(h.frameLength)) // 4, MessageHeader.FrameLength
}

func (h *messageHeaderV1) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, h.Len())
	// 1, MessageFormatVersion of AlgorithmSuite
	// 1, MessageType
	buf = append(buf, uint8(h.algorithmSuite.MessageFormatVersion), uint8(h.messageType))
	buf = append(buf, h.algorithmSuite.IDBytes()...)                            // 2, AlgorithmID of AlgorithmSuite
	buf = append(buf, h.messageID...)                                           // 16
	buf = append(buf, conv.FromInt.Uint16BigEndian(h.aadLen)...)                // 2
	writeAAD(&buf, h.aadLen, h.authenticatedData)                               // 2(count) + 25 + 29 + 45 = 101
	buf = append(buf, conv.FromInt.Uint16BigEndian(h.encryptedDataKeyCount)...) // 2
	writeEncryptedDataKeys(&buf, h.encryptedDataKeys)                           // 272
	buf = append(buf, uint8(h.contentType))                                     // 1
	buf = append(buf, reservedField...)                                         // 4, Reserved
	buf = append(buf, uint8(h.ivLen))                                           // 1, IvLen
	buf = append(buf, conv.FromInt.Uint32BigEndian(h.frameLength)...)           // 4
	return buf
}

func (h *messageHeaderV2) Len() int {
	edkLen := 0
	for _, key := range h.encryptedDataKeys {
		edkLen += key.Len()
	}

	// 1 + 32 + 2 + 2 + 101 + 2 + 272 + 1 + 4 + 32
	return singleFieldBytes + // MessageHeader version of AlgorithmSuite
		len(h.algorithmSuite.IDBytes()) + // AlgorithmID of AlgorithmSuite
		len(h.messageID) +
		lenFieldBytes + // MessageHeader.aadLen field itself
		h.aadLen + // whi  ch is AADData.Len(), 0 if aadLen == 0
		countFieldBytes + // MessageHeader.EncryptedDataKeyCount
		edkLen +
		singleFieldBytes + // MessageHeader.contentType
		len(conv.FromInt.Uint32BigEndian(h.frameLength)) + // MessageHeader.FrameLength
		len(h.algorithmSuiteData)
}

func (h *messageHeaderV2) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, h.Len())
	buf = append(buf, uint8(h.algorithmSuite.MessageFormatVersion))             // 1, MessageFormatVersion of AlgorithmSuite
	buf = append(buf, h.algorithmSuite.IDBytes()...)                            // 2, AlgorithmID of AlgorithmSuite
	buf = append(buf, h.messageID...)                                           // 32
	buf = append(buf, conv.FromInt.Uint16BigEndian(h.aadLen)...)                // 2
	writeAAD(&buf, h.aadLen, h.authenticatedData)                               // 2(count) + 25 + 29 + 45 = 101
	buf = append(buf, conv.FromInt.Uint16BigEndian(h.encryptedDataKeyCount)...) // 2
	writeEncryptedDataKeys(&buf, h.encryptedDataKeys)                           // 272
	buf = append(buf, uint8(h.contentType))                                     // 1
	buf = append(buf, conv.FromInt.Uint32BigEndian(h.frameLength)...)           // 4
	buf = append(buf, h.algorithmSuiteData...)                                  // 32
	return buf
}

func (h *messageHeader) Version() suite.MessageFormatVersion {
	return h.version
}

func (h *messageHeader) AlgorithmSuite() *suite.AlgorithmSuite {
	return h.algorithmSuite
}

func (h *messageHeader) MessageID() []byte {
	return h.messageID
}

func (h *messageHeader) AADLength() int {
	return h.aadLen
}

func (h *messageHeader) AADData() format.MessageAAD {
	return h.authenticatedData
}

func (h *messageHeader) EncryptedDataKeyCount() int {
	return h.encryptedDataKeyCount
}

func (h *messageHeader) EncryptedDataKeys() []format.MessageEDK {
	return h.encryptedDataKeys
}

func (h *messageHeader) ContentType() suite.ContentType {
	return h.contentType
}

func (h *messageHeader) FrameLength() int {
	return h.frameLength
}

func (h *messageHeaderV1) Type() suite.MessageType {
	return h.messageType
}

func (h *messageHeaderV1) Reserved() []byte {
	return h.reserved
}

func (h *messageHeaderV1) IVLength() int {
	return h.ivLen
}

func (h *messageHeaderV1) AlgorithmSuiteData() []byte {
	return nil
}

func (h *messageHeaderV2) Type() suite.MessageType {
	return 0
}

func (h *messageHeaderV2) Reserved() []byte {
	return nil
}

func (h *messageHeaderV2) IVLength() int {
	return 0
}

func (h *messageHeaderV2) AlgorithmSuiteData() []byte {
	return h.algorithmSuiteData
}

func writeAAD(buf *[]byte, aadLen int, data format.MessageAAD) {
	if aadLen > 0 && data.Len() > 0 {
		*buf = append(*buf, data.Bytes()...) // 2(count) + 25 + 29 + 45 = 101
	}
}

func writeEncryptedDataKeys(buf *[]byte, edks []format.MessageEDK) {
	for _, key := range edks {
		*buf = append(*buf, key.Bytes()...) // 272
	}
}
