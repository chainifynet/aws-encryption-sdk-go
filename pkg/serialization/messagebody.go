// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

var (
	bodyDeserializeErr = errors.New("body deserialization error")
	bodySerializeErr   = errors.New("body serialization error")
	frameErr           = errors.New("frame error")
)

var (
	finalFrameIndicator = []uint8{0xFF, 0xFF, 0xFF, 0xFF} // 4, An indicator for the final frame. The value is encoded as the 4 bytes FF FF FF FF in hexadecimal notation.
)

var MessageBody messageBody

type messageBody struct{}

type body struct {
	algorithmSuite *suite.AlgorithmSuite
	frameLength    int
	frames         []frame
	sequenceNumber int
}

type frame struct {
	isFinal           bool   // 4, isFinal present if first 4 bytes in the frame equals to finalFrameIndicator
	sequenceNumber    int    // 4, The frame sequenceNumber. It is an incremental counter number for the frame. It is a 4-byte value interpreted as a 32-bit unsigned integer.
	iV                []byte // 12, Each 96-bit (12-byte) IV is concatenation of 64-bits zero's and frame sequenceNumber as a 32-bits unsigned int.
	contentLength     int    // 4, present if isFinal, otherwise len is body.frameLength, and field not present.
	encryptedContent  []byte // vary, encryptedContent
	authenticationTag []byte // 16, authenticationTag for the frame
}

func (mb messageBody) NewBody(algorithmSuite *suite.AlgorithmSuite, frameLength int) (*body, error) {
	if algorithmSuite == nil {
		return nil, fmt.Errorf("empty algorithm suite, %w", bodyDeserializeErr)
	}
	if frameLength == 0 {
		return nil, fmt.Errorf("frameLenght is 0, %w", bodyDeserializeErr)
	}
	return &body{
		algorithmSuite: algorithmSuite,
		frameLength:    frameLength,
		frames:         []frame{},
		sequenceNumber: 1,
	}, nil
}

func (mb messageBody) fromBuffer(algorithmSuite *suite.AlgorithmSuite, frameLength int, buf *bytes.Buffer) (*body, error) {
	if buf == nil {
		return nil, fmt.Errorf("empty buffer, %w", bodyDeserializeErr)
	}
	// early check if buffer has enough bytes to read sequence number
	//  or final frame indicator frameFieldBytes (4 bytes)
	if buf.Len() < frameFieldBytes {
		return nil, fmt.Errorf("malformed message, %w", bodyDeserializeErr)
	}
	data, errBody := mb.NewBody(algorithmSuite, frameLength)
	if errBody != nil {
		return nil, errBody
	}
	// The sequence number is the sequence number of the frame being encrypted.
	//  If this is the first frame sequentially, this value MUST be 1.
	//  Otherwise, this value MUST be 1 greater than
	//  the value of the sequence number of the previous frame.
	//  see https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md#construct-a-frame
	for {
		dFrame, err := data.readFrame(buf)
		if err != nil {
			return nil, fmt.Errorf("%v, %w", err, bodyDeserializeErr)
		}
		if dFrame.sequenceNumber != data.sequenceNumber {
			return nil, fmt.Errorf("malformed message, frame sequence out of order, %w", bodyDeserializeErr)
		}
		data.sequenceNumber++
		data.frames = append(data.frames, dFrame)
		if dFrame.isFinal {
			break
		}
	}
	return data, nil
}

func (b *body) len() int {
	var framesLength int
	for _, f := range b.frames {
		framesLength += f.len()
	}
	return framesLength
}

func (b *body) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, b.len())
	for _, f := range b.frames {
		buf = append(buf, f.Bytes()...)
	}
	return buf
}

func (b *body) Frames() []frame {
	return b.frames
}

// AddFrame does business
func (b *body) AddFrame(final bool, seqNum int, IV []byte, contentLength int, ciphertext, authTag []byte) error {
	if seqNum != b.sequenceNumber {
		return fmt.Errorf("malformed message, frame sequence out of order, %w", bodySerializeErr)
	}
	if b.algorithmSuite.EncryptionSuite.IVLen != len(IV) {
		return fmt.Errorf("IV length mismatch, %w", bodySerializeErr)
	}
	if b.algorithmSuite.EncryptionSuite.AuthLen != len(authTag) {
		return fmt.Errorf("authTag length mismatch, %w", bodySerializeErr)
	}
	if contentLength != len(ciphertext) {
		return fmt.Errorf("contentLength mismatch, %w", bodySerializeErr)
	}

	b.frames = append(b.frames, frame{
		isFinal:           final,
		sequenceNumber:    seqNum,
		iV:                IV,
		contentLength:     contentLength,
		encryptedContent:  ciphertext,
		authenticationTag: authTag,
	})
	b.sequenceNumber++
	return nil
}

func (b *body) readFrame(buf *bytes.Buffer) (frame, error) {
	if buf == nil {
		return frame{}, fmt.Errorf("empty buffer, %w", frameErr)
	}
	if buf.Len() < frameFieldBytes {
		return frame{}, fmt.Errorf("empty buffer, cant read seqNum or finalFrameIndicator, %w", frameErr)
	}

	sequenceNumberOrFinal := buf.Next(frameFieldBytes)
	if bytes.Equal(sequenceNumberOrFinal, finalFrameIndicator) {
		// at this point we know that this is final frame
		// so minimum available len in buffer must be:
		// 4: sequenceNumber +
		// 12: IV (suite.AlgorithmSuite.EncryptionSuite.IVLen) +
		// 4: contentLength field +
		// N (check before read): encryptedContent (contentLength) +
		// 16: authenticationTag (suite.AlgorithmSuite.EncryptionSuite.AuthLen)
		// 4 + 12 + 4 + N + 16 = 36 minimum bytes must be available in buffer in order to read a frame
		minBufferFrame := frameFieldBytes + b.algorithmSuite.EncryptionSuite.IVLen + frameFieldBytes +
			b.algorithmSuite.EncryptionSuite.AuthLen
		if buf.Len() < minBufferFrame {
			return frame{}, fmt.Errorf("empty buffer, cant read a final frame, %w", frameErr)
		}
		sequenceNumber, err := fieldReader.ReadFrameField(buf) // checked by minBufferFrame
		if err != nil {
			return frame{}, fmt.Errorf("cant read sequenceNumber, %v, %w", err, frameErr)
		}
		IV := buf.Next(b.algorithmSuite.EncryptionSuite.IVLen) // checked by minBufferFrame
		contentLength, err := fieldReader.ReadFrameField(buf)  // checked by minBufferFrame
		if err != nil {
			return frame{}, fmt.Errorf("cant read contentLength, %v, %w", err, frameErr)
		}

		// contentLength of final frame will be 0 if both conditions are met:
		// - frame length equals to content length (an extra empty frame)
		// - encryptedContent is empty
		// otherwise make sure buffer has enough bytes to read encryptedContent
		if contentLength != 0 && buf.Len() < contentLength {
			return frame{}, fmt.Errorf("empty buffer, cant read encryptedContent, %w", frameErr)
		}
		// with contentLength 0, it will return an empty slice.
		// The buffer's internal read position will not be advanced. nothing to worry about here.
		encryptedContent := buf.Next(contentLength)

		if buf.Len() < b.algorithmSuite.EncryptionSuite.AuthLen {
			return frame{}, fmt.Errorf("empty buffer, cant read authenticationTag, %w", frameErr)
		}
		authenticationTag := buf.Next(b.algorithmSuite.EncryptionSuite.AuthLen)
		return frame{
			isFinal:           true,
			sequenceNumber:    sequenceNumber,
			iV:                IV,
			contentLength:     contentLength,
			encryptedContent:  encryptedContent,
			authenticationTag: authenticationTag,
		}, nil
	} else {
		// at this point we know that this is NOT a final frame
		// sequenceNumber we already read as sequenceNumberOrFinal
		// so minimum available len in buffer must be:
		// 12: IV (suite.AlgorithmSuite.EncryptionSuite.IVLen) +
		// N: encryptedContent (b.frameLength) +
		// 16: authenticationTag (suite.AlgorithmSuite.EncryptionSuite.AuthLen)
		// 12 + N + 16 = 36 minimum bytes must be available in buffer in order to read a frame
		minBufferFrame := b.algorithmSuite.EncryptionSuite.IVLen + b.frameLength + b.algorithmSuite.EncryptionSuite.AuthLen
		if buf.Len() < minBufferFrame {
			return frame{}, fmt.Errorf("empty buffer, cant read a regular frame, %w", frameErr)
		}
		sequenceNumber := conv.FromBytes.Uint32IntBigEndian(sequenceNumberOrFinal)
		IV := buf.Next(b.algorithmSuite.EncryptionSuite.IVLen)
		encryptedContent := buf.Next(b.frameLength)
		authenticationTag := buf.Next(b.algorithmSuite.EncryptionSuite.AuthLen)
		return frame{
			isFinal:           false,
			sequenceNumber:    sequenceNumber,
			iV:                IV,
			contentLength:     b.frameLength,
			encryptedContent:  encryptedContent,
			authenticationTag: authenticationTag,
		}, nil
	}
}

func (bf frame) len() int {
	if bf.isFinal {
		return 4 + // isFinal
			4 + // sequenceNumber
			12 + // IV
			4 + // contentLength
			len(bf.encryptedContent) + // vary or 0 if frameLength == contentLength
			len(bf.authenticationTag) // must be 16
	} else {
		return 4 + // sequenceNumber
			12 + // IV
			len(bf.encryptedContent) + // vary
			len(bf.authenticationTag) // must be 16
	}
}

func (bf frame) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, bf.len())
	if bf.isFinal {
		buf = append(buf, finalFrameIndicator...)
	}
	buf = append(buf, conv.FromInt.Uint32BigEndian(bf.sequenceNumber)...)
	buf = append(buf, bf.iV...)
	if bf.isFinal {
		buf = append(buf, conv.FromInt.Uint32BigEndian(bf.contentLength)...)
	}
	buf = append(buf, bf.encryptedContent...)
	buf = append(buf, bf.authenticationTag...)
	return buf
}

func (bf frame) IsFinal() bool {
	return bf.isFinal
}

func (bf frame) SequenceNumber() int {
	return bf.sequenceNumber
}

func (bf frame) IV() []byte {
	return bf.iV
}

func (bf frame) EncryptedContent() []byte {
	return bf.encryptedContent
}

func (bf frame) AuthenticationTag() []byte {
	return bf.authenticationTag
}
