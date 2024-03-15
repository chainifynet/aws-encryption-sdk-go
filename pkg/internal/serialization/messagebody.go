// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var (
	errBodyDeserialize = errors.New("body deserialization error")
	errBodySerialize   = errors.New("body serialization error")
	errFrame           = errors.New("frame error")
)

var (
	//nolint:gochecknoglobals
	finalFrameIndicator = []uint8{0xFF, 0xFF, 0xFF, 0xFF} // 4, An indicator for the final frame. The value is encoded as the 4 bytes FF FF FF FF in hexadecimal notation.
)

type body struct {
	algorithmSuite *suite.AlgorithmSuite
	frameLength    int
	frames         []format.BodyFrame
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

func newBody(algorithmSuite *suite.AlgorithmSuite, frameLength int) (*body, error) {
	if algorithmSuite == nil {
		return nil, fmt.Errorf("empty algorithm suite: %w", errBodyDeserialize)
	}
	if frameLength == 0 {
		return nil, fmt.Errorf("frameLenght is 0: %w", errBodyDeserialize)
	}
	return &body{
		algorithmSuite: algorithmSuite,
		frameLength:    frameLength,
		frames:         make([]format.BodyFrame, 0),
		sequenceNumber: 1,
	}, nil
}

func deserializeBody(algorithmSuite *suite.AlgorithmSuite, frameLength int, buf *bytes.Buffer) (*body, error) {
	if buf == nil {
		return nil, fmt.Errorf("empty buffer: %w", errBodyDeserialize)
	}
	// early check if buffer has enough bytes to read sequence number
	//  or final frame indicator frameFieldBytes (4 bytes)
	if buf.Len() < frameFieldBytes {
		return nil, fmt.Errorf("malformed message: %w", errBodyDeserialize)
	}
	data, errBody := newBody(algorithmSuite, frameLength)
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
			return nil, fmt.Errorf("frame: %w", errors.Join(errBodyDeserialize, err))
		}
		if dFrame.sequenceNumber != data.sequenceNumber {
			return nil, fmt.Errorf("malformed message, frame sequence out of order: %w", errBodyDeserialize)
		}
		data.sequenceNumber++
		data.frames = append(data.frames, dFrame)
		if dFrame.isFinal {
			break
		}
	}
	return data, nil
}

func (b *body) Len() int {
	var framesLength int
	for _, f := range b.frames {
		framesLength += f.Len()
	}
	return framesLength
}

func (b *body) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, b.Len())
	for _, f := range b.frames {
		buf = append(buf, f.Bytes()...)
	}
	return buf
}

func (b *body) Frames() []format.BodyFrame {
	return b.frames
}

// AddFrame does business
func (b *body) AddFrame(final bool, seqNum int, IV []byte, contentLength int, ciphertext, authTag []byte) error {
	if seqNum != b.sequenceNumber {
		return fmt.Errorf("malformed message, frame sequence out of order: %w", errBodySerialize)
	}
	if b.algorithmSuite.EncryptionSuite.IVLen != len(IV) {
		return fmt.Errorf("IV length mismatch: %w", errBodySerialize)
	}
	if b.algorithmSuite.EncryptionSuite.AuthLen != len(authTag) {
		return fmt.Errorf("authTag length mismatch: %w", errBodySerialize)
	}
	if contentLength != len(ciphertext) {
		return fmt.Errorf("contentLength mismatch: %w", errBodySerialize)
	}

	b.frames = append(b.frames, &frame{
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

func (b *body) readFrame(buf *bytes.Buffer) (*frame, error) {
	if buf == nil {
		return nil, fmt.Errorf("empty buffer: %w", errFrame)
	}
	if buf.Len() < frameFieldBytes {
		return nil, fmt.Errorf("empty buffer, cant read seqNum or finalFrameIndicator: %w", errFrame)
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
		sequenceNumber, err := fieldReader.ReadFrameField(buf)
		if err != nil {
			return nil, fmt.Errorf("cant read sequenceNumber: %w", errors.Join(errFrame, err))
		}
		if buf.Len() < b.algorithmSuite.EncryptionSuite.IVLen {
			return nil, fmt.Errorf("empty buffer, cant read IV: %w", errFrame)
		}
		IV := buf.Next(b.algorithmSuite.EncryptionSuite.IVLen)
		contentLength, err := fieldReader.ReadFrameField(buf)
		if err != nil {
			return nil, fmt.Errorf("cant read contentLength: %w", errors.Join(errFrame, err))
		}

		// contentLength of final frame will be 0 if both conditions are met:
		// - frame length equals to content length (an extra empty frame)
		// - encryptedContent is empty
		// otherwise make sure buffer has enough bytes to read encryptedContent
		if contentLength != 0 && buf.Len() < contentLength {
			return nil, fmt.Errorf("empty buffer, cant read encryptedContent: %w", errFrame)
		}
		// with contentLength 0, it will return an empty slice.
		// The buffer's internal read position will not be advanced. nothing to worry about here.
		encryptedContent := buf.Next(contentLength)

		if buf.Len() < b.algorithmSuite.EncryptionSuite.AuthLen {
			return nil, fmt.Errorf("empty buffer, cant read authenticationTag: %w", errFrame)
		}
		authenticationTag := buf.Next(b.algorithmSuite.EncryptionSuite.AuthLen)
		return &frame{
			isFinal:           true,
			sequenceNumber:    sequenceNumber,
			iV:                IV,
			contentLength:     contentLength,
			encryptedContent:  encryptedContent,
			authenticationTag: authenticationTag,
		}, nil
	} else { //nolint:revive
		// at this point we know that this is NOT a final frame
		// sequenceNumber we already read as sequenceNumberOrFinal
		// so minimum available len in buffer must be:
		// 12: IV (suite.AlgorithmSuite.EncryptionSuite.IVLen) +
		// N: encryptedContent (b.frameLength) +
		// 16: authenticationTag (suite.AlgorithmSuite.EncryptionSuite.AuthLen)
		// 12 + N + 16 = 36 minimum bytes must be available in buffer in order to read a frame
		minBufferFrame := b.algorithmSuite.EncryptionSuite.IVLen + b.frameLength + b.algorithmSuite.EncryptionSuite.AuthLen
		if buf.Len() < minBufferFrame {
			return nil, fmt.Errorf("empty buffer, cant read a regular frame: %w", errFrame)
		}
		sequenceNumber := conv.FromBytes.Uint32IntBigEndian(sequenceNumberOrFinal)
		IV := buf.Next(b.algorithmSuite.EncryptionSuite.IVLen)
		encryptedContent := buf.Next(b.frameLength)
		authenticationTag := buf.Next(b.algorithmSuite.EncryptionSuite.AuthLen)
		return &frame{
			isFinal:           false,
			sequenceNumber:    sequenceNumber,
			iV:                IV,
			contentLength:     b.frameLength,
			encryptedContent:  encryptedContent,
			authenticationTag: authenticationTag,
		}, nil
	}
}

func (bf frame) Len() int {
	if bf.isFinal {
		return 4 + // isFinal
			4 + // sequenceNumber
			12 + // IV
			4 + // contentLength
			len(bf.encryptedContent) + // vary or 0 if frameLength == contentLength
			len(bf.authenticationTag) // must be 16
	} else { //nolint:revive
		return 4 + // sequenceNumber
			12 + // IV
			len(bf.encryptedContent) + // vary
			len(bf.authenticationTag) // must be 16
	}
}

func (bf frame) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, bf.Len())
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
