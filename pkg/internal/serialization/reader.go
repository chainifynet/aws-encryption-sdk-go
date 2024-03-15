// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
)

var fieldReader bufReader //nolint:gochecknoglobals

type bufReader struct{}

func (br bufReader) readLenFieldBytes(buf []byte) int {
	return conv.FromBytes.Uint16IntBigEndian(buf)
}

func (br bufReader) ReadLenField(b *bytes.Buffer) (int, error) {
	if err := br.checkBuffer(b, lenFieldBytes); err != nil {
		return 0, err
	}
	fieldBytes := b.Next(lenFieldBytes)
	return br.readLenFieldBytes(fieldBytes), nil
}

func (br bufReader) readCountFieldBytes(buf []byte) int {
	return conv.FromBytes.Uint16IntBigEndian(buf)
}

func (br bufReader) ReadCountField(b *bytes.Buffer) (int, error) {
	if err := br.checkBuffer(b, countFieldBytes); err != nil {
		return 0, err
	}
	fieldBytes := b.Next(countFieldBytes)
	return br.readCountFieldBytes(fieldBytes), nil
}

func (br bufReader) readSingleFieldByte(buf []byte) uint8 {
	// bulletproof check
	_ = buf[0]
	return buf[0]
}

func (br bufReader) ReadSingleField(b *bytes.Buffer) uint8 {
	// TODO andrew refactor to use checkBuffer and return (uint8, error)
	fieldBytes := b.Next(singleFieldBytes)
	return br.readSingleFieldByte(fieldBytes)
}

func (br bufReader) readFrameField(buf []byte) int {
	return conv.FromBytes.Uint32IntBigEndian(buf)
}

// ReadFrameField reads a frame field from the provided bytes.Buffer.
// It ensures that the buffer has at least `frameFieldBytes` length.
// If the buffer passes the checks, the function reads the field and returns its integer representation.
//
// Parameters:
//   - b: the bytes.Buffer from which to read the frame field.
//
// Returns:
//   - an integer representation of the frame field read from the buffer.
//   - an error if the buffer is nil or doesn't have enough bytes to read the frame field.
func (br bufReader) ReadFrameField(b *bytes.Buffer) (int, error) {
	if err := br.checkBuffer(b, frameFieldBytes); err != nil {
		return 0, err
	}
	fieldBytes := b.Next(frameFieldBytes)
	return br.readFrameField(fieldBytes), nil
}

// checkBuffer checks if a given bytes.Buffer is valid and if it has at least `n` bytes available for reading.
//
// Parameters:
//   - b: the bytes.Buffer to check.
//   - n: the minimum number of bytes the buffer should have.
//
// Returns:
//   - nil if the buffer is valid and has enough bytes.
//   - an error if the buffer is nil or doesn't have enough bytes.
func (br bufReader) checkBuffer(b *bytes.Buffer, n int) error {
	if b == nil {
		return fmt.Errorf("buffer is nil")
	}
	if b.Len() < n {
		return fmt.Errorf("cant read numBytes")
	}
	return nil
}
