// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conv

import (
	"math"
)

var FromInt fromInt
var FromBytes fromBytes

type fromInt struct{}
type fromBytes struct{}

func intUint16(v int) uint16 {
	if v > math.MaxUint16 || v < 0 {
		panic("int value out of range unsigned 16-bit integer")
	}
	return uint16(v)
}

func intUint32(v int) uint32 {
	if v > math.MaxUint32 || v < 0 {
		panic("int value out of range unsigned 32-bit integer")
	}
	return uint32(v)
}

func intUint64(v int) uint64 {
	if v < 0 {
		panic("int value out of range unsigned 64-bit integer")
	}
	return uint64(v)
}

func (fi fromInt) Uint16BigEndian(v int) []byte {
	return fi.UUint16BigEndian(intUint16(v))
}

func (fi fromInt) UUint16BigEndian(v uint16) []byte {
	bs := make([]byte, 0, 2)
	bs = append(bs, uint8(v>>8), uint8(v&0xff))
	return bs
}

func (fi fromInt) Uint32BigEndian(v int) []byte {
	return fi.uint32BigEndian(intUint32(v))
}

func (fi fromInt) uint32BigEndian(v uint32) []byte {
	bs := make([]byte, 0, 4)
	bs = append(bs, uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v&0xff))
	return bs
}

func (fi fromInt) Uint64BigEndian(v int) []byte {
	return fi.uint64BigEndian(intUint64(v))
}

func (fi fromInt) uint64BigEndian(v uint64) []byte {
	bs := make([]byte, 0, 8)
	bs = append(bs, uint8(v>>56), uint8(v>>48), uint8(v>>40), uint8(v>>32), uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v&0xff))
	return bs
}

func (fb fromBytes) Uint16IntBigEndian(data []byte) int {
	return int(fb.UUint16BigEndian(data))
}

func (fb fromBytes) UUint16BigEndian(data []byte) uint16 {
	if len(data) < 2 {
		panic("not enough bytes to convert to uint16")
	}
	ui := uint16(data[1]) | uint16(data[0])<<8
	return ui
}

func (fb fromBytes) Uint32IntBigEndian(data []byte) int {
	return int(fb.uint32BigEndian(data))
}

func (fb fromBytes) uint32BigEndian(data []byte) uint32 {
	if len(data) < 4 {
		panic("not enough bytes to convert to uint32")
	}
	ui := uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24
	return ui
}
