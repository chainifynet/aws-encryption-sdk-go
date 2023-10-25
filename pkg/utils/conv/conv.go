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
	return uint64(v)
}

func (fi fromInt) Uint16BigEndian(v int) []byte {
	ui := intUint16(v)
	return fi.UUint16BigEndian(ui)
}

func (fi fromInt) UUint16BigEndian(v uint16) []byte {
	bs := make([]byte, 0, 2)
	bs = append(bs, uint8(v>>8), uint8(v&0xff))
	return bs
}

func (fi fromInt) Uint32BigEndian(v int) []byte {
	ui := intUint32(v)
	return fi.uint32BigEndian(ui)
}

func (fi fromInt) uint32BigEndian(v uint32) []byte {
	bs := make([]byte, 0, 4)
	bs = append(bs, uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v&0xff))
	return bs
}

func (fi fromInt) Uint64BigEndian(v int) []byte {
	ui := intUint64(v)
	return fi.uint64BigEndian(ui)
}

func (fi fromInt) uint64BigEndian(v uint64) []byte {
	bs := make([]byte, 0, 8)
	bs = append(bs, uint8(v>>56), uint8(v>>48), uint8(v>>40), uint8(v>>32), uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v&0xff))
	return bs
}

func (fb fromBytes) Uint16IntBigEndian(data []byte) int {
	ui := fb.UUint16BigEndian(data)
	return int(ui)
}

func (fb fromBytes) UUint16BigEndian(data []byte) uint16 {
	ui := uint16(data[1]) | uint16(data[0])<<8
	return ui
}

func (fb fromBytes) Uint32IntBigEndian(data []byte) int {
	ui := fb.uint32BigEndian(data)
	return int(ui)
}

func (fb fromBytes) uint32BigEndian(data []byte) uint32 {
	ui := uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24
	return ui
}
