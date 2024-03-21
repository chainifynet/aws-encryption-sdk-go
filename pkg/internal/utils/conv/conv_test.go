// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conv

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_intUint16(t *testing.T) {
	tests := []struct {
		name   string
		v      int
		want   uint16
		panics bool
	}{
		{"zero", 0, 0, false},
		{"max", math.MaxUint16, math.MaxUint16, false},
		{"more than uint16", math.MaxUint16 + 1, 0, true},
		{"min", 1, 1, false},
		{"negative", -1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				assert.Panics(t, func() { intUint16(tt.v) })
				return
			}
			assert.Equalf(t, tt.want, intUint16(tt.v), "intUint16(%v)", tt.v)
		})
	}
}

func Test_intUint32(t *testing.T) {
	tests := []struct {
		name   string
		v      int
		want   uint32
		panics bool
	}{
		{"zero", 0, 0, false},
		{"max", 4294967295, 4294967295, false},
		{"more than uint32", 4294967296, 0, true},
		{"min", 1, 1, false},
		{"negative", -1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				assert.Panics(t, func() { intUint32(tt.v) })
				return
			}
			assert.Equalf(t, tt.want, intUint32(tt.v), "intUint32(%v)", tt.v)
		})
	}
}

func Test_intUint64(t *testing.T) {
	tests := []struct {
		name   string
		v      int
		want   uint64
		panics bool
	}{
		{"zero", 0, 0, false},
		{"max", 4294967295, 4294967295, false},
		{"min", 1, 1, false},
		{"negative", -1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				assert.Panics(t, func() { intUint64(tt.v) })
				return
			}
			assert.Equalf(t, tt.want, intUint64(tt.v), "intUint64(%v)", tt.v)
		})
	}
}

func Test_fromInt_Uint16BigEndian(t *testing.T) {
	tests := []struct {
		name string
		v    int
		want []byte
	}{
		{
			name: "Min",
			v:    0,
			want: []byte{0, 0},
		},
		{
			name: "Middle value",
			v:    32767,
			want: []byte{127, 255},
		},
		{
			name: "Middle second byte",
			v:    40000,
			want: []byte{0x9c, 0x40},
		},
		{
			name: "Max",
			v:    math.MaxUint16,
			want: []byte{255, 255},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fromInt{}
			assert.Equalf(t, tt.want, fi.Uint16BigEndian(tt.v), "Uint16BigEndian(%v)", tt.v)
		})
	}
}

func Test_fromInt_UUint16BigEndian(t *testing.T) {
	tests := []struct {
		name string
		v    uint16
		want []byte
	}{
		{
			name: "Min",
			v:    0,
			want: []byte{0, 0},
		},
		{
			name: "Middle value",
			v:    32767,
			want: []byte{127, 255},
		},
		{
			name: "Middle second byte",
			v:    40000,
			want: []byte{0x9c, 0x40},
		},
		{
			name: "Max",
			v:    math.MaxUint16,
			want: []byte{255, 255},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fromInt{}
			assert.Equalf(t, tt.want, fi.UUint16BigEndian(tt.v), "UUint16BigEndian(%v)", tt.v)
		})
	}
}

func Test_fromInt_Uint32BigEndian(t *testing.T) {
	tests := []struct {
		name string
		v    int
		want []byte
	}{
		{
			name: "Min",
			v:    0,
			want: []byte{0, 0, 0, 0},
		},
		{
			name: "One",
			v:    1,
			want: []byte{0, 0, 0, 1},
		},
		{
			name: "Middle value",
			v:    32767,
			want: []byte{0, 0, 127, 255},
		},
		{
			name: "Middle second byte",
			v:    40000,
			want: []byte{0x0, 0x0, 0x9c, 0x40},
		},
		{
			name: "Max Int32",
			v:    2147483647,
			want: []byte{0x7f, 0xff, 0xff, 0xff},
		},
		{
			name: "Max",
			v:    math.MaxUint32,
			want: []byte{255, 255, 255, 255},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fromInt{}
			assert.Equalf(t, tt.want, fi.Uint32BigEndian(tt.v), "Uint32BigEndian(%v)", tt.v)
		})
	}
}

func Test_fromInt_Uint64BigEndian(t *testing.T) {
	tests := []struct {
		name string
		v    int
		want []byte
	}{
		{
			name: "Zero",
			v:    0,
			want: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "One",
			v:    1,
			want: []byte{0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "Middle value",
			v:    32767,
			want: []byte{0, 0, 0, 0, 0, 0, 127, 255},
		},
		{
			name: "Middle second byte",
			v:    40000,
			want: []byte{0, 0, 0, 0, 0x0, 0x0, 0x9c, 0x40},
		},
		{
			name: "Max Int32",
			v:    2147483647,
			want: []byte{0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff},
		},
		{
			name: "Max",
			v:    math.MaxUint32,
			want: []byte{0, 0, 0, 0, 255, 255, 255, 255},
		},
		{
			name: "Max uint32 plus 32767",
			v:    math.MaxUint32 + 32767,
			want: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x7f, 0xfe},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fromInt{}
			assert.Equalf(t, tt.want, fi.Uint64BigEndian(tt.v), "Uint64BigEndian(%v)", tt.v)
		})
	}
}

func Test_fromBytes_UUint16BigEndian(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		want   uint16
		panics bool
	}{
		{
			name:   "empty data",
			data:   []byte{},
			want:   0,
			panics: true,
		},
		{
			name:   "nil data",
			data:   nil,
			want:   0,
			panics: true,
		},
		{
			name:   "single byte",
			data:   []byte{0x55},
			want:   0,
			panics: true,
		},
		{
			name: "two bytes",
			data: []byte{0x7f, 0xff},
			want: 32767,
		},
		{
			name: "maximum value",
			data: []byte{0xff, 0xff},
			want: math.MaxUint16,
		},
		{
			name: "more than two bytes",
			data: []byte{0xff, 0xff, 0x7f},
			want: math.MaxUint16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := fromBytes{}
			if tt.panics {
				assert.Panics(t, func() { fb.UUint16BigEndian(tt.data) })
				return
			}
			assert.Equalf(t, tt.want, fb.UUint16BigEndian(tt.data), "UUint16BigEndian(%v)", tt.data)
			assert.EqualValuesf(t, tt.want, fb.Uint16IntBigEndian(tt.data), "Uint16IntBigEndian(%v)", tt.data)
		})
	}
}

func Test_fromBytes_Uint32IntBigEndian(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		want   int
		panics bool
	}{
		{
			name:   "empty data",
			data:   []byte{},
			want:   0,
			panics: true,
		},
		{
			name:   "nil data",
			data:   nil,
			want:   0,
			panics: true,
		},
		{
			name:   "single byte",
			data:   []byte{0x55},
			want:   0,
			panics: true,
		},
		{
			name:   "three bytes",
			data:   []byte{0x55, 0xff, 0xff},
			want:   0,
			panics: true,
		},
		{
			name: "Middle value",
			data: []byte{0, 0, 127, 255},
			want: 32767,
		},
		{
			name: "Middle second byte",
			data: []byte{0x0, 0x0, 0x9c, 0x40},
			want: 40000,
		},
		{
			name: "Max Int32",
			data: []byte{0x7f, 0xff, 0xff, 0xff},
			want: 2147483647,
		},
		{
			name: "Max",
			data: []byte{255, 255, 255, 255},
			want: math.MaxUint32,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := fromBytes{}
			if tt.panics {
				assert.Panics(t, func() { fb.Uint32IntBigEndian(tt.data) })
				return
			}
			assert.Equalf(t, tt.want, fb.Uint32IntBigEndian(tt.data), "Uint32IntBigEndian(%v)", tt.data)
		})
	}
}
