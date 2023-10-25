// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"testing"
)

func TestReadFrameField(t *testing.T) {
	// frameFieldBytes is 4
	tests := []struct {
		name      string
		input     *bytes.Buffer
		want      int
		wantErr   bool
		errString string
	}{
		{name: "Test with nil buffer", input: nil, want: 0, wantErr: true, errString: "buffer is nil"},
		{name: "Test with short buffer", input: bytes.NewBuffer([]byte{0x01, 0x02, 0x03}), want: 0, wantErr: true, errString: "cant read numBytes"},
		// 0x0102 in decimal is 258
		{name: "Test normal buffer read", input: bytes.NewBuffer([]byte{0x00, 0x00, 0x01, 0x02}), want: 258, wantErr: false, errString: ""},
		{name: "Test normal buffer read", input: bytes.NewBuffer([]byte{0x00, 0x00, 0x01, 0x02, 0x03}), want: 258, wantErr: false, errString: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fieldReader.ReadFrameField(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFrameField() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.errString {
				t.Errorf("ReadFrameField() error = %v, wantErr %v", err, tt.errString)
			}
			if got != tt.want {
				t.Errorf("ReadFrameField() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckBuffer(t *testing.T) {
	tests := []struct {
		name      string
		input     *bytes.Buffer
		n         int
		wantErr   bool
		errString string
	}{
		{name: "Test with nil buffer", input: nil, n: 4, wantErr: true, errString: "buffer is nil"},
		{name: "Test with short buffer", input: bytes.NewBuffer([]byte{0x01, 0x02, 0x03}), n: 4, wantErr: true, errString: "cant read numBytes"},
		{name: "Test buffer with enough bytes", input: bytes.NewBuffer([]byte{0x00, 0x00, 0x01, 0x02}), n: 4, wantErr: false, errString: ""},
		{name: "Test buffer with enough bytes", input: bytes.NewBuffer([]byte{0x00, 0x00, 0x01, 0x02}), n: 2, wantErr: false, errString: ""},
		{name: "Test buffer with enough bytes", input: bytes.NewBuffer([]byte{0x00, 0x00, 0x01, 0x02}), n: 1, wantErr: false, errString: ""},
		{name: "Test buffer with enough bytes", input: bytes.NewBuffer([]byte{0x00, 0x00, 0x01, 0x02}), n: 0, wantErr: false, errString: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fieldReader.checkBuffer(tt.input, tt.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkBuffer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.errString {
				t.Errorf("checkBuffer() error = %v, wantErr %v", err, tt.errString)
			}
		})
	}
}
