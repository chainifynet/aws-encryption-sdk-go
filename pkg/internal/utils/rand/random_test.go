// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rand

import (
	"bytes"
	randpkg "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type errorReader struct{}

func (r errorReader) Read(_ []byte) (n int, err error) {
	return 0, assert.AnError
}

type mockRandReader struct{}

func (r mockRandReader) Read(b []byte) (n int, err error) {
	b = bytes.Repeat([]byte{0x00}, len(b))
	return len(b), nil
}

func TestCryptoRandomBytes(t *testing.T) {
	type args struct {
		r io.Reader
		n int
	}
	tests := []struct {
		name        string
		args        args
		want        []byte
		wantErr     bool
		wantErrStr  string
		wantErrType error
	}{
		{
			name: "Success",
			args: args{
				r: mockRandReader{},
				n: 32,
			},
			want: bytes.Repeat([]byte{0x00}, 32),
		},
		{
			name: "Reader Error",
			args: args{
				r: errorReader{},
				n: 32,
			},
			want:        nil,
			wantErr:     true,
			wantErrStr:  "failed to read random value",
			wantErrType: assert.AnError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				Reader = randpkg.Reader
			}()
			Reader = tt.args.r

			got, err := CryptoRandomBytes(tt.args.n)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.ErrorIs(t, err, tt.wantErrType)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
