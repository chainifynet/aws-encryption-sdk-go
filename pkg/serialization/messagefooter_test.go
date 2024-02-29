// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func Test_footer_len(t *testing.T) {
	tests := []struct {
		name           string
		algorithmSuite *suite.AlgorithmSuite
		want           int
	}{
		{
			name:           "COMMIT_KEY",
			algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
			want:           2 + suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY.Authentication.SignatureLen,
		},
		{
			name:           "COMMIT_KEY_ECDSA_P384",
			algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			want:           2 + suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &footer{
				algorithmSuite: tt.algorithmSuite,
				signature:      make([]byte, tt.algorithmSuite.Authentication.SignatureLen),
				signLen:        tt.algorithmSuite.Authentication.SignatureLen,
			}
			assert.Equalf(t, tt.want, f.Len(), "Len()")
		})
	}
}

func Test_footer_Bytes(t *testing.T) {
	type fields struct {
		algorithmSuite *suite.AlgorithmSuite
		signLen        int
		Signature      []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{"COMMIT_KEY", fields{algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY, signLen: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY.Authentication.SignatureLen, Signature: make([]byte, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY.Authentication.SignatureLen)}, []byte{0x00, 0x00}},
		{"COMMIT_KEY_ECDSA_P384", fields{algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, signLen: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen, Signature: make([]byte, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen)}, append([]byte{0x00, 0x67}, make([]byte, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &footer{
				algorithmSuite: tt.fields.algorithmSuite,
				signLen:        tt.fields.signLen,
				signature:      tt.fields.Signature,
			}
			assert.Equalf(t, tt.want, f.Bytes(), "Bytes()")
		})
	}
}

func Test_messageFooter_FromBuffer(t *testing.T) {
	zeroSignature := make([]byte, 0)
	p384Signature := make([]byte, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen)
	type args struct {
		alg *suite.AlgorithmSuite
		buf *bytes.Buffer
	}
	tests := []struct {
		name      string
		args      args
		want      *footer
		wantErr   bool
		errString string
	}{
		{
			name:      "nil buffer",
			args:      args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, buf: bytes.NewBuffer([]byte(nil))},
			wantErr:   true,
			errString: "cant read signLen",
		},
		{
			name:      "nil buffer",
			args:      args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, buf: nil},
			wantErr:   true,
			errString: "cant read signLen",
		},
		{
			name:      "empty buffer",
			args:      args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, buf: bytes.NewBuffer([]byte{})},
			wantErr:   true,
			errString: "cant read signLen",
		},
		{
			name: "Mismatching signature length",

			args: args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				// required is 0 from AuthSuite, but here is 1
				buf: bytes.NewBuffer(append([]byte{0x0, 0x1}, zeroSignature...))},
			wantErr:   true,
			errString: "invalid signature length",
		},

		{
			name: "Mismatching signature length",
			args: args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				// required is 103 from AuthSuite, trying to pass nothing
				buf: bytes.NewBuffer(append([]byte{0x0, 0x67}, zeroSignature...))},
			wantErr:   true,
			errString: "malformed footer",
		},
		{
			name: "Mismatching signature length",
			args: args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				// required is 103 (0x0, 0x67) from AuthSuite, but here is 104 (0x0, 0x68)
				buf: bytes.NewBuffer(append([]byte{0x0, 0x68}, p384Signature...))},
			wantErr:   true,
			errString: "invalid signature length",
		},
		{
			name: "Valid buffer",
			args: args{
				alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				buf: bytes.NewBuffer(append([]byte{0x0, 0x0}, zeroSignature...)),
			},
			want: &footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				signLen:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY.Authentication.SignatureLen,
				signature:      zeroSignature,
			},
			wantErr: false,
		},
		{
			name: "Valid buffer",
			args: args{
				alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				buf: bytes.NewBuffer(append([]byte{0x0, 0x67}, p384Signature...)),
			},
			want: &footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				signLen:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen,
				signature:      p384Signature,
			},
			wantErr: false,
		},
		{
			name: "Buffer longer than required",
			args: args{alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				// here using twice P384 (206 bytes) longer signature than required P384 (103 bytes)
				buf: bytes.NewBuffer(append([]byte{0x0, 0x67}, append(p384Signature, p384Signature...)...))},
			want: &footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				signLen:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen,
				signature:      p384Signature,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deserializeFooter(tt.args.alg, tt.args.buf)
			if err != nil && tt.wantErr {
				require.ErrorIs(t, err, errFooter)
				require.Errorf(t, err, "deserializeFooter() error = %v, wantErr %v", err, tt.wantErr)
				require.ErrorContainsf(t, err, tt.errString, "deserializeFooter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "deserializeFooter() = %v, want %v", got, tt.want)
		})
	}
}

func TestFooterString(t *testing.T) {
	tests := []struct {
		name         string
		footer       footer
		signLen      int
		signatureLen int
	}{
		{
			name: "COMMIT_KEY",
			footer: footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				signLen:        2,
				signature:      []byte("signature1"),
			},
			signLen:      2,
			signatureLen: 10,
		},
		{
			name: "COMMIT_KEY_ECDSA_P384",
			footer: footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				signLen:        3,
				signature:      []byte("signature384"),
			},
			signLen:      3,
			signatureLen: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedStr := fmt.Sprintf("footer: %s, signLen: %d, signature: %d", tt.footer.algorithmSuite, tt.signLen, tt.signatureLen)
			assert.Equal(t, expectedStr, tt.footer.String())
		})
	}
}

func TestNewFooter(t *testing.T) {
	zeroSignature := make([]byte, 0)
	p384Signature := make([]byte, suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384.Authentication.SignatureLen)
	tests := []struct {
		name           string
		algorithmSuite *suite.AlgorithmSuite
		signature      []byte
		want           *footer
		wantErr        bool
		errString      string
	}{
		{
			name:           "Valid Signature COMMIT_KEY_ECDSA_P384",
			algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			signature:      p384Signature,
			want: &footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				signLen:        len(p384Signature),
				signature:      p384Signature,
			},
			wantErr: false,
		},
		{
			name:           "Valid Signature COMMIT_KEY",
			algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
			signature:      zeroSignature,
			want: &footer{
				algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
				signLen:        len(zeroSignature),
				signature:      zeroSignature,
			},
			wantErr: false,
		},
		{
			name:           "Invalid Signature Length COMMIT_KEY",
			algorithmSuite: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
			signature:      []byte("invalidSig"),
			want:           nil,
			wantErr:        true,
			errString:      "invalid signature length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newFooter(tt.algorithmSuite, tt.signature)
			if err != nil && tt.wantErr {
				require.ErrorIs(t, err, errFooter)
				require.Errorf(t, err, "newFooter() error = %v, wantErr %v", err, tt.wantErr)
				require.ErrorContainsf(t, err, tt.errString, "newFooter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equalf(t, tt.want, got, "newFooter() = %v, want %v", got, tt.want)
			assert.Equal(t, len(tt.signature), got.SignLen())
			assert.Equal(t, tt.signature, got.Signature())
		})
	}
}
