// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_algorithm_ByID(t *testing.T) {
	type args struct {
		algorithmID uint16
	}
	tests := []struct {
		name    string
		args    args
		want    *AlgorithmSuite
		wantErr bool
	}{
		{"unknown_alg", args{0x0301}, nil, true},
		{"zero_alg", args{0}, nil, true},
		{"AES_128_GCM_IV12_TAG16", args{0x0014}, AES_128_GCM_IV12_TAG16, false},
		{"AES_192_GCM_IV12_TAG16", args{0x0046}, AES_192_GCM_IV12_TAG16, false},
		{"AES_256_GCM_IV12_TAG16", args{0x0078}, AES_256_GCM_IV12_TAG16, false},
		{"AES_128_GCM_IV12_TAG16_HKDF_SHA256", args{0x0114}, AES_128_GCM_IV12_TAG16_HKDF_SHA256, false},
		{"AES_192_GCM_IV12_TAG16_HKDF_SHA256", args{0x0146}, AES_192_GCM_IV12_TAG16_HKDF_SHA256, false},
		{"AES_256_GCM_IV12_TAG16_HKDF_SHA256", args{0x0178}, AES_256_GCM_IV12_TAG16_HKDF_SHA256, false},
		{"AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256", args{0x0214}, AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, false},
		{"AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", args{0x0346}, AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, false},
		{"AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", args{0x0378}, AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, false},
		{"AES_256_GCM_HKDF_SHA512_COMMIT_KEY", args{0x0478}, AES_256_GCM_HKDF_SHA512_COMMIT_KEY, false},
		{"AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384", args{0x0578}, AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			al := algorithm{}
			got, err := al.ByID(tt.args.algorithmID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ByID() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_algorithm_FromBytes(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *AlgorithmSuite
		wantErr bool
	}{
		{"alg_nil", args{[]byte(nil)}, nil, true},
		{"zero_alg", args{[]byte{0x00}}, nil, true},
		{"AES_256_GCM_IV12_TAG16", args{[]byte{0x00, 0x78}}, AES_256_GCM_IV12_TAG16, false},
		{"AES_256_GCM_IV12_TAG16_HKDF_SHA256", args{[]byte{0x01, 0x78}}, AES_256_GCM_IV12_TAG16_HKDF_SHA256, false},
		{"AES_256_GCM_HKDF_SHA512_COMMIT_KEY", args{[]byte{0x04, 0x78}}, AES_256_GCM_HKDF_SHA512_COMMIT_KEY, false},
		{"AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384", args{[]byte{0x05, 0x78}}, AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg := algorithm{}
			got, err := alg.FromBytes(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromBytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_NewEncryptionSuite(t *testing.T) {
	type args struct {
		algorithm  encAlgorithm
		mode       cipherMode
		dataKeyLen int
		ivLen      int
		authLen    int
	}
	tests := []struct {
		name string
		args args
		want encryptionSuite
	}{
		{"aes128", args{"AES", "GCM", 16, 12, 16}, aes_128_GCM_IV12_TAG16},
		{"aes192", args{"AES", "GCM", 24, 12, 16}, aes_192_GCM_IV12_TAG16},
		{"aes256", args{"AES", "GCM", 32, 12, 16}, aes_256_GCM_IV12_TAG16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEncryptionSuite(tt.args.algorithm, tt.args.mode, tt.args.dataKeyLen, tt.args.ivLen, tt.args.authLen); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewEncryptionSuite() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authenticationSuiteSignatureLen(t *testing.T) {
	tests := []struct {
		name      string
		authSuite authenticationSuite
		want      int
	}{
		{"NONE", authSuite_NONE, 0},
		{"SHA256_ECDSA_P256", authSuite_SHA256_ECDSA_P256, 71},
		{"SHA256_ECDSA_P384", authSuite_SHA256_ECDSA_P384, 103},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.authSuite.SignatureLen; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authSuite.SignatureLen = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmSuite_MessageIDLen(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want int
	}{
		{"HKDF_SHA256", AES_256_GCM_IV12_TAG16_HKDF_SHA256, 16},
		{"COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, 32},
		{"COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.MessageIDLen(); got != tt.want {
				t.Errorf("MessageIDLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmSuite_IsSigning(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want bool
	}{
		{"not_signing", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, false},
		{"signing", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.IsSigning(); got != tt.want {
				t.Errorf("IsSigning() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmSuite_IsCommitting(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want bool
	}{
		{"NOT_COMMITTING", AES_256_GCM_IV12_TAG16_HKDF_SHA256, false},
		{"COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, true},
		{"COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, true},
		{"NO_COMMIT_KEY", newAlgorithmSuite(0x0302, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_NONE), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.IsCommitting(); got != tt.want {
				t.Errorf("IsCommitting() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmSuite_AlgorithmSuiteDataLen(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want int
	}{
		{"HKDF_SHA256", AES_256_GCM_IV12_TAG16_HKDF_SHA256, 0},
		{"COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, 32},
		{"COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.AlgorithmSuiteDataLen(); got != tt.want {
				t.Errorf("AlgorithmSuiteDataLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmSuite_IDBytes(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want []byte
	}{
		{"COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, []byte{0x04, 0x78}},
		{"COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, []byte{0x05, 0x78}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.IDBytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IDBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmSuite_Name(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want string
	}{
		{"AES_128_GCM_IV12_TAG16", AES_128_GCM_IV12_TAG16, "AES_128_GCM_IV12_TAG16"},
		{"AES_192_GCM_IV12_TAG16", AES_192_GCM_IV12_TAG16, "AES_192_GCM_IV12_TAG16"},
		{"AES_256_GCM_IV12_TAG16", AES_256_GCM_IV12_TAG16, "AES_256_GCM_IV12_TAG16"},
		{"AES_128_GCM_IV12_TAG16_HKDF_SHA256", AES_128_GCM_IV12_TAG16_HKDF_SHA256, "AES_128_GCM_IV12_TAG16_HKDF_SHA256"},
		{"AES_192_GCM_IV12_TAG16_HKDF_SHA256", AES_192_GCM_IV12_TAG16_HKDF_SHA256, "AES_192_GCM_IV12_TAG16_HKDF_SHA256"},
		{"AES_256_GCM_IV12_TAG16_HKDF_SHA256", AES_256_GCM_IV12_TAG16_HKDF_SHA256, "AES_256_GCM_IV12_TAG16_HKDF_SHA256"},
		{"AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256", AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, "AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256"},
		{"AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, "AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384"},
		{"AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384", AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384, "AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384"},
		{"AES_256_GCM_HKDF_SHA512_COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, "AES_256_GCM_HKDF_SHA512_COMMIT_KEY"},
		{"AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.alg.Name(), "Name()")
		})
	}
}

func TestAlgorithmSuite_String(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want string
	}{
		{"AES_128_GCM_IV12_TAG16", AES_128_GCM_IV12_TAG16, "AlgID 0x0014: AES_128_GCM_IV12_TAG16"},
		{"AES_256_GCM_IV12_TAG16", AES_256_GCM_IV12_TAG16, "AlgID 0x0078: AES_256_GCM_IV12_TAG16"},
		{"AES_256_GCM_IV12_TAG16_HKDF_SHA256", AES_256_GCM_IV12_TAG16_HKDF_SHA256, "AlgID 0x0178: AES_256_GCM_IV12_TAG16_HKDF_SHA256"},
		{"COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, "AlgID 0x0478: AES_256_GCM_HKDF_SHA512_COMMIT_KEY"},
		{"COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, "AlgID 0x0578: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.alg.String(), "String()")
		})
	}
}

func TestAlgorithmSuite_GoString(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want string
	}{
		{
			name: "COMMIT_KEY_ECDSA_P384",
			alg:  AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			want: fmt.Sprintf("%#v", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fmt.Sprintf("%#v", tt.alg))
		})
	}
}

func TestAlgorithmSuite_IDString(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want string
	}{
		{"0014_AES_128_GCM_IV12_TAG16", AES_128_GCM_IV12_TAG16, "0014"},
		{"0078_AES_256_GCM_IV12_TAG16", AES_256_GCM_IV12_TAG16, "0078"},
		{"0178_AES_256_GCM_IV12_TAG16_HKDF_SHA256", AES_256_GCM_IV12_TAG16_HKDF_SHA256, "0178"},
		{"0478_COMMIT_KEY", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, "0478"},
		{"0578_COMMIT_KEY_ECDSA_P384", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, "0578"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.alg.IDString(), "IDString()")
		})
	}
}

func TestAlgorithmSuite_IsKDFSupported(t *testing.T) {
	tests := []struct {
		name string
		alg  *AlgorithmSuite
		want bool
	}{
		{"0014_KDF_not_supported", AES_128_GCM_IV12_TAG16, false},
		{"0046_KDF_not_supported", AES_192_GCM_IV12_TAG16, false},
		{"0078_KDF_not_supported", AES_256_GCM_IV12_TAG16, false},
		{"0146_KDF_supported", AES_192_GCM_IV12_TAG16_HKDF_SHA256, true},
		{"0214_KDF_supported", AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, true},
		{"0478_KDF_supported", AES_256_GCM_HKDF_SHA512_COMMIT_KEY, true},
		{"0578_KDF_supported", AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.IsKDFSupported(); got != tt.want {
				t.Errorf("IsKDFSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}
