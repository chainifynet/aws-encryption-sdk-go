// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"reflect"
	"testing"
)

var (
	key       = []byte("superSecureKeySecureKey32bytes32")
	plainText = []byte("PlainTextAndMoreTextJustToMakeItLonger")
	iv        = []byte("iv12byteLong")
	aadData   = []byte("someAadData")
)

func Test_gcmEncryptor_encrypt(t *testing.T) {
	type args struct {
		key       []byte
		iv        []byte
		plaintext []byte
		aadData   []byte
	}
	tests := []struct {
		name           string
		args           args
		wantCiphertext []byte
		wantTag        []byte
		wantErr        bool
	}{
		{"just_encrypt", args{key, iv, plainText, aadData}, []byte{0x3f, 0x46, 0x3a, 0x8d, 0xd7, 0x30, 0x98, 0x49, 0xe9, 0xdb, 0xa1, 0x4d, 0x85, 0x15, 0x4a, 0x8a, 0x81, 0xb1, 0x91, 0x8b, 0x1, 0x93, 0xfa, 0x61, 0x63, 0xb2, 0x54, 0x4, 0xb6, 0xe2, 0x41, 0xab, 0xc, 0x76, 0xd5, 0x3, 0x2e, 0x59}, []byte{0xf3, 0xb6, 0x30, 0x9, 0xdd, 0xd4, 0xf, 0x82, 0x82, 0x66, 0x1e, 0x5c, 0xf5, 0x7f, 0xb6, 0xc7}, false},
		{"encrypt_short_key", args{[]byte("shortKey"), iv, plainText, aadData}, nil, nil, true},
		{"encrypt_nil_plaintext", args{key, iv, nil, aadData}, []byte{}, []byte{0x5a, 0xd1, 0xc7, 0xeb, 0x67, 0x45, 0xc0, 0x1f, 0x28, 0x5, 0x99, 0x79, 0x9b, 0xb8, 0x6d, 0x0}, false},
		{"encrypt_nil_plaintext_and_aadData", args{key, iv, nil, nil}, []byte{}, []byte{0x4, 0x7a, 0xa0, 0xc1, 0xa9, 0x36, 0x56, 0x88, 0xac, 0xc5, 0xa4, 0x34, 0x56, 0xf, 0x68, 0xdb}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ge := gcmEncryptor{}
			ciphertext, tag, err := ge.encrypt(tt.args.key, tt.args.iv, tt.args.plaintext, tt.args.aadData)
			if (err != nil) != tt.wantErr {
				t.Errorf("encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(ciphertext, tt.wantCiphertext) {
				t.Errorf("encrypt() ciphertext = %#v, wantCiphertext %#v", ciphertext, tt.wantCiphertext)
			}
			if !reflect.DeepEqual(tag, tt.wantTag) {
				t.Errorf("encrypt() tag = %#v, wantTag %#v", tag, tt.wantTag)
			}
		})
	}
}

func Test_gcmEncryptor_generateHeaderAuth(t *testing.T) {
	type args struct {
		derivedDataKey []byte
		headerBytes    []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"authNilHeader", args{key, nil}, []byte{0x78, 0x74, 0x8b, 0xaf, 0x67, 0x83, 0x94, 0x66, 0xb8, 0x2c, 0xb1, 0x5c, 0x1e, 0x83, 0xa4, 0x7a}, false},
		{"authWithHeader", args{key, []byte{0x01}}, []byte{0xbd, 0x5a, 0xf0, 0xa9, 0x88, 0xee, 0xbd, 0xbe, 0xf8, 0x95, 0x50, 0xb1, 0xeb, 0x23, 0x2c, 0x32}, false},
		{"short_key", args{[]byte("shortKey"), []byte{0x01}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ge := gcmEncryptor{}
			got, err := ge.generateHeaderAuth(tt.args.derivedDataKey, tt.args.headerBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateHeaderAuth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateHeaderAuth() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_gcmDecrypter_validateHeaderAuth(t *testing.T) {
	type args struct {
		derivedDataKey []byte
		headerAuthTag  []byte
		headerBytes    []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"authNilHeader", args{key, []byte{0x78, 0x74, 0x8b, 0xaf, 0x67, 0x83, 0x94, 0x66, 0xb8, 0x2c, 0xb1, 0x5c, 0x1e, 0x83, 0xa4, 0x7a}, nil}, false},
		{"authWithHeader", args{key, []byte{0xbd, 0x5a, 0xf0, 0xa9, 0x88, 0xee, 0xbd, 0xbe, 0xf8, 0x95, 0x50, 0xb1, 0xeb, 0x23, 0x2c, 0x32}, []byte{0x01}}, false},
		{"short_key", args{[]byte("shortKey"), []byte{0xbd, 0x5a, 0xf0, 0xa9, 0x88, 0xee, 0xbd, 0xbe, 0xf8, 0x95, 0x50, 0xb1, 0xeb, 0x23, 0x2c, 0x32}, []byte{0x01}}, true},
		{"authWrongKey", args{bytes.Repeat([]byte{0x01}, 32), []byte{0xbd, 0x5a, 0xf0, 0xa9, 0x88, 0xee, 0xbd, 0xbe, 0xf8, 0x95, 0x50, 0xb1, 0xeb, 0x23, 0x2c, 0x32}, []byte{0x01}}, true},
		{"authWithWrongHeader", args{key, []byte{0xbd, 0x5a, 0xf0, 0xa9, 0x88, 0xee, 0xbd, 0xbe, 0xf8, 0x95, 0x50, 0xb1, 0xeb, 0x23, 0x2c, 0x32}, []byte{0x05}}, true},
		{"authWithWrongTag", args{key, bytes.Repeat([]byte{0x01}, 32), []byte{0x01}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gd := gcmDecrypter{}
			if err := gd.validateHeaderAuth(tt.args.derivedDataKey, tt.args.headerAuthTag, tt.args.headerBytes); (err != nil) != tt.wantErr {
				t.Errorf("validateHeaderAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_gcmDecrypter_decrypt(t *testing.T) {
	type args struct {
		key        []byte
		iv         []byte
		ciphertext []byte
		tag        []byte
		aadData    []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"just_decrypt", args{key, iv, []byte{0x3f, 0x46, 0x3a, 0x8d, 0xd7, 0x30, 0x98, 0x49, 0xe9, 0xdb, 0xa1, 0x4d, 0x85, 0x15, 0x4a, 0x8a, 0x81, 0xb1, 0x91, 0x8b, 0x1, 0x93, 0xfa, 0x61, 0x63, 0xb2, 0x54, 0x4, 0xb6, 0xe2, 0x41, 0xab, 0xc, 0x76, 0xd5, 0x3, 0x2e, 0x59}, []byte{0xf3, 0xb6, 0x30, 0x9, 0xdd, 0xd4, 0xf, 0x82, 0x82, 0x66, 0x1e, 0x5c, 0xf5, 0x7f, 0xb6, 0xc7}, aadData}, plainText, false},
		{"decrypt_short_key", args{[]byte("shortKey"), iv, nil, nil, aadData}, nil, true},
		{"decrypt_short_IV", args{key, []byte("shortIV"), nil, nil, aadData}, nil, true},
		{"decrypt_nil_IV", args{key, nil, nil, nil, aadData}, nil, true},
		{"decrypt_empty_IV", args{key, []byte{}, nil, nil, aadData}, nil, true},
		{"decrypt_nil_bytes_plaintext", args{key, iv, []byte(nil), []byte{0x5a, 0xd1, 0xc7, 0xeb, 0x67, 0x45, 0xc0, 0x1f, 0x28, 0x5, 0x99, 0x79, 0x9b, 0xb8, 0x6d, 0x0}, aadData}, []byte(nil), false},
		{"decrypt_nil_plaintext", args{key, iv, nil, []byte{0x5a, 0xd1, 0xc7, 0xeb, 0x67, 0x45, 0xc0, 0x1f, 0x28, 0x5, 0x99, 0x79, 0x9b, 0xb8, 0x6d, 0x0}, aadData}, []byte(nil), false},
		{"decrypt_nil_plaintext_and_aadData", args{key, iv, nil, []byte{0x4, 0x7a, 0xa0, 0xc1, 0xa9, 0x36, 0x56, 0x88, 0xac, 0xc5, 0xa4, 0x34, 0x56, 0xf, 0x68, 0xdb}, nil}, []byte(nil), false},
		{"decrypt_wrong_key_nil_plaintext_and_aadData", args{bytes.Repeat([]byte{0x01}, 32), iv, nil, []byte{0x4, 0x7a, 0xa0, 0xc1, 0xa9, 0x36, 0x56, 0x88, 0xac, 0xc5, 0xa4, 0x34, 0x56, 0xf, 0x68, 0xdb}, nil}, []byte(nil), true},
		{"decrypt_wrong_iv_nil_plaintext_and_aadData", args{key, bytes.Repeat([]byte{0x01}, 12), nil, []byte{0x4, 0x7a, 0xa0, 0xc1, 0xa9, 0x36, 0x56, 0x88, 0xac, 0xc5, 0xa4, 0x34, 0x56, 0xf, 0x68, 0xdb}, nil}, []byte(nil), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gd := gcmDecrypter{}
			got, err := gd.decrypt(tt.args.key, tt.args.iv, tt.args.ciphertext, tt.args.tag, tt.args.aadData)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decrypt() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_constructIV(t *testing.T) {
	tests := []struct {
		name   string
		seqNum int
		want   []byte
	}{
		{"seq0", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"seq5", 5, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}},
		{"seq10", 10, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := constructIV(tt.seqNum); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("constructIV() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
