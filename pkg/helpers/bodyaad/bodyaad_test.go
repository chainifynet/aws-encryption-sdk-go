// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bodyaad

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func Test_bodyAAD_ContentString(t *testing.T) {
	type args struct {
		contentType suite.ContentType
		finalFrame  bool
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"NotFinalFrame", args{suite.FramedContent, false}, []byte("AWSKMSEncryptionClient Frame")},
		{"FinalFrame", args{suite.FramedContent, true}, []byte("AWSKMSEncryptionClient Final Frame")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bo := bodyAAD{}
			if got := bo.ContentString(tt.args.contentType, tt.args.finalFrame); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ContentString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_bodyAAD_ContentAADBytes(t *testing.T) {
	contentString := BodyAAD.ContentString(suite.FramedContent, false)
	contentStringFinal := BodyAAD.ContentString(suite.FramedContent, true)
	type args struct {
		messageID     []byte
		contentString []byte
		seqNum        int
		length        int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"seq1notFinalLen50", args{[]byte{0x01}, contentString, 1, 50}, []byte{0x1, 0x41, 0x57, 0x53, 0x4b, 0x4d, 0x53, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x32}},
		{"seq5NotFinalLen80", args{[]byte{0x01}, contentString, 5, 80}, []byte{0x1, 0x41, 0x57, 0x53, 0x4b, 0x4d, 0x53, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50}},
		{"seq10FinalLen120", args{[]byte{0x01}, contentStringFinal, 10, 120}, []byte{0x1, 0x41, 0x57, 0x53, 0x4b, 0x4d, 0x53, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x20, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x78}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bo := bodyAAD{}
			if got := bo.ContentAADBytes(tt.args.messageID, tt.args.contentString, tt.args.seqNum, tt.args.length); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ContentAADBytes() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestBodyAAD_ContentStringPanic(t *testing.T) {
	tests := []struct {
		name    string
		f       func()
		isPanic bool
	}{
		{"panicFinal", func() { BodyAAD.ContentString(suite.NonFramedContent, true) }, true},
		{"panicNotFinal", func() { BodyAAD.ContentString(suite.NonFramedContent, false) }, true},
		{"NotPanicFinal", func() { BodyAAD.ContentString(suite.FramedContent, true) }, false},
		{"NotPanicNotFinal", func() { BodyAAD.ContentString(suite.FramedContent, false) }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.isPanic {
				assert.Panics(t, test.f)
			} else {
				assert.NotPanics(t, test.f)
			}
		})
	}
}
