// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bodyaad_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/bodyaad"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestContentString(t *testing.T) {
	type args struct {
		contentType suite.ContentType
		finalFrame  bool
	}
	tests := []struct {
		name    string
		wantErr bool
		args    args
		want    []byte
	}{
		{"Not Final Frame", false, args{suite.FramedContent, false}, []byte("AWSKMSEncryptionClient Frame")},
		{"Final Frame", false, args{suite.FramedContent, true}, []byte("AWSKMSEncryptionClient Final Frame")},
		{"Non Framed Content", true, args{suite.NonFramedContent, true}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bodyaad.ContentString(tt.args.contentType, tt.args.finalFrame)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestContentAADBytes(t *testing.T) {
	contentString, _ := bodyaad.ContentString(suite.FramedContent, false)
	contentStringFinal, _ := bodyaad.ContentString(suite.FramedContent, true)
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
			if got := bodyaad.ContentAADBytes(tt.args.messageID, tt.args.contentString, tt.args.seqNum, tt.args.length); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ContentAADBytes() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
