// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestIsEntryOverLimits(t *testing.T) {
	type entry struct {
		age      float64
		messages uint64
		bytes    uint64
	}
	type conf struct {
		maxAge      float64
		maxMessages uint64
		maxBytes    uint64
	}
	tests := []struct {
		name   string
		entry  entry
		config conf
		want   bool
	}{
		{
			name:   "Not over limits with valid age, messages, and bytes",
			entry:  entry{age: 5, messages: 10, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
		{
			name:   "Over age limit",
			entry:  entry{age: 15, messages: 10, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   true,
		},
		{
			name:   "Over messages limit",
			entry:  entry{age: 5, messages: 20, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   true,
		},
		{
			name:   "Over bytes limit",
			entry:  entry{age: 5, messages: 10, bytes: 4096},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   true,
		},
		{
			name:   "Exactly at age limit",
			entry:  entry{age: 10, messages: 10, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
		{
			name:   "Exactly at messages limit",
			entry:  entry{age: 5, messages: 15, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
		{
			name:   "Exactly at bytes limit",
			entry:  entry{age: 5, messages: 10, bytes: 2048},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
		{
			name:   "Negative age, below age limit",
			entry:  entry{age: -5, messages: 10, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
		{
			name:   "Negative messages, below messages limit",
			entry:  entry{age: 5, messages: 0, bytes: 1024},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
		{
			name:   "Negative bytes, below bytes limit",
			entry:  entry{age: 5, messages: 10, bytes: 0},
			config: conf{maxAge: 10, maxMessages: 15, maxBytes: 2048},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEntry := mocks.NewMockCacheEntry(t)
			mockEntry.EXPECT().Age().Return(tt.entry.age).Once()
			mockEntry.EXPECT().Messages().Return(tt.entry.messages).Once()
			mockEntry.EXPECT().Bytes().Return(tt.entry.bytes).Once()

			manager := &CachingCryptoMaterialsManager{
				maxAge:      time.Duration(tt.config.maxAge) * time.Second,
				maxMessages: tt.config.maxMessages,
				maxBytes:    tt.config.maxBytes,
			}
			got := manager.isEntryOverLimits(mockEntry)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestShouldCacheEncryptionRequest(t *testing.T) {
	tests := []struct {
		name string
		req  model.EncryptionMaterialsRequest
		got  bool
	}{
		{
			name: "Valid request with KDF supported and positive length",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 100, Algorithm: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256},
			got:  true,
		},
		{
			name: "Valid request with KDF supported and zero length",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 0, Algorithm: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256},
			got:  false,
		},
		{
			name: "Valid request with KDF unsupported and positive length",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 100, Algorithm: suite.AES_256_GCM_IV12_TAG16},
			got:  false,
		},
		{
			name: "Valid request with zero length and KDF unsupported",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 0, Algorithm: suite.AES_256_GCM_IV12_TAG16},
			got:  false,
		},
		{
			name: "Request with nil algorithm",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 100, Algorithm: nil},
			got:  false,
		},
		{
			name: "Request with small positive length and KDF supported",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 1, Algorithm: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256},
			got:  true,
		},
		{
			name: "Large plaintext length with KDF unsupported",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 5000, Algorithm: suite.AES_256_GCM_IV12_TAG16},
			got:  false,
		},
		{
			name: "Large plaintext length with KDF supported",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 5000, Algorithm: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256},
			got:  true,
		},
		{
			name: "Negative plaintext length with KDF supported",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: -10, Algorithm: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256},
			got:  false,
		},
		{
			name: "Nil algorithm and zero plaintext length",
			req:  model.EncryptionMaterialsRequest{PlaintextLength: 0, Algorithm: nil},
			got:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.got, shouldCacheEncryptionRequest(tt.req))
		})
	}
}
