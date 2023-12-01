// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterKeyIDs(t *testing.T) {
	tests := []struct {
		name       string
		filterFunc FilterFunc
		keyIDs     []string
		want       []string
		wantErr    bool
	}{
		{
			name: "Filter Accepts All",
			filterFunc: func(s string) (bool, error) {
				return true, nil
			},
			keyIDs:  []string{"key1", "key2", "key3"},
			want:    []string{"key1", "key2", "key3"},
			wantErr: false,
		},
		{
			name: "Filter Rejects All",
			filterFunc: func(s string) (bool, error) {
				return false, nil
			},
			keyIDs:  []string{"key1", "key2", "key3"},
			want:    []string{},
			wantErr: false,
		},
		{
			name: "Filter With Error",
			filterFunc: func(s string) (bool, error) {
				if s == "key2" {
					return false, errors.New("filter error")
				}
				return true, nil
			},
			keyIDs:  []string{"key1", "key2", "key3"},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Complex Filter",
			filterFunc: func(s string) (bool, error) {
				return s != "key2", nil
			},
			keyIDs:  []string{"key1", "key2", "key3"},
			want:    []string{"key1", "key3"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FilterKeyIDs(tt.filterFunc, tt.keyIDs)
			assert.Equal(t, tt.want, result)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKeyResourceEqual(t *testing.T) {
	tests := []struct {
		name    string
		key1    string
		key2    string
		want    bool
		wantErr bool
	}{
		{
			name:    "Equal ResourceIDs",
			key1:    "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
			key2:    "arn:aws:kms:us-east-1:123456789012:key/abcd1234",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Different ResourceIDs",
			key1:    "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
			key2:    "arn:aws:kms:us-west-2:123456789012:key/xyz9876",
			want:    false,
			wantErr: false,
		},
		{
			name:    "Invalid First ARN",
			key1:    "invalid-arn",
			key2:    "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
			want:    false,
			wantErr: true,
		},
		{
			name:    "Invalid Second ARN",
			key1:    "arn:aws:kms:us-west-2:123456789012:key/abcd1234",
			key2:    "invalid-arn",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal, err := KeyResourceEqual(tt.key1, tt.key2)
			assert.Equal(t, tt.want, equal)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
