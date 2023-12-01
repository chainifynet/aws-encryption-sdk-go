// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_regionForKeyID(t *testing.T) {
	tests := []struct {
		name          string
		keyID         string
		defaultRegion string
		want          string
		wantErr       bool
		wantErrStr    string
	}{
		{
			name:          "Valid keyID with region",
			keyID:         "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			defaultRegion: "us-east-1",
			want:          "us-west-2",
			wantErr:       false,
		},
		{
			name:          "Invalid keyID format, valid defaultRegion",
			keyID:         "invalid-key-format",
			defaultRegion: "eu-central-1",
			want:          "eu-central-1",
			wantErr:       false,
		},
		{
			name:          "Invalid keyID and defaultRegion format",
			keyID:         "invalid-key-format",
			defaultRegion: "short",
			want:          "",
			wantErr:       true,
			wantErrStr:    "InvalidRegionError",
		},
		{
			name:          "Valid keyID format, region part too short",
			keyID:         "arn:aws:kms:us:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			defaultRegion: "us-east-1",
			want:          "",
			wantErr:       true,
			wantErrStr:    "UnknownRegionError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := regionForKeyID(tt.keyID, tt.defaultRegion)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Equal(t, tt.want, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
