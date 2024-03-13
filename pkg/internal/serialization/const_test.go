// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import "testing"

func TestConstants(t *testing.T) {
	tests := []struct {
		name  string
		value int
		want  int
	}{
		{name: "lenFieldBytes value", value: lenFieldBytes, want: 2},
		{name: "countFieldBytes value", value: countFieldBytes, want: 2},
		{name: "singleFieldBytes value", value: singleFieldBytes, want: 1},
		{name: "frameFieldBytes value", value: frameFieldBytes, want: 4},
		{name: "algorithmIDFieldBytes value", value: algorithmIDFieldBytes, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}
