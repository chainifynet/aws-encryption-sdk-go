// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package itertools_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/itertools"
)

func BenchmarkCombinationsNew(b *testing.B) {
	type subtest struct {
		name  string
		slice []string
		size  int
	}
	type test struct {
		name string
		ts   []subtest
	}

	var tests []test

	for i := 1; i < 12; i++ {
		tc := test{
			name: fmt.Sprintf("slice %d", i),
			ts:   make([]subtest, 0),
		}
		for j := 0; j < 10; j++ {
			if j <= i+1 {
				tc.ts = append(tc.ts, subtest{
					name:  fmt.Sprintf("size %d", j),
					slice: genSlice(i),
					size:  j,
				})
			}
		}
		tests = append(tests, tc)
	}
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for _, st := range tt.ts {
				b.Run(st.name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							itertools.Combinations(st.slice, st.size)
						}
					})
				})
			}
		})
	}
}

func genSlice(n int) (s []string) {
	if n < 1 || n > 26 {
		return nil
	}
	s = make([]string, n)
	for i := 0; i < n; i++ {
		s[i] = string(rune('a' + i))
	}
	return s
}

func TestCombinations(t *testing.T) {
	type subtest struct {
		name  string
		slice []string
		size  int
	}
	type test struct {
		name string
		ts   []subtest
	}

	var tests []test

	for i := 1; i < 13; i++ {
		tc := test{
			name: fmt.Sprintf("slice %d", i),
			ts:   make([]subtest, 0),
		}
		for j := 0; j < 11; j++ {
			if j <= i+1 {
				tc.ts = append(tc.ts, subtest{
					name:  fmt.Sprintf("size %d", j),
					slice: genSlice(i),
					size:  j,
				})
			}
		}
		tests = append(tests, tc)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, st := range tt.ts {
				t.Run(st.name, func(t *testing.T) {
					res := itertools.Combinations(st.slice, st.size)
					if st.size <= 0 {
						assert.Equal(t, 0, len(res))
					} else if st.size > len(st.slice) {
						assert.Equal(t, 0, len(res))
					} else if st.size == len(st.slice) {
						assert.Equal(t, 1, len(res))
					} else if st.size < len(st.slice) {
						assert.Greater(t, len(res), st.size)
					}

					for _, v := range res {
						assert.Equal(t, st.size, len(v))
						assert.Subset(t, st.slice, v)
					}
				})
			}
		})
	}
}
