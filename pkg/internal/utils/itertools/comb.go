// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package itertools

import "math/bits"

// Combinations returns combinations of n elements for a given s slice.
//
// Modified [version] to comply with requirements.
//
//   - return [][]T{} on empty combinations
//   - return [][]T{} if n <= 0
//
// Original license: MIT
// Copyright (c) 2018 Max Schmitt
//
// [version]: https://github.com/mxschmitt/golang-combinations/blob/main/combinations.go
func Combinations[T any](s []T, n int) (ss [][]T) {
	if n <= 0 {
		return [][]T{}
	}

	l := uint(len(s))

	// Iterate through all combinations of o
	// from 1 (only first o in sbs) to 2^l length (all objects in sbs)
	for ssb := 1; ssb < (1 << l); ssb++ {
		if n > 0 && bits.OnesCount(uint(ssb)) != n {
			continue
		}

		var sbs []T

		for o := uint(0); o < l; o++ {
			// checks if o is contained in sbs
			// by checking if bit 'o' is set in ssb
			if (ssb>>o)&1 == 1 {
				// add o to sbs
				sbs = append(sbs, s[o])
			}
		}
		// add sbs to ss
		ss = append(ss, sbs)
	}
	if len(ss) == 0 {
		return [][]T{}
	}
	return ss
}
