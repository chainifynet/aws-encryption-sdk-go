// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package structs

import "sort"

func MapContains[K comparable, V any](m map[K]V, k K) bool {
	for key := range m {
		if key == k {
			return true
		}
	}
	return false
}

func MapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func MapSort[K ~string | ~int, V any](m map[K]V) map[K]V {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	mCopy := make(map[K]V)
	for _, k := range keys {
		mCopy[k] = m[k]
	}
	return mCopy
}
