// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package structs

import "sort"

// MapContains checks if a map contains a specific key.
// It takes a map and a key as parameters.
// It returns true if the key is found in the map, otherwise it returns false.
func MapContains[K comparable, V any](m map[K]V, k K) bool {
	for key := range m {
		if key == k {
			return true
		}
	}
	return false
}

// MapKeys returns all keys from a map.
// It takes a map as a parameter.
// It returns a slice containing all keys from the map.
func MapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// MapSort sorts a map by its keys.
// It takes a map as a parameter.
// It returns a new map with the same key-value pairs, but sorted by keys.
// The sorting is only applicable for maps with string or integer keys.
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
