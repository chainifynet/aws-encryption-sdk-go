// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package structs

// Contains checks if a slice contains a specific element.
// It takes a slice and an element as parameters.
// It returns true if the element is found in the slice, otherwise it returns false.
func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}
