// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package arn

// FilterFunc is a function that filters a string.
//
// Examples: [IsValidMrkArn], [IsValidMrkIdentifier]
type FilterFunc func(s string) (bool, error)

// FilterKeyIDs filters a list of key IDs using the given filter function. It
// returns a list of key IDs that pass the filter.
func FilterKeyIDs(f FilterFunc, keyIDs []string) ([]string, error) {
	result := make([]string, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		ok, err := f(keyID)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, keyID)
		}
	}
	return result, nil
}

// KeyResourceEqual checks if the given key ARNs refer to the same KMS MRK resourceID.
func KeyResourceEqual(key1, key2 string) (bool, error) {
	arn1, err := ParseArn(key1)
	if err != nil {
		return false, err
	}
	arn2, err := ParseArn(key2)
	if err != nil {
		return false, err
	}
	if arn1.ResourceID == arn2.ResourceID {
		return true, nil
	}
	return false, nil
}
