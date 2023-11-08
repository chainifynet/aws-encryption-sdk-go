// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import "fmt"

type RawProviderOptions struct {
	staticKeys map[string][]byte
}

type RawOptionFunc func(*RawProviderOptions) error

func WithStaticKey(keyID string, key []byte) RawOptionFunc {
	return func(o *RawProviderOptions) error {
		if keyID == "" {
			return fmt.Errorf("static keyID must not be empty")
		}
		if len(key) < _rawMinKeyLength {
			return fmt.Errorf("static key length must be at least %d bytes", _rawMinKeyLength)
		}
		if o.staticKeys == nil {
			o.staticKeys = make(map[string][]byte)
		}
		o.staticKeys[keyID] = key
		return nil
	}
}
