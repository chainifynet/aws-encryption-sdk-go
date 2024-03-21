// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"

type staticKey struct {
	keyID string
	key   []byte
}

// Options contains the configuration options for the [RawKeyProvider].
type Options struct {
	staticKeys  map[string][]byte
	configKeys  []staticKey
	keyFactory  model.MasterKeyFactory
	keyProvider model.BaseKeyProvider
}

// OptionsFunc is a function that applies an option to the [Options].
type OptionsFunc func(*Options) error

// WithStaticKey configures a static key for the Raw provider.
func WithStaticKey(keyID string, key []byte) OptionsFunc {
	return func(o *Options) error {
		o.configKeys = append(o.configKeys, staticKey{keyID, key})
		return nil
	}
}

// WithKeyFactory sets the master key factory for the Raw provider.
func WithKeyFactory(keyFactory model.MasterKeyFactory) OptionsFunc {
	return func(o *Options) error {
		o.keyFactory = keyFactory
		return nil
	}
}

// WithKeyProvider sets the base key provider for the Raw provider.
func WithKeyProvider(keyProvider model.BaseKeyProvider) OptionsFunc {
	return func(o *Options) error {
		o.keyProvider = keyProvider
		return nil
	}
}
