// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"

type staticKey struct {
	keyID string
	key   []byte
}

type Options struct {
	staticKeys  map[string][]byte
	configKeys  []staticKey
	keyFactory  model.MasterKeyFactory
	keyProvider model.BaseKeyProvider
}

type OptionsFunc func(*Options) error

func WithStaticKey(keyID string, key []byte) OptionsFunc {
	return func(o *Options) error {
		o.configKeys = append(o.configKeys, staticKey{keyID, key})
		return nil
	}
}

func WithKeyFactory(keyFactory model.MasterKeyFactory) OptionsFunc {
	return func(o *Options) error {
		o.keyFactory = keyFactory
		return nil
	}
}

func WithKeyProvider(keyProvider model.BaseKeyProvider) OptionsFunc {
	return func(o *Options) error {
		o.keyProvider = keyProvider
		return nil
	}
}
