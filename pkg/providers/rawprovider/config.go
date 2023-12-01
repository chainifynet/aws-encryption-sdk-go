// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rawprovider

import (
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
)

func validateConfig(providerID string, opts *Options) error {
	if providerID == "" {
		return fmt.Errorf("providerID must not be empty: %w", providers.ErrConfig)
	}
	if providerID == types.KmsProviderID {
		return fmt.Errorf("%q providerID is reserved for AWS: %w", providerID, providers.ErrConfig)
	}

	if len(opts.configKeys) == 0 {
		return fmt.Errorf("no static keys provided: %w", providers.ErrConfig)
	}

	for _, sk := range opts.configKeys {
		if err := validateStaticKey(sk.keyID, sk.key); err != nil {
			return fmt.Errorf("static key validation: %w", errors.Join(providers.ErrConfig, err))
		}
		if _, ok := opts.staticKeys[sk.keyID]; ok {
			return fmt.Errorf("%q static key already exists: %w", sk.keyID, providers.ErrConfig)
		}
		opts.staticKeys[sk.keyID] = sk.key
	}

	if opts.keyFactory == nil {
		return fmt.Errorf("keyFactory must not be nil: %w", providers.ErrConfig)
	}

	if opts.keyProvider == nil {
		return fmt.Errorf("keyProvider must not be nil: %w", providers.ErrConfig)
	}

	return nil
}

func resolveKeyProvider(providerID string, opts *Options) {
	// if keyProvider is already set by WithKeyProvider option, do nothing
	if opts.keyProvider != nil {
		return
	}
	// vendOnDecrypt explicitly false for RawKeyProvider
	opts.keyProvider = keyprovider.NewKeyProvider(providerID, types.Raw, false)
}

func validateStaticKey(keyID string, key []byte) error {
	if keyID == "" {
		return fmt.Errorf("static keyID must not be empty")
	}
	if len(key) < _rawMinKeyLength {
		return fmt.Errorf("static key length must be at least %d bytes", _rawMinKeyLength)
	}
	return nil
}
