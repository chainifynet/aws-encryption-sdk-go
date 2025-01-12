// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"fmt"
	"time"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

// CachingOptions defines the available options for setting with [CachingCryptoMaterialsManager].
type CachingOptions struct {

	// AdditionalProviders is a slice of MasterKeyProvider instances used to supplement the primary key provider.
	AdditionalProviders []model.MasterKeyProvider

	// Manager is a [model.CryptoMaterialsManager] instance.
	Manager model.CryptoMaterialsManager

	// KeyHasherFn is a function that returns a new instance of [model.CacheHasher].
	// It is used to generate a unique key for each [model.CacheEntry] entry in the [model.Cache] cache.
	KeyHasherFn model.KeyHasherFunc

	// MaxAge specifies the duration for which cached items remain valid before expiring in the cache.
	MaxAge time.Duration

	// MaxMessages specifies number of messages that may be encrypted under a cache entry.
	MaxMessages uint64

	// MaxBytes specifies the number of bytes that a cache entry may be used to process
	MaxBytes uint64
}

// CachingOptionFunc is a type that defines a function used to configure CachingOptions.
type CachingOptionFunc func(o *CachingOptions) error

// WithAdditionalProviders provides a CachingOptionFunc to configure additional MasterKeyProviders in CachingOptions.
func WithAdditionalProviders(providers ...model.MasterKeyProvider) CachingOptionFunc {
	return func(o *CachingOptions) error {
		if len(providers) == 0 {
			return fmt.Errorf("providers must present")
		}
		o.AdditionalProviders = providers
		return nil
	}
}

// WithMaterialsManager provides a CachingOptionFunc to configure a [model.CryptoMaterialsManager] in CachingOptions.
func WithMaterialsManager(cmm model.CryptoMaterialsManager) CachingOptionFunc {
	return func(o *CachingOptions) error {
		if cmm == nil {
			return fmt.Errorf("cmm must present")
		}
		o.Manager = cmm
		return nil
	}
}

// WithKeyHasher provides a CachingOptionFunc to configure a [model.KeyHasherFunc] in CachingOptions.
func WithKeyHasher(h model.KeyHasherFunc) CachingOptionFunc {
	return func(o *CachingOptions) error {
		if h == nil {
			return fmt.Errorf("keyHasher must present")
		}
		o.KeyHasherFn = h
		return nil
	}
}

// WithMaxAge sets the maximum age for caching in the CachingOptions.
// An error is returned if maxAge is less than or equal to 0.
func WithMaxAge(maxAge time.Duration) CachingOptionFunc {
	return func(o *CachingOptions) error {
		if maxAge <= 0 {
			return fmt.Errorf("maxAge cannot be less than or equal to 0")
		}
		o.MaxAge = maxAge
		return nil
	}
}

// WithMaxMessages sets the maximum number of messages for caching in the CachingOptions.
func WithMaxMessages(maxMessages uint64) CachingOptionFunc {
	return func(o *CachingOptions) error {
		if maxMessages < 1 {
			return fmt.Errorf("maxMessages cannot be less than 1")
		}
		o.MaxMessages = maxMessages
		return nil
	}
}

// WithMaxBytes sets the maximum number of bytes for caching in the CachingOptions.
func WithMaxBytes(maxBytes uint64) CachingOptionFunc {
	return func(o *CachingOptions) error {
		if maxBytes < 1 {
			return fmt.Errorf("maxBytes cannot be less than 1")
		}
		o.MaxBytes = maxBytes
		return nil
	}
}
