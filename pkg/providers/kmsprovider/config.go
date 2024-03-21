// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/kmsclient"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/itertools"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/structs"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys/kms"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/arn"
)

func resolveProviderType(opts *Options) ProviderType {
	if opts.discoveryRegion != "" {
		return MrkAwareDiscoveryKmsProvider
	}
	if opts.discovery {
		if opts.mrkAware {
			return MrkAwareDiscoveryKmsProvider
		}
		return DiscoveryKmsProvider
	}
	if opts.mrkAware {
		return MrkAwareStrictKmsProvider
	}
	return StrictKmsProvider
}

func resolveVendOnDecrypt(t ProviderType) bool {
	switch t {
	case StrictKmsProvider, MrkAwareStrictKmsProvider:
		return false
	case DiscoveryKmsProvider, MrkAwareDiscoveryKmsProvider:
		return true
	default:
		return false
	}
}

func resolveClientFactory(opts *Options) {
	if opts.clientFactory != nil {
		return
	}
	opts.clientFactory = kmsclient.NewFactory()
}

func resolveKeyFactory(t ProviderType, opts *Options) {
	// if keyFactory is already set by WithKeyFactory option, do nothing
	if opts.keyFactory != nil {
		return
	}
	switch t {
	case StrictKmsProvider, DiscoveryKmsProvider:
		// use default key factory for non-MRK aware providers
		opts.keyFactory = &kms.KeyFactory{}
	case MrkAwareStrictKmsProvider, MrkAwareDiscoveryKmsProvider:
		// use MRK aware key factory for MRK aware providers
		opts.keyFactory = &kms.MrkKeyFactory{}
	default:
		// use default key factory as fallback
		opts.keyFactory = &kms.KeyFactory{}
	}
}

func resolveKeyProvider(t ProviderType, opts *Options) {
	// if keyProvider is already set by WithKeyProvider option, do nothing
	if opts.keyProvider != nil {
		return
	}
	opts.keyProvider = keyprovider.NewKeyProvider(types.KmsProviderID, types.AwsKms, resolveVendOnDecrypt(t))
}

func resolveDefaultRegion(keyIDs []string, opts *Options) {
	if opts.defaultRegion != "" {
		return
	}
	var region string
	if len(keyIDs) > 0 {
		for _, keyID := range keyIDs {
			keyArn, err := arn.ParseArn(keyID)
			if err != nil {
				// try next keyID in case of invalid ARN
				continue
			}
			if keyArn.Region != "" {
				region = keyArn.Region
				break
			}
		}
	}
	if region == "" {
		cfg, _ := config.LoadDefaultConfig(context.Background(), opts.awsConfigLoaders...)
		if cfg.Region != "" {
			region = cfg.Region
		}
	}
	opts.defaultRegion = region
}

//nolint:cyclop
func validateConfig(t ProviderType, keyIDs []string, options *Options) error { //nolint:gocognit
	switch t {
	case StrictKmsProvider, MrkAwareStrictKmsProvider:
		if len(keyIDs) == 0 {
			return fmt.Errorf("keyIDs must not be empty for %q: %w", t, providers.ErrConfig)
		}
		if err := validateKeyArns(keyIDs); err != nil {
			return fmt.Errorf("keyIDs validation: %w", errors.Join(providers.ErrConfig, err))
		}
		if options.discovery {
			return fmt.Errorf("discovery must not be enabled for %q: %w", t, providers.ErrConfig)
		}
		if options.discoveryFilter != nil {
			return fmt.Errorf("discovery filter must not be set for %q: %w", t, providers.ErrConfig)
		}
		if options.discoveryRegion != "" {
			return fmt.Errorf("discovery region must not be set for %q: %w", t, providers.ErrConfig)
		}
	case DiscoveryKmsProvider, MrkAwareDiscoveryKmsProvider:
		if len(keyIDs) > 0 {
			return fmt.Errorf("keyIDs must be empty for %q: %w", t, providers.ErrConfig)
		}
		if !options.discovery {
			return fmt.Errorf("discovery must be enabled for %q: %w", t, providers.ErrConfig)
		}
		if options.discoveryFilter != nil {
			if err := validateDiscoveryFilter(options.discoveryFilter); err != nil {
				return fmt.Errorf("discovery filter error: %w", errors.Join(providers.ErrConfig, err))
			}
		}
	default:
		return fmt.Errorf("unknown KMS provider type %q: %w", t, providers.ErrConfig)
	}

	switch t { //nolint:exhaustive
	// because StrictKmsProvider already validated above
	case MrkAwareStrictKmsProvider:
		if err := validateUniqueMrks(keyIDs); err != nil {
			return fmt.Errorf("MRK keyIDs validation: %w", errors.Join(providers.ErrConfig, err))
		}
	case DiscoveryKmsProvider:
		if options.discoveryRegion != "" {
			return fmt.Errorf("discovery region must not be set for %q: %w", t, providers.ErrConfig)
		}
	case MrkAwareDiscoveryKmsProvider:
		if options.discoveryRegion == "" {
			if options.defaultRegion == "" {
				return fmt.Errorf("discovery region must be set for %q: %w", t, providers.ErrConfig)
			}
			options.discoveryRegion = options.defaultRegion
		}
	}

	if options.keyFactory == nil {
		return fmt.Errorf("keyFactory must not be nil: %w", providers.ErrConfig)
	}

	if options.keyProvider == nil {
		return fmt.Errorf("keyProvider must not be nil: %w", providers.ErrConfig)
	}

	return nil
}

func validateKeyArns(keyIDs []string) error {
	for _, keyID := range keyIDs {
		if _, err := arn.ParseArn(keyID); err != nil {
			return fmt.Errorf("%q keyID is not a valid ARN: %w", keyID, err)
		}
	}
	return nil
}

func validateDiscoveryFilter(df *discoveryFilter) error {
	if len(df.accountIDs) == 0 {
		return fmt.Errorf("accountIDs must not be empty")
	}
	if df.partition != _awsPartition {
		return fmt.Errorf("%s partition is not supported", df.partition)
	}

	for _, accountID := range df.accountIDs {
		if err := validateAccountID(accountID); err != nil {
			return fmt.Errorf("validate accountID: %w", err)
		}
	}
	return nil
}

func validateAccountID(accountID string) error {
	if accountID == "" {
		return fmt.Errorf("accountID must not be empty")
	}
	if len(accountID) != _awsAccountIDLength {
		return fmt.Errorf("%q accountID must be %d digits long", accountID, _awsAccountIDLength)
	}
	if _, err := strconv.Atoi(accountID); err != nil {
		return fmt.Errorf("%q accountID must contain only digits", accountID)
	}
	return nil
}

func validateUniqueMrks(keyIDs []string) error {
	mrkKeyIDs, err := arn.FilterKeyIDs(arn.IsValidMrkIdentifier, keyIDs)
	if err != nil {
		return err
	}
	duplicateIDs := make(map[string]struct{})
	for _, pair := range itertools.Combinations(mrkKeyIDs, 2) { //nolint:gomnd
		key1, key2 := pair[0], pair[1]
		if structs.MapContains(duplicateIDs, key1) && structs.MapContains(duplicateIDs, key2) {
			continue
		}
		ok, _ := arn.KeyResourceEqual(key1, key2)
		// error ignored because ARN is already validated IsValidMrkIdentifier
		// or filtered out by FilterKeyIDs
		if ok {
			if !structs.MapContains(duplicateIDs, key1) {
				duplicateIDs[key1] = struct{}{}
			}
			if !structs.MapContains(duplicateIDs, key2) {
				duplicateIDs[key2] = struct{}{}
			}
		}
	}
	if len(duplicateIDs) > 0 {
		return fmt.Errorf("configured MRK key ids must be unique. Found related MRKs: %v", strings.Join(structs.MapKeys(duplicateIDs), ", "))
	}
	return nil
}
