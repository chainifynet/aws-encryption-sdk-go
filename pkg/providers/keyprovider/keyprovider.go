// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
)

// NewKeyProvider is an alias for internal [keyprovider.NewKeyProvider].
//
// It returns a new [keyprovider.KeyProvider] with the given providerID,
// providerKind, and vendOnDecrypt.
//
//   - providerID: The provider ID. Must be unique across all providers.
//   - providerKind: The provider kind. Use [types.Custom] for custom providers.
//   - vendOnDecrypt: If true, the provider will vend data keys on decrypt which
//     enables discovery of the provider.
func NewKeyProvider(providerID string, providerKind types.ProviderKind, vendOnDecrypt bool) *keyprovider.KeyProvider {
	return keyprovider.NewKeyProvider(providerID, providerKind, vendOnDecrypt)
}
