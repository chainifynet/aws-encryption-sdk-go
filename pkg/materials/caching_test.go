// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestNewCaching(t *testing.T) {
	// TODO Write proper tests once CachingCryptoMaterialsManager is implemented.
	ctx := context.Background()

	mc := &MemoryCache{
		cache: sync.Map{},
	}

	caching, err := NewCaching(mc, nil)
	assert.NoError(t, err)
	assert.NotNil(t, caching)

	encMaterials, err := caching.GetEncryptionMaterials(ctx, model.EncryptionMaterialsRequest{})
	assert.NoError(t, err)
	assert.Nil(t, encMaterials)

	decMaterials, err := caching.DecryptMaterials(ctx, model.DecryptionMaterialsRequest{})
	assert.NoError(t, err)
	assert.Nil(t, decMaterials)

	instance := caching.GetInstance()
	assert.NotNil(t, instance)
	assert.Equal(t, caching, instance)
	assert.EqualValues(t, caching, instance)
	assert.NotSame(t, caching, instance)
}
