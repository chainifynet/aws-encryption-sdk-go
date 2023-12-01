// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package keys

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"

type BaseKey struct {
	metadata model.KeyMeta
}

func NewBaseKey(metadata model.KeyMeta) BaseKey {
	return BaseKey{metadata: metadata}
}

func (mk *BaseKey) KeyID() string {
	return mk.metadata.KeyID
}

func (mk *BaseKey) Metadata() model.KeyMeta {
	return mk.metadata
}

func (mk *BaseKey) OwnsDataKey(key model.Key) bool {
	return mk.metadata.KeyID == key.KeyID()
}
