// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import "github.com/chainifynet/aws-encryption-sdk-go/pkg/model"

type KeyEntry[V any] struct {
	Entry V
}

func (ke KeyEntry[V]) GetEntry() V {
	return ke.Entry
}

func NewKeyEntry[V model.MasterKey](key V) KeyEntry[V] {
	newEntry := KeyEntry[V]{Entry: key}
	return newEntry
}

func NewKeyEntryPtr[V model.MasterKey](key V) *KeyEntry[V] {
	newEntry := new(KeyEntry[V])
	newEntry.Entry = key
	return newEntry
}
