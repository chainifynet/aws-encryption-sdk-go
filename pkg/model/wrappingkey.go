// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

type Wrapper interface {
	SerializeEncryptedDataKey(encryptedKey, tag, iv []byte) []byte
	DeserializeEncryptedDataKey(b []byte, iVLen int) (encryptedData, iv []byte)
	SerializeKeyInfoPrefix(keyID string) []byte
}
