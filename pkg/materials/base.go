// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

type CryptoMaterialsManager interface {
	GetEncryptionMaterials(request EncryptionMaterialsRequest) (*EncryptionMaterials, error)
	DecryptMaterials(request DecryptionMaterialsRequest) (*DecryptionMaterials, error)
	GetInstance() CryptoMaterialsManager // TODO research and test
}
