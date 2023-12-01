// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import "errors"

var (
	ErrMasterKeyProvider                 = errors.New("MKP error")
	ErrMasterKeyProviderDecrypt          = errors.New("MKP decrypt error")
	ErrMasterKeyProviderDecryptForbidden = errors.New("MKP decrypt forbidden error")
	ErrMasterKeyProviderEncrypt          = errors.New("MKP encrypt error")
	ErrMasterKeyProviderNoPrimaryKey     = errors.New("MKP no primary key")
	ErrConfig                            = errors.New("MKP config error")
	ErrFilterKeyNotAllowed               = errors.New("MKP key not allowed by filter")
)
