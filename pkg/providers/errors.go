// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package providers

import "errors"

// ErrMasterKeyProvider is a generic error for master key provider.
var ErrMasterKeyProvider = errors.New("MKP error")

// ErrMasterKeyProviderDecrypt is returned when the master key provider fails to
// decrypt.
var ErrMasterKeyProviderDecrypt = errors.New("MKP decrypt error")

// ErrMasterKeyProviderDecryptForbidden is returned when the master key provider
// fails to decrypt due to forbidden access or filtering.
var ErrMasterKeyProviderDecryptForbidden = errors.New("MKP decrypt forbidden error")

// ErrMasterKeyProviderEncrypt is returned when the master key provider fails to
// encrypt.
var ErrMasterKeyProviderEncrypt = errors.New("MKP encrypt error")

// ErrMasterKeyProviderNoPrimaryKey is returned when the master key provider has
// no primary key.
var ErrMasterKeyProviderNoPrimaryKey = errors.New("MKP no primary key")

// ErrConfig is returned when the master key provider has a configuration error.
var ErrConfig = errors.New("MKP config error")

// ErrFilterKeyNotAllowed is returned when the master key provider has a key that
// is not allowed by the filter.
var ErrFilterKeyNotAllowed = errors.New("MKP key not allowed by filter")
