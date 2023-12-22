// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const (
	DefaultFrameLength = int(4096) // default frame size for encryption
)

// EncryptOptions defines the configuration options for the encryption process.
// It contains settings such as the algorithm to use for encryption and the frame length.
//
// Fields:
//   - Algorithm [suite.AlgorithmSuite]: AlgorithmSuite that defines the encryption algorithm to be used.
//     If nil, a default [suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384] algorithm is used.
//   - FrameLength int: Specifies the frame length for encryption. If not set, a default value of DefaultFrameLength is used.
type EncryptOptions struct {
	Algorithm   *suite.AlgorithmSuite
	FrameLength int
}

// EncryptOptionFunc is a function type that applies a configuration option to an EncryptOptions struct.
// It is used to customize the encryption process by setting various options in EncryptOptions.
//
// Each function of this type takes a pointer to an EncryptOptions struct and modifies it accordingly.
// It returns an error if the provided option is invalid or cannot be applied.
//
// Use WithAlgorithm and WithFrameLength to create EncryptOptionFunc functions.
type EncryptOptionFunc func(o *EncryptOptions) error

// WithAlgorithm returns an EncryptOptionFunc that sets the encryption algorithm in EncryptOptions.
// This function allows the caller to specify a custom algorithm for encryption.
//
// Parameters:
//   - alg [suite.AlgorithmSuite]: [suite.AlgorithmSuite] which defines the encryption algorithm to be used.
//
// Returns:
//   - EncryptOptionFunc: A function that sets the Algorithm field in EncryptOptions.
//
// Errors:
//   - If alg is nil, it returns an error indicating that the algorithm must not be nil.
func WithAlgorithm(alg *suite.AlgorithmSuite) EncryptOptionFunc {
	return func(o *EncryptOptions) error {
		if alg == nil {
			return fmt.Errorf("algorithm must not be nil")
		}
		o.Algorithm = alg
		return nil
	}
}

// WithFrameLength returns an EncryptOptionFunc that sets the frame length in EncryptOptions.
// This function allows the caller to specify a custom frame length for encryption, within allowed limits.
//
// Parameters:
//   - frameLength int: The frame length to be set for encryption.
//
// Returns:
//   - EncryptOptionFunc: A function that sets the FrameLength field in EncryptOptions.
//
// Errors:
//   - If frameLength is less than [suite.MinFrameSize] (128) or greater than [suite.MaxFrameSize] (2147483647),
//     it returns an error indicating that the frame length is out of range.
//   - If frameLength is not a multiple of the [suite.BlockSize] (128) of the crypto
//     algorithm, it returns an error indicating that.
func WithFrameLength(frameLength int) EncryptOptionFunc {
	return func(o *EncryptOptions) error {
		if err := suite.ValidateFrameLength(frameLength); err != nil {
			return err
		}
		o.FrameLength = frameLength
		return nil
	}
}
