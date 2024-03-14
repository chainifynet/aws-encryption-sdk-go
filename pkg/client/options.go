// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const (
	// DefaultFrameLength default frame length for encryption.
	DefaultFrameLength = int(4096)
)

// EncryptOptions defines the configuration options for the encryption process.
// It contains settings such as the algorithm to use for encryption and the frame length.
//
// Fields:
//   - Algorithm [suite.AlgorithmSuite]: AlgorithmSuite that defines the encryption algorithm to be used.
//     If nil, a default [suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384] algorithm is used.
//   - FrameLength int: Specifies the frame length for encryption. If not set, a default value of DefaultFrameLength is used.
//   - Handler: Specifies a function that creates [model.EncryptionHandler] encryption handler.
//     If not set, a default [encrypter.New] function is used.
type EncryptOptions struct {
	// Algorithm that defines the encryption algorithm to be used.
	Algorithm *suite.AlgorithmSuite
	// FrameLength specifies the frame length for encryption.
	FrameLength int
	// Handler specifies a function that creates model.EncryptionHandler encryption handler.
	Handler func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler
}

// DecryptOptions defines the configuration options for the decryption process.
//
// Fields:
//   - Handler: Specifies a function that creates [model.DecryptionHandler] decryption handler.
//     If not set, a default [decrypter.New] function is used.
type DecryptOptions struct {
	// Handler specifies a function that creates model.DecryptionHandler decryption handler.
	Handler func(config crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler
}

// EncryptOptionFunc is a function type that applies a configuration option to an EncryptOptions struct.
// It is used to customize the encryption process by setting various options in EncryptOptions.
//
// Each function of this type takes a pointer to an EncryptOptions struct and modifies it accordingly.
// It returns an error if the provided option is invalid or cannot be applied.
//
// Use WithAlgorithm and WithFrameLength to create EncryptOptionFunc functions.
type EncryptOptionFunc func(o *EncryptOptions) error

// DecryptOptionFunc is a function type that applies a configuration option to an DecryptOptions struct.
// It is used to customize the decryption process by setting various options in DecryptOptions.
//
// Each function of this type takes a pointer to an DecryptOptions struct and modifies it accordingly.
// It returns an error if the provided option is invalid or cannot be applied.
//
// Use WithDecryptionHandler to create DecryptOptionFunc function.
type DecryptOptionFunc func(o *DecryptOptions) error

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
		if _, err := suite.ByID(alg.AlgorithmID); err != nil {
			return fmt.Errorf("algorithm error: %w", err)
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

// WithEncryptionHandler returns an EncryptOptionFunc that sets the encryption handler in EncryptOptions.
// This function allows the caller to specify a custom encryption handler.
//
// Used mainly for testing purposes.
//
// Parameters:
//   - h: A function that returns [model.EncryptionHandler].
func WithEncryptionHandler(h func(config crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler) EncryptOptionFunc {
	return func(o *EncryptOptions) error {
		if h == nil {
			return fmt.Errorf("handler must not be nil")
		}
		o.Handler = h
		return nil
	}
}

// WithDecryptionHandler returns an DecryptOptionFunc that sets the decryption handler in DecryptOptions.
// This function allows the caller to specify a custom decryption handler.
//
// Used mainly for testing purposes.
//
// Parameters:
//   - h: A function that returns [model.DecryptionHandler].
func WithDecryptionHandler(h func(config crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler) DecryptOptionFunc {
	return func(o *DecryptOptions) error {
		if h == nil {
			return fmt.Errorf("handler must not be nil")
		}
		o.Handler = h
		return nil
	}
}
