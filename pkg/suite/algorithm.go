// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
)

// ErrAlgorithmSuite is returned when algorithm suite is invalid or not supported.
var ErrAlgorithmSuite = errors.New("algorithm suite error")

type encAlgorithm string
type cipherMode string

const (
	messageIDV1Len        = int(16) // V1 Message ID size 16 bytes (128-bit unsigned integer)
	messageIDLen          = int(32) // V2 Message ID size 32 bytes (256-bit unsigned integer)
	algorithmSuiteDataLen = int(32)

	bitSize        = int(8) // 1 byte = 8 bits
	algorithmIDLen = int(2) // Algorithm ID size must be 2 bytes (16-bit unsigned integer)

	aesAlg encAlgorithm = "AES"

	gcmMode cipherMode = "GCM"
)

type encryptionSuite struct {
	Algorithm  encAlgorithm
	Mode       cipherMode
	DataKeyLen int
	IVLen      int
	AuthLen    int
}

//goland:noinspection GoSnakeCaseUsage
var (
	aes_128_GCM_IV12_TAG16 = NewEncryptionSuite(aesAlg, gcmMode, 16, 12, 16)
	aes_192_GCM_IV12_TAG16 = NewEncryptionSuite(aesAlg, gcmMode, 24, 12, 16)
	aes_256_GCM_IV12_TAG16 = NewEncryptionSuite(aesAlg, gcmMode, 32, 12, 16)
)

//goland:noinspection GoExportedFuncWithUnexportedType
func NewEncryptionSuite(algorithm encAlgorithm, mode cipherMode, dataKeyLen, ivLen, authLen int) encryptionSuite { //nolint:revive
	return encryptionSuite{Algorithm: algorithm, Mode: mode, DataKeyLen: dataKeyLen, IVLen: ivLen, AuthLen: authLen}
}

type kdfSuite struct {
	KDFFunc  func(hash func() hash.Hash, secret, salt, info []byte) io.Reader
	HashFunc func() hash.Hash
}

//goland:noinspection GoSnakeCaseUsage
var (
	hkdf_NONE   = NewKdfSuite(nil, nil)
	hkdf_SHA256 = NewKdfSuite(hkdf.New, sha256.New)
	hkdf_SHA384 = NewKdfSuite(hkdf.New, sha512.New384)
	hkdf_SHA512 = NewKdfSuite(hkdf.New, sha512.New)
)

//goland:noinspection GoExportedFuncWithUnexportedType
func NewKdfSuite(KDFFunc func(hash func() hash.Hash, secret, salt, info []byte) io.Reader, hashFunc func() hash.Hash) kdfSuite { //nolint:revive
	return kdfSuite{KDFFunc: KDFFunc, HashFunc: hashFunc}
}

type authenticationSuite struct {
	Algorithm    elliptic.Curve
	HashFunc     func() hash.Hash
	SignatureLen int
}

//goland:noinspection GoSnakeCaseUsage
var (
	authSuite_NONE              = newAuthenticationSuite(nil, nil, 0)
	authSuite_SHA256_ECDSA_P256 = newAuthenticationSuite(elliptic.P256(), sha256.New, 71)
	authSuite_SHA256_ECDSA_P384 = newAuthenticationSuite(elliptic.P384(), sha512.New384, 103)
)

func newAuthenticationSuite(algorithm elliptic.Curve, hashFunc func() hash.Hash, signatureLen int) authenticationSuite {
	return authenticationSuite{Algorithm: algorithm, HashFunc: hashFunc, SignatureLen: signatureLen}
}

// AlgorithmSuite represents the algorithm suite used for encryption and decryption.
type AlgorithmSuite struct {
	AlgorithmID          uint16               // An identifier for the algorithm. It is a 2-byte value interpreted as a 16-bit unsigned integer.
	EncryptionSuite      encryptionSuite      // Encryption of the algorithm suite
	MessageFormatVersion MessageFormatVersion // Message format version
	KDFSuite             kdfSuite             // Key Derivation Suite of the algorithm suite
	Authentication       authenticationSuite  // Authentication Suite of the algorithm suite
	name                 string               // Name of the algorithm suite
}

func (as *AlgorithmSuite) GoString() string {
	//return as.String()
	return fmt.Sprintf("%#v", *as)
}

func buildAlgorithmName(as *AlgorithmSuite) string {
	var sb strings.Builder
	// AES_256_GCM
	sb.WriteString(fmt.Sprintf("%v_%d_%v",
		as.EncryptionSuite.Algorithm,
		as.EncryptionSuite.DataKeyLen*bitSize,
		as.EncryptionSuite.Mode,
	))
	if as.MessageFormatVersion == V1 {
		// _IV12_TAG16
		sb.WriteString(fmt.Sprintf("_IV%d_TAG%d", as.EncryptionSuite.IVLen, as.EncryptionSuite.AuthLen))
	}

	if as.KDFSuite.HashFunc != nil {
		// _HKDF_SHA512
		sb.WriteString(fmt.Sprintf("_HKDF_SHA%d", as.KDFSuite.HashFunc().Size()*bitSize))
	}

	if as.IsCommitting() {
		// _COMMIT_KEY
		sb.WriteString("_COMMIT_KEY")
	}

	if as.IsSigning() {
		// _ECDSA_P384
		sb.WriteString(fmt.Sprintf("_ECDSA_P%d", as.Authentication.Algorithm.Params().BitSize))
	}

	// format: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
	return sb.String()
}

// Name returns the name of AlgorithmSuite.
//
// Example:
//
//	AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
func (as *AlgorithmSuite) Name() string {
	return as.name
}

// String returns a string representation of AlgorithmSuite.
//
// Example:
//
//	AlgID 0x0578: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
func (as *AlgorithmSuite) String() string {
	return fmt.Sprintf("AlgID 0x%04X: %s", as.AlgorithmID, as.Name())
}

// IDString returns the ID of AlgorithmSuite as a string.
//
// Example:
//
//	0578
func (as *AlgorithmSuite) IDString() string {
	// format: 0578
	return fmt.Sprintf("%04X", as.AlgorithmID)
}

// IDBytes returns the ID of AlgorithmSuite as a slice of bytes.
func (as *AlgorithmSuite) IDBytes() []byte {
	return conv.FromInt.UUint16BigEndian(as.AlgorithmID)
}

// IsSigning indicates whether the AlgorithmSuite is using ECDSA for signing over
// the ciphertext header and body.
func (as *AlgorithmSuite) IsSigning() bool {
	return as.Authentication.Algorithm != nil
}

// IsKDFSupported indicates whether the AlgorithmSuite is using key derivation to
// derive the data encryption key.
func (as *AlgorithmSuite) IsKDFSupported() bool {
	return as.KDFSuite.KDFFunc != nil
}

// IsCommitting indicates whether the AlgorithmSuite is using key commitment.
// Only [V2] message format version supports key commitment.
func (as *AlgorithmSuite) IsCommitting() bool {
	if bytes.HasPrefix(as.IDBytes(), []byte{0x05}) || bytes.HasPrefix(as.IDBytes(), []byte{0x04}) {
		return true
	}
	return false
}

// MessageIDLen returns the length of the message ID.
func (as *AlgorithmSuite) MessageIDLen() int {
	// all supported algorithmSuite MessageFormatVersion 1 has 16 bytes MessageID length
	if as.MessageFormatVersion == V1 {
		return messageIDV1Len
	}
	// all supported algorithmSuite MessageFormatVersion 2 has 32 bytes MessageID length
	return messageIDLen
}

// AlgorithmSuiteDataLen returns the length of the Algorithm Suite Data field.
func (as *AlgorithmSuite) AlgorithmSuiteDataLen() int {
	if as.MessageFormatVersion == V1 {
		// Algorithm Suite Data field not present in MessageFormatVersion 1
		return 0
	}
	// all supported algorithmSuite version 2 has 32 bytes Algorithm Suite Data field length
	return algorithmSuiteDataLen
}

// Supported [AlgorithmSuite] by AWS Encryption SDK.
//
// See [AWS Encryption SDK algorithms reference] for more information.
//
// [AWS Encryption SDK algorithms reference]: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
//
//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
var (
	// MessageFormatVersion 1 algorithm suites

	AES_128_GCM_IV12_TAG16                        = newAlgorithmSuite(0x0014, aes_128_GCM_IV12_TAG16, V1, hkdf_NONE, authSuite_NONE)                // Algorithm ID: 00 14
	AES_192_GCM_IV12_TAG16                        = newAlgorithmSuite(0x0046, aes_192_GCM_IV12_TAG16, V1, hkdf_NONE, authSuite_NONE)                // Algorithm ID: 00 46
	AES_256_GCM_IV12_TAG16                        = newAlgorithmSuite(0x0078, aes_256_GCM_IV12_TAG16, V1, hkdf_NONE, authSuite_NONE)                // Algorithm ID: 00 78
	AES_128_GCM_IV12_TAG16_HKDF_SHA256            = newAlgorithmSuite(0x0114, aes_128_GCM_IV12_TAG16, V1, hkdf_SHA256, authSuite_NONE)              // Algorithm ID: 01 14
	AES_192_GCM_IV12_TAG16_HKDF_SHA256            = newAlgorithmSuite(0x0146, aes_192_GCM_IV12_TAG16, V1, hkdf_SHA256, authSuite_NONE)              // Algorithm ID: 01 46
	AES_256_GCM_IV12_TAG16_HKDF_SHA256            = newAlgorithmSuite(0x0178, aes_256_GCM_IV12_TAG16, V1, hkdf_SHA256, authSuite_NONE)              // Algorithm ID: 01 78
	AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 = newAlgorithmSuite(0x0214, aes_128_GCM_IV12_TAG16, V1, hkdf_SHA256, authSuite_SHA256_ECDSA_P256) // Algorithm ID: 02 14
	AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = newAlgorithmSuite(0x0346, aes_192_GCM_IV12_TAG16, V1, hkdf_SHA384, authSuite_SHA256_ECDSA_P384) // Algorithm ID: 03 46
	AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 = newAlgorithmSuite(0x0378, aes_256_GCM_IV12_TAG16, V1, hkdf_SHA384, authSuite_SHA256_ECDSA_P384) // Algorithm ID: 03 78

	// MessageFormatVersion 2 algorithm suites with commitment

	AES_256_GCM_HKDF_SHA512_COMMIT_KEY            = newAlgorithmSuite(0x0478, aes_256_GCM_IV12_TAG16, V2, hkdf_SHA512, authSuite_NONE)              // Algorithm ID: 04 78
	AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 = newAlgorithmSuite(0x0578, aes_256_GCM_IV12_TAG16, V2, hkdf_SHA512, authSuite_SHA256_ECDSA_P384) // Algorithm ID: 05 78
)

// Note: we are not accessing this map concurrently on write, so no need to use sync.Map.
var algorithmLookup = map[uint16]*AlgorithmSuite{} //nolint:gochecknoglobals

func newAlgorithmSuite(algorithmID uint16, encryptionSuite encryptionSuite, messageFormatVersion MessageFormatVersion, kdfSuite kdfSuite, authentication authenticationSuite) *AlgorithmSuite { //nolint:unparam
	alg := &AlgorithmSuite{AlgorithmID: algorithmID, EncryptionSuite: encryptionSuite, MessageFormatVersion: messageFormatVersion, KDFSuite: kdfSuite, Authentication: authentication}
	alg.name = buildAlgorithmName(alg)
	algorithmLookup[algorithmID] = alg
	return alg
}

// ByID returns [AlgorithmSuite] by its algorithmID 16-bit unsigned integer.
func ByID(algorithmID uint16) (*AlgorithmSuite, error) {
	val, ok := algorithmLookup[algorithmID]
	if !ok {
		return nil, fmt.Errorf("%#v algorithm not supported: %w", algorithmID, ErrAlgorithmSuite)
	}
	return val, nil
}

// FromBytes returns [AlgorithmSuite] from slice of bytes, slice must have a length of 2 bytes.
func FromBytes(b []byte) (*AlgorithmSuite, error) {
	if len(b) != algorithmIDLen {
		return nil, fmt.Errorf("%#v algorithm size must be 2 bytes: %w", b, ErrAlgorithmSuite)
	}
	return ByID(conv.FromBytes.UUint16BigEndian(b))
}
