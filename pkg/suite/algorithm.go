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

	"golang.org/x/crypto/hkdf"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

var ErrAlgorithmSuite = errors.New("algorithm suite error")

type encAlgorithm string
type cipherMode string

const (
	messageIDLen          = int(32)
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

//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
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

//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
var (
	hkdf_SHA256 = NewKdfSuite(hkdf.New, sha256.New)    //nolint:unused
	hkdf_SHA384 = NewKdfSuite(hkdf.New, sha512.New384) //nolint:unused
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

//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
var (
	authSuite_NONE              = newAuthenticationSuite(nil, nil, 0)
	authSuite_SHA256_ECDSA_P256 = newAuthenticationSuite(elliptic.P256(), sha256.New, 71)
	authSuite_SHA256_ECDSA_P384 = newAuthenticationSuite(elliptic.P384(), sha512.New384, 103)
)

func newAuthenticationSuite(algorithm elliptic.Curve, hashFunc func() hash.Hash, signatureLen int) authenticationSuite {
	return authenticationSuite{Algorithm: algorithm, HashFunc: hashFunc, SignatureLen: signatureLen}
}

type AlgorithmSuite struct {
	AlgorithmID          uint16
	EncryptionSuite      encryptionSuite
	MessageFormatVersion int
	KDFSuite             kdfSuite
	Authentication       authenticationSuite
}

func (as *AlgorithmSuite) GoString() string {
	//return as.String()
	return fmt.Sprintf("%#v", *as)
}

func (as *AlgorithmSuite) Name() string {
	if as.IsSigning() {
		// AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
		return fmt.Sprintf("%v_%d_%v_HKDF_SHA%d_COMMIT_KEY_ECDSA_P%d",
			as.EncryptionSuite.Algorithm,
			as.EncryptionSuite.DataKeyLen*bitSize,
			as.EncryptionSuite.Mode,
			as.KDFSuite.HashFunc().Size()*bitSize,
			as.Authentication.Algorithm.Params().BitSize,
		)
	}
	// AES_256_GCM_HKDF_SHA512_COMMIT_KEY
	return fmt.Sprintf("%v_%d_%v_HKDF_SHA%d_COMMIT_KEY",
		as.EncryptionSuite.Algorithm,
		as.EncryptionSuite.DataKeyLen*bitSize,
		as.EncryptionSuite.Mode,
		as.KDFSuite.HashFunc().Size()*bitSize,
	)
}

func (as *AlgorithmSuite) String() string {
	// format: AlgID 0x0578: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
	return fmt.Sprintf("AlgID 0x%04X: %s", as.AlgorithmID, as.Name())
}

func (as *AlgorithmSuite) IDBytes() []byte {
	return conv.FromInt.UUint16BigEndian(as.AlgorithmID)
}

func (as *AlgorithmSuite) IsSigning() bool {
	return as.Authentication.Algorithm != nil
}

func (as *AlgorithmSuite) IsCommitting() bool {
	if bytes.HasPrefix(as.IDBytes(), []byte{0x05}) || bytes.HasPrefix(as.IDBytes(), []byte{0x04}) {
		return true
	}
	return false
}

func (as *AlgorithmSuite) MessageIDLen() int {
	// all supported algorithmSuite version 2 has 32 bytes MessageID length
	return messageIDLen
}

func (as *AlgorithmSuite) AlgorithmSuiteDataLen() int {
	// all supported algorithmSuite version 2 has 32 bytes Algorithm Suite Data field length
	return algorithmSuiteDataLen
}

//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
var (
	AES_256_GCM_HKDF_SHA512_COMMIT_KEY            = newAlgorithmSuite(0x0478, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_NONE)
	AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 = newAlgorithmSuite(0x0578, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_SHA256_ECDSA_P384)
	//AES_256_GCM_HKDF_SHA512_COMMIT_KEY_WRAPPING            = newAlgorithmSuite(0x0470, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_NONE)
	//AES_256_GCM_HKDF_SHA512_COMMIT_KEY_WRAPPING_ECDSA_P384 = newAlgorithmSuite(0x0570, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_SHA256_ECDSA_P384)
)

// Note: we are not accessing this map concurrently on write, so no need to use sync.Map.
var algorithmLookup = map[uint16]*AlgorithmSuite{} //nolint:gochecknoglobals

func newAlgorithmSuite(algorithmID uint16, encryptionSuite encryptionSuite, messageFormatVersion int, kdfSuite kdfSuite, authentication authenticationSuite) *AlgorithmSuite { //nolint:unparam
	alg := &AlgorithmSuite{AlgorithmID: algorithmID, EncryptionSuite: encryptionSuite, MessageFormatVersion: messageFormatVersion, KDFSuite: kdfSuite, Authentication: authentication}
	algorithmLookup[algorithmID] = alg
	return alg
}

var Algorithm algorithm

type algorithm struct{}

// ByID returns proper AlgorithmSuite by its algorithmID 16-bit unsigned integer
func (algorithm) ByID(algorithmID uint16) (*AlgorithmSuite, error) {
	val, ok := algorithmLookup[algorithmID]
	if !ok {
		return nil, fmt.Errorf("%#v algorithm not supported: %w", algorithmID, ErrAlgorithmSuite)
	}
	return val, nil
}

// FromBytes returns proper AlgorithmSuite from slice of bytes, slice must have a length of 2 bytes
func (alg algorithm) FromBytes(b []byte) (*AlgorithmSuite, error) {
	if len(b) != algorithmIDLen {
		return nil, fmt.Errorf("%#v algorithm size must be 2 bytes: %w", b, ErrAlgorithmSuite)
	}
	return alg.ByID(conv.FromBytes.UUint16BigEndian(b))
}
