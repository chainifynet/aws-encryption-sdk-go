// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suite

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

type encAlgorithm string
type cipherMode string

const (
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
	aes_128_GCM_IV12_TAG16 = newEncryptionSuite(aesAlg, gcmMode, 16, 12, 16)
	aes_192_GCM_IV12_TAG16 = newEncryptionSuite(aesAlg, gcmMode, 24, 12, 16)
	aes_256_GCM_IV12_TAG16 = newEncryptionSuite(aesAlg, gcmMode, 32, 12, 16)
)

func newEncryptionSuite(algorithm encAlgorithm, mode cipherMode, dataKeyLen int, ivLen int, authLen int) encryptionSuite {
	return encryptionSuite{Algorithm: algorithm, Mode: mode, DataKeyLen: dataKeyLen, IVLen: ivLen, AuthLen: authLen}
}

type kdfSuite struct {
	KDFFunc  func(hash func() hash.Hash, secret, salt, info []byte) io.Reader
	HashFunc func() hash.Hash
}

//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
var (
	hkdf_SHA256 = newKdfSuite(hkdf.New, sha256.New)
	hkdf_SHA384 = newKdfSuite(hkdf.New, sha512.New384)
	hkdf_SHA512 = newKdfSuite(hkdf.New, sha512.New)
)

func newKdfSuite(KDFFunc func(hash func() hash.Hash, secret, salt, info []byte) io.Reader, hashFunc func() hash.Hash) kdfSuite {
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
			as.EncryptionSuite.DataKeyLen*8,
			as.EncryptionSuite.Mode,
			as.KDFSuite.HashFunc().Size()*8,
			as.Authentication.Algorithm.Params().BitSize,
		)
	} else {
		// AES_256_GCM_HKDF_SHA512_COMMIT_KEY
		return fmt.Sprintf("%v_%d_%v_HKDF_SHA%d_COMMIT_KEY",
			as.EncryptionSuite.Algorithm,
			as.EncryptionSuite.DataKeyLen*8,
			as.EncryptionSuite.Mode,
			as.KDFSuite.HashFunc().Size()*8,
		)
	}
}

func (as *AlgorithmSuite) String() string {
	// format: AlgID 0x0578: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
	return fmt.Sprintf("AlgID 0x%04X: %s", as.AlgorithmID, as.Name())
}

func (as *AlgorithmSuite) IDBytes() []byte {
	return conv.FromInt.UUint16BigEndian(as.AlgorithmID)
}

func (as *AlgorithmSuite) IsSigning() bool {
	if as.Authentication.Algorithm != nil {
		return true
	}
	return false
}

func (as *AlgorithmSuite) IsCommitting() bool {
	if bytes.HasPrefix(as.IDBytes(), []byte{0x05}) || bytes.HasPrefix(as.IDBytes(), []byte{0x04}) {
		return true
	}
	return false
}

func (as *AlgorithmSuite) MessageIDLen() int {
	// all supported algorithmSuite version 2 has 32 bytes MessageID length
	return 32
}

func (as *AlgorithmSuite) AlgorithmSuiteDataLen() int {
	// all supported algorithmSuite version 2 has 32 bytes Algorithm Suite Data field length
	return 32
}

//goland:noinspection GoSnakeCaseUsage,GoUnusedGlobalVariable
var (
	AES_256_GCM_HKDF_SHA512_COMMIT_KEY            = newAlgorithmSuite(0x0478, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_NONE)
	AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 = newAlgorithmSuite(0x0578, aes_256_GCM_IV12_TAG16, 2, hkdf_SHA512, authSuite_SHA256_ECDSA_P384)
)

// Note: we are not accessing this map concurrently on write, so no need to use sync.Map
var algorithmLookup = map[uint16]*AlgorithmSuite{}

func newAlgorithmSuite(algorithmID uint16, encryptionSuite encryptionSuite, messageFormatVersion int, kdfSuite kdfSuite, authentication authenticationSuite) *AlgorithmSuite {
	alg := &AlgorithmSuite{AlgorithmID: algorithmID, EncryptionSuite: encryptionSuite, MessageFormatVersion: messageFormatVersion, KDFSuite: kdfSuite, Authentication: authentication}
	algorithmLookup[algorithmID] = alg
	return alg
}

var Algorithm algorithm

type algorithm struct{}

// ByID returns proper AlgorithmSuite by its algorithmID 16-bit unsigned integer or panics if algorithm not supported
func (algorithm) ByID(algorithmID uint16) (*AlgorithmSuite, error) {
	val, ok := algorithmLookup[algorithmID]
	if !ok {
		return nil, fmt.Errorf("%#v algorithm not supported", algorithmID)
	}
	return val, nil
}

// FromBytes returns proper AlgorithmSuite from slice of bytes, slice must have a length of 2 bytes. panic if slice length is not 2
func (alg algorithm) FromBytes(b []byte) (*AlgorithmSuite, error) {
	if len(b) != 2 {
		return nil, fmt.Errorf("%#v - algorithm size must be 2 bytes", b)
	}
	return alg.ByID(conv.FromBytes.UUint16BigEndian(b))
}
