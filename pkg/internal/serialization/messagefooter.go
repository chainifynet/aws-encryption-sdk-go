// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

var (
	errFooter = errors.New("message footer error")
)

type footer struct {
	algorithmSuite *suite.AlgorithmSuite // algorithmSuite in suite.AlgorithmSuite in order to check with Authentication.SignatureLen
	signLen        int                   // 2, SignLen is a length of signature
	signature      []byte                // vary, length is SignLen, ECDSA signature
}

func newFooter(alg *suite.AlgorithmSuite, signature []byte) (*footer, error) {
	if alg.Authentication.SignatureLen != len(signature) {
		return nil, fmt.Errorf("invalid signature length, %w", errFooter)
	}
	return &footer{
		algorithmSuite: alg,
		signLen:        len(signature),
		signature:      signature,
	}, nil
}

func deserializeFooter(alg *suite.AlgorithmSuite, buf *bytes.Buffer) (*footer, error) {
	signLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant read signLen: %w", errors.Join(errFooter, err))
	}
	if signLen != alg.Authentication.SignatureLen {
		return nil, fmt.Errorf("invalid signature length: %w", errFooter)
	}
	if buf.Len() < signLen {
		return nil, fmt.Errorf("malformed footer: %w", errFooter)
	}
	signature := buf.Next(signLen)
	return &footer{
		algorithmSuite: alg,
		signLen:        signLen,
		signature:      signature,
	}, nil
}

func (f *footer) Len() int {
	return lenFieldBytes + f.signLen
}

func (f *footer) String() string {
	return fmt.Sprintf("footer: %s, signLen: %d, signature: %d", f.algorithmSuite, f.signLen, len(f.signature))
	//return fmt.Sprintf("%#v", *f)
}

func (f *footer) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, f.Len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(f.signLen)...)
	buf = append(buf, f.signature...)
	return buf
}

func (f *footer) SignLen() int {
	return f.signLen
}

func (f *footer) Signature() []byte {
	return f.signature
}
