// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/conv"
)

var (
	errFooter = errors.New("message footer error")
)

var MessageFooter = messageFooter{ //nolint:gochecknoglobals
	lenFields: 1,
}

type messageFooter struct {
	lenFields int
}

type footer struct {
	algorithmSuite *suite.AlgorithmSuite // algorithmSuite in suite.AlgorithmSuite in order to check with Authentication.SignatureLen
	signLen        int                   // 2, SignLen is a length of Signature
	Signature      []byte                // vary, length is SignLen, ECDSA Signature
}

func (mf messageFooter) NewFooter(alg *suite.AlgorithmSuite, signature []byte) (*footer, error) {
	if alg.Authentication.SignatureLen != len(signature) {
		return nil, fmt.Errorf("invalid signature length, %w", errFooter)
	}
	return &footer{
		algorithmSuite: alg,
		signLen:        len(signature),
		Signature:      signature,
	}, nil
}

func (mf messageFooter) FromBuffer(alg *suite.AlgorithmSuite, buf *bytes.Buffer) (*footer, error) {
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
		Signature:      signature,
	}, nil
}

func (f *footer) len() int {
	return (MessageFooter.lenFields * lenFieldBytes) +
		f.signLen
}

func (f *footer) String() string {
	return fmt.Sprintf("footer: %s, signLen: %d, Signature: %d", f.algorithmSuite, f.signLen, len(f.Signature))
	//return fmt.Sprintf("%#v", *f)
}

func (f *footer) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, f.len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(f.signLen)...)
	buf = append(buf, f.Signature...)
	return buf
}
