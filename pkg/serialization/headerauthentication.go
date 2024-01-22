// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

const (
	headerAuthDataLen = int(16) // TODO suite.AlgorithmSuite.EncryptionSuite.AuthLen
	headerAuthIvLen   = int(12) // iv only present in V1 TODO suite.AlgorithmSuite.EncryptionSuite.IvLen
)

type headerAuth struct {
	version            suite.MessageFormatVersion
	authenticationData []byte // 16 bytes, authenticationData is auth tag
	iv                 []byte // 12 bytes, iv always 0x00 bytes in MessageFormatVersion V1, not present in V2
}

func (ha headerAuth) AuthData() []byte {
	return ha.authenticationData
}

func (ha headerAuth) IV() []byte {
	return ha.iv
}

func NewHeaderAuth(v suite.MessageFormatVersion, iv, authData []byte) (format.MessageHeaderAuth, error) {
	// TODO validate MessageFormatVersion and iv
	if len(authData) != headerAuthDataLen {
		return nil, fmt.Errorf("incorrect len of authData %d", len(authData))
	}
	return &headerAuth{
		version:            v,
		iv:                 iv,
		authenticationData: authData,
	}, nil
}

func (ha headerAuth) Len() int {
	if ha.version == suite.V1 {
		return headerAuthIvLen + headerAuthDataLen // 12 + 16 bytes
	}
	return headerAuthDataLen // 16 bytes, headerAuth.authenticationData is auth tag
}

func (ha headerAuth) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, ha.Len())
	if ha.version == suite.V1 {
		buf = append(buf, ha.iv...)
	}
	buf = append(buf, ha.authenticationData...)
	return buf
}

func deserializeHeaderAuth(v suite.MessageFormatVersion, buf *bytes.Buffer) (format.MessageHeaderAuth, error) {
	var iv []byte
	if v == suite.V1 {
		if buf.Len() < headerAuthIvLen {
			return nil, fmt.Errorf("cant read IV, empty buffer")
		}
		iv = buf.Next(headerAuthIvLen)
	}
	if buf.Len() < headerAuthDataLen {
		return nil, fmt.Errorf("cant read authData, empty buffer")
	}

	authData := buf.Next(headerAuthDataLen)
	// TODO copy authData into new slice, otherwise authData capacity is equal to buf capacity

	return NewHeaderAuth(v, iv, authData)
}
