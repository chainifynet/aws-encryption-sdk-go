// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"fmt"
)

const (
	headerAuthDataLen = int(16) // TODO suite.AlgorithmSuite.EncryptionSuite.AuthLen
)

var MessageHeaderAuth mha

type mha struct{}

type headerAuth struct {
	authenticationData []byte // 16 bytes, authenticationData is auth tag
}

func (ha headerAuth) AuthData() []byte {
	return ha.authenticationData
}

func (h mha) New(authData []byte) (*headerAuth, error) {
	if len(authData) != headerAuthDataLen {
		return nil, fmt.Errorf("incorect len of authData %d", len(authData))
	}
	return &headerAuth{authenticationData: authData}, nil
}

func (ha headerAuth) Len() int {
	return headerAuthDataLen // 16 bytes, headerAuth.authenticationData is auth tag
}

func (ha headerAuth) Serialize() []byte {
	var buf []byte
	buf = make([]byte, 0, headerAuthDataLen)
	buf = append(buf, ha.authenticationData...)
	return buf
}

// Deserialize can be private
// TODO andrew change to private
func (h mha) Deserialize(buf *bytes.Buffer) (*headerAuth, error) {
	if buf.Len() < headerAuthDataLen {
		return nil, fmt.Errorf("empty buffer")
	}

	authData := buf.Next(headerAuthDataLen)

	return h.New(authData)
}
