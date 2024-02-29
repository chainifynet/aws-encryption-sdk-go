// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"io"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type DecryptionHandler interface {
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, format.MessageHeader, error)
}

type EncryptionHandler interface {
	Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, format.MessageHeader, error)
}

type EncryptionBuffer interface {
	io.ReadWriter
	Bytes() []byte
	Len() int
	Reset()
}
