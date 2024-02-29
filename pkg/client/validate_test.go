// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func Test_validateParams(t *testing.T) {
	tests := []struct {
		name       string
		ctx        context.Context //nolint:containedctx
		source     []byte
		cmm        model.CryptoMaterialsManager
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "valid",
			ctx:     context.Background(),
			source:  []byte("source"),
			cmm:     mocks.NewMockCryptoMaterialsManager(t),
			wantErr: false,
		},
		{
			name:       "nil context",
			ctx:        nil,
			source:     []byte("source"),
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			wantErr:    true,
			wantErrStr: "nil context",
		},
		{
			name:       "empty source",
			ctx:        context.Background(),
			source:     []byte(""),
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			wantErr:    true,
			wantErrStr: "empty source",
		},
		{
			name:       "nil source",
			ctx:        context.Background(),
			source:     nil,
			cmm:        mocks.NewMockCryptoMaterialsManager(t),
			wantErr:    true,
			wantErrStr: "empty source",
		},
		{
			name:       "nil cmm",
			ctx:        context.Background(),
			source:     []byte("source"),
			cmm:        nil,
			wantErr:    true,
			wantErrStr: "nil materials manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateParams(tt.ctx, tt.source, tt.cmm)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
