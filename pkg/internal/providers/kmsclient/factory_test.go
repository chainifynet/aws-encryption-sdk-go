// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsclient_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/kmsclient"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestNewFactory(t *testing.T) {
	tests := []struct {
		name string
		want *kmsclient.Factory
	}{
		{
			name: "New Factory",
			want: &kmsclient.Factory{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, kmsclient.NewFactory(), "NewFactory()")
		})
	}
}

func TestFactory_NewFromConfig(t *testing.T) {
	type args struct {
		cfg    aws.Config
		optFns []func(options *kms.Options)
	}
	tests := []struct {
		name string
		args args
		want model.KMSClient
	}{
		{
			name: "NewFromConfig",
			args: args{
				cfg: aws.Config{},
			},
			want: kms.NewFromConfig(aws.Config{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &kmsclient.Factory{}
			got := f.NewFromConfig(tt.args.cfg, tt.args.optFns...)
			assert.Implements(t, (*model.KMSClient)(nil), got)
			assert.IsType(t, tt.want, got)
		})
	}
}
