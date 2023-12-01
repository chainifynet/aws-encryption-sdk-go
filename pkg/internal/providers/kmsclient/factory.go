// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsclient

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

const userAgentSuffix string = "AwsEncryptionSdkGo/" + pkg.Version

type Factory struct{}

func NewFactory() *Factory {
	return &Factory{}
}

func (f *Factory) NewFromConfig(cfg aws.Config, optFns ...func(options *kms.Options)) model.KMSClient { //nolint:gocritic
	optFns = append(optFns, kms.WithAPIOptions(withUserAgentAppender(userAgentSuffix)))
	return kms.NewFromConfig(cfg, optFns...)
}
