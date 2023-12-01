// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers/kmsprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func AlgSuffix(as *suite.AlgorithmSuite) string {
	if as == nil {
		return "NO_ALG"
	}
	if as.IsSigning() {
		return "SIGN"
	}
	return "NONE"
}

var SetupEncryptCmd = func(keyIDs []string, ec map[string]string, frame int, edk int, alg string) *CliCmd { //nolint:gochecknoglobals,gocritic
	return NewEncryptCmd(keyIDs, ec, frame, edk, alg)
}

var SetupDecryptCmd = func(keyIDs []string, ec map[string]string, frame int, edk int, alg string) *CliCmd { //nolint:gochecknoglobals
	return NewDecryptCmd(keyIDs, ec, frame, edk)
}

var SetupCMM = func(keyIDs []string, opts ...func(options *config.LoadOptions) error) model.CryptoMaterialsManager { //nolint:gochecknoglobals
	var kp model.MasterKeyProvider
	if len(keyIDs) > 0 {
		keyProvider, err := kmsprovider.NewWithOpts(
			keyIDs,
			kmsprovider.WithAwsLoadOptions(opts...),
		)
		if err != nil {
			log.Error().Err(err).Msg("setupCMM")
			return nil
		}
		kp = keyProvider
	} else {
		keyProvider, err := kmsprovider.NewWithOpts(
			nil,
			kmsprovider.WithAwsLoadOptions(opts...),
			kmsprovider.WithDiscovery(),
		)
		if err != nil {
			log.Error().Err(err).Msg("setupCMM")
			return nil
		}
		kp = keyProvider
	}

	cmm, _ := materials.NewDefault(kp)

	return cmm
}

var SetupClient = func(maxEdk int) *client.Client { //nolint:gochecknoglobals
	cfg, err := clientconfig.NewConfigWithOpts(
		clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
		clientconfig.WithMaxEncryptedDataKeys(maxEdk),
	)
	if err != nil {
		panic(err)
	}

	c := client.NewClientWithConfig(cfg)

	return c
}
