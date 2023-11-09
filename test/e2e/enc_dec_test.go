// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/client"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	u "github.com/chainifynet/aws-encryption-sdk-go/test/e2e/testutils"
)

type testParam struct {
	tKeys   []string
	tEC     map[string]string
	tFrame  int
	tEdk    int
	tClient func(maxEdk int) *client.Client
	tCMM    func(keyIDs []string, opts ...func(options *config.LoadOptions) error) materials.CryptoMaterialsManager
	tCMMi   materials.CryptoMaterialsManager
	tCliCmd func(keyIDs []string, ec map[string]string, frame int, edk int, alg string) *u.CliCmd
}

type tableTestCase struct {
	tName    string
	tWantErr bool
	tInputs  []testFile
	tAlg     *suite.AlgorithmSuite
	tEnc     *testParam
	tDec     *testParam
}

var testEncryptDecryptTableShort = []tableTestCase{
	{
		"Keys3_F1024_Edk3", false, testFilesShort, algSig,
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1_F4096_Edk1", false, testFilesShort,
		algNoSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 4096, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		}, nil,
	},
}

var testEncryptDecryptTable = []tableTestCase{
	{
		"Keys3_F1024_Edk3", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys3_F1024_Edk3", false, testFilesTable,
		algNoSig,
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys3_F1024_Edk3_CMM0", true, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm0keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys3_F1024_Edk3_CMM0", true, testFilesTable,
		algNoSig,
		&testParam{
			tKeys: []string{key1Arn, key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm0keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1_F1024_Edk2_CMM1(2)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1(2)_F1024_Edk2_CMM1(1)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1(2)_F1024_Edk2_CMM1(1)", false, testFilesTable,
		algNoSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1(2)_F1024_Edk3_CMM3(123)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm123keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1(3)_F1024_Edk3_CMM3(123)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 3,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm123keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(1)_Keys1(1)_F1024_Edk2_CMM1(2)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(2)_Keys1(2)_F1024_Edk2_CMM1(1)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(2)_Keys2(23)_F1024_Edk2_CMM1(1)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(1)_Keys2(23)_F1024_Edk2_CMM1(2)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM2(23)_Keys2(23)_F1024_Edk2_CMM1(2)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm2keys23, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM2(23)_Keys2(23)_F1024_Edk2_CMM1(1)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn, key3Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm2keys23, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM2(23)_Keys1(1)_F1024_Edk2_CMM1(2)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm2keys23, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys2, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(1)_Keys1(2)_F1024_Edk2_CMM1(3)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys3, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(3)_Keys1(2)_F1024_Edk2_CMM1(1)", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys3, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"CMM1(3)_Keys1(2)_F1024_Edk2_CMM1(1)", false, testFilesTable,
		algNoSig,
		&testParam{
			tKeys: []string{key2Arn}, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys3, tCliCmd: u.SetupEncryptCmd,
		},
		&testParam{
			tKeys: nil, tEC: testEc, tFrame: 1024, tEdk: 2,
			tClient: u.SetupClient, tCMM: nil, tCMMi: cmm1keys, tCliCmd: u.SetupDecryptCmd,
		},
	},
	{
		"Keys1_F16384_Edk1", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 16384, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		nil,
	},
	{
		"Keys1_F16384_Edk1", false, testFilesTable,
		algNoSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 16384, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		nil,
	},
	{
		"Keys1_F128_Edk1", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 128, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		nil,
	},
	{
		"Keys1_F4096_Edk1", false, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 4096, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		nil,
	},
	{
		"Keys1_F64_Edk1", true, testFilesTable, algSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 64, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		nil,
	},
	{
		"Keys1_F64_Edk1", true, testFilesTable,
		algNoSig,
		&testParam{
			tKeys: []string{key1Arn}, tEC: testEc, tFrame: 64, tEdk: 1,
			tClient: u.SetupClient, tCMM: u.SetupCMM, tCMMi: nil, tCliCmd: u.SetupEncryptCmd,
		},
		nil,
	},
}

func getTestTable(_ *testing.T) []tableTestCase {
	if testing.Short() {
		return testEncryptDecryptTableShort
	}
	return testEncryptDecryptTable
}

func Test_Integration_EncryptSDKDecryptCLI(t *testing.T) {
	setupGroupTest(t)

	tests := getTestTable(t)

	for _, tc := range tests {
		for _, tf := range tc.tInputs {
			t.Run(strings.Join([]string{tc.tName, u.AlgSuffix(tc.tAlg), tf.Name}, "_"), func(t *testing.T) {
				ctx := context.Background()
				log.Debug().
					Int("len", len(tf.data)).
					Str("bytes", logger.FmtBytes(tf.data)).
					Str("file", tf.Name).
					Msg("Input")
				///////////
				// encrypt with SDK
				c := tc.tEnc.tClient(tc.tEnc.tEdk)
				assert.NotNil(t, c)
				var cmm materials.CryptoMaterialsManager
				if tc.tEnc.tCMM != nil {
					cmm = tc.tEnc.tCMM(tc.tEnc.tKeys, testAwsLoadOptions...)
				} else {
					cmm = tc.tEnc.tCMMi
				}
				assert.NotNil(t, cmm)
				ciphertextSdk1, header1, err := c.EncryptWithOpts(ctx, tf.data, tc.tEnc.tEC, cmm, tc.tAlg, tc.tEnc.tFrame)
				if err != nil && tc.tWantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.NotNil(t, ciphertextSdk1)
				assert.NotNil(t, header1)

				log.Debug().
					Int("len", len(ciphertextSdk1)).
					Str("bytes", logger.FmtBytes(ciphertextSdk1)).
					Msg("Encrypt SDK")

				////////////
				// decrypt with CLI
				var cmdDecrypt1 *u.CliCmd
				if tc.tDec == nil {
					cmdDecrypt1 = u.NewDecryptCmd(tc.tEnc.tKeys, tc.tEnc.tEC, tc.tEnc.tFrame, tc.tEnc.tEdk)
					require.NotNil(t, cmdDecrypt1)
				} else {
					cmdDecrypt1 = tc.tDec.tCliCmd(tc.tDec.tKeys, tc.tDec.tEC, tc.tDec.tFrame, tc.tDec.tEdk, tc.tAlg.Name())
					require.NotNil(t, cmdDecrypt1)
				}

				plaintextCli1, err := cmdDecrypt1.Run(ciphertextSdk1, tc.tWantErr)
				if err != nil && tc.tWantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				log.Debug().
					Int("len", len(plaintextCli1)).
					Str("bytes", logger.FmtBytes(plaintextCli1)).
					Msg("Decrypt CLI")
				assert.Equal(t, tf.data, plaintextCli1)
			})
		}
	}
}

func Test_Integration_EncryptCLIDecryptSDK(t *testing.T) {
	setupGroupTest(t)
	tests := getTestTable(t)

	for _, tc := range tests {
		for _, tf := range tc.tInputs {
			t.Run(strings.Join([]string{tc.tName, u.AlgSuffix(tc.tAlg), tf.Name}, "_"), func(t *testing.T) {
				ctx := context.Background()
				log.Debug().
					Int("len", len(tf.data)).
					Str("bytes", logger.FmtBytes(tf.data)).
					Str("file", tf.Name).
					Msg("Input")
				////////////
				// encrypt with CLI
				var cmdEncrypt1 *u.CliCmd
				if tc.tDec == nil {
					cmdEncrypt1 = u.NewEncryptCmd(tc.tEnc.tKeys, tc.tEnc.tEC, tc.tEnc.tFrame, tc.tEnc.tEdk, tc.tAlg.Name())
					require.NotNil(t, cmdEncrypt1)
				} else {
					cmdEncrypt1 = tc.tEnc.tCliCmd(tc.tEnc.tKeys, tc.tEnc.tEC, tc.tEnc.tFrame, tc.tEnc.tEdk, tc.tAlg.Name())
					require.NotNil(t, cmdEncrypt1)
				}

				ciphertextCli1, err := cmdEncrypt1.Run(tf.data, tc.tWantErr)
				if err != nil && tc.tWantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				log.Debug().
					Int("len", len(ciphertextCli1)).
					Str("bytes", logger.FmtBytes(ciphertextCli1)).
					Msg("Encrypt CLI")

				///////////
				// decrypt with SDK
				c := tc.tEnc.tClient(tc.tEnc.tEdk)
				assert.NotNil(t, c)
				var cmm materials.CryptoMaterialsManager
				if tc.tDec == nil {
					cmm = tc.tEnc.tCMM(tc.tEnc.tKeys, testAwsLoadOptions...)
				} else {
					if tc.tDec.tCMM != nil {
						cmm = tc.tDec.tCMM(tc.tDec.tKeys, testAwsLoadOptions...)
					} else {
						cmm = tc.tDec.tCMMi
					}
				}
				assert.NotNil(t, cmm)

				// TODO assert header when implemented
				plaintextSdk1, _, err := c.Decrypt(ctx, ciphertextCli1, cmm)
				if err != nil && tc.tWantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tf.data, plaintextSdk1)
				log.Debug().
					Int("len", len(plaintextSdk1)).
					Str("bytes", logger.FmtBytes(plaintextSdk1)).
					Msg("Decrypt SDK")
			})
		}
	}
}

func Test_Integration_EncryptSDK_DecryptCLI_EncryptCLI_DecryptSDK(t *testing.T) { //nolint:gocognit
	setupGroupTest(t)
	tests := getTestTable(t)

	for _, tc := range tests {
		for _, tf := range tc.tInputs {
			t.Run(strings.Join([]string{tc.tName, u.AlgSuffix(tc.tAlg), tf.Name}, "_"), func(t *testing.T) {
				ctx := context.Background()
				tLog := log.With().
					Str("test", tc.tName).
					Logger()
				tLog.Debug().
					Str("alg", u.AlgSuffix(tc.tAlg)).
					Str("bytes", logger.FmtBytes(tf.data)).
					Str("file", tf.Name).
					Msg("Input")
				///////////
				// encrypt with SDK
				c := tc.tEnc.tClient(tc.tEnc.tEdk)
				assert.NotNil(t, c)
				var cmm materials.CryptoMaterialsManager
				if tc.tEnc.tCMM != nil {
					cmm = tc.tEnc.tCMM(tc.tEnc.tKeys, testAwsLoadOptions...)
				} else {
					cmm = tc.tEnc.tCMMi
				}
				assert.NotNil(t, cmm)
				ciphertextSdk1, header1, err := c.EncryptWithOpts(ctx, tf.data, tc.tEnc.tEC, cmm, tc.tAlg, tc.tEnc.tFrame)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrEncryption)
					assert.NotErrorIs(t, err, crypto.ErrDecryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.NotNil(t, ciphertextSdk1)
				assert.NotNil(t, header1)

				tLog.Debug().
					Int("len", len(ciphertextSdk1)).
					Msg("1. Encrypt SDK(cmm and c)")

				////////////
				// decrypt with CLI
				var cmdDecrypt1 *u.CliCmd
				if tc.tDec == nil {
					cmdDecrypt1 = u.NewDecryptCmd(tc.tEnc.tKeys, tc.tEnc.tEC, tc.tEnc.tFrame, tc.tEnc.tEdk)
					require.NotNil(t, cmdDecrypt1)
				} else {
					cmdDecrypt1 = tc.tDec.tCliCmd(tc.tDec.tKeys, tc.tDec.tEC, tc.tDec.tFrame, tc.tDec.tEdk, tc.tAlg.Name())
					require.NotNil(t, cmdDecrypt1)
				}

				plaintextCli1, err := cmdDecrypt1.Run(ciphertextSdk1, tc.tWantErr)
				if err != nil && tc.tWantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				tLog.Debug().
					Int("len", len(plaintextCli1)).
					Msg("2. Decrypt CLI")
				assert.Equal(t, tf.data, plaintextCli1)

				////////////
				// encrypt with CLI
				var cmdEncrypt2 *u.CliCmd
				if tc.tDec == nil {
					cmdEncrypt2 = u.NewEncryptCmd(tc.tEnc.tKeys, tc.tEnc.tEC, tc.tEnc.tFrame, tc.tEnc.tEdk, tc.tAlg.Name())
					require.NotNil(t, cmdEncrypt2)
				} else {
					cmdEncrypt2 = tc.tEnc.tCliCmd(tc.tEnc.tKeys, tc.tEnc.tEC, tc.tEnc.tFrame, tc.tEnc.tEdk, tc.tAlg.Name())
					require.NotNil(t, cmdEncrypt2)
				}

				ciphertextCli2, err := cmdEncrypt2.Run(tf.data, tc.tWantErr)
				if err != nil && tc.tWantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				tLog.Debug().
					Int("len", len(ciphertextCli2)).
					Msg("3. Encrypt CLI")

				///////////
				// decrypt with SDK
				// using the same cmm and client

				// TODO assert header when implemented
				plaintextSdk2, _, err := c.Decrypt(ctx, ciphertextCli2, cmm)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrDecryption)
					assert.NotErrorIs(t, err, crypto.ErrEncryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tf.data, plaintextSdk2)
				assert.Equal(t, plaintextCli1, plaintextSdk2)
				tLog.Debug().
					Int("len", len(plaintextSdk2)).
					Msg("4. Decrypt SDK(cmm and c)")

				//////////
				// decrypt with SDK
				// using new cmm and client
				var c2 *client.Client
				if tc.tDec == nil {
					c2 = tc.tEnc.tClient(tc.tEnc.tEdk)
				} else {
					c2 = tc.tDec.tClient(tc.tDec.tEdk)
				}
				assert.NotNil(t, c2)
				var cmm2 materials.CryptoMaterialsManager
				if tc.tDec == nil {
					cmm2 = tc.tEnc.tCMM(tc.tEnc.tKeys, testAwsLoadOptions...)
				} else {
					if tc.tDec.tCMM != nil {
						cmm2 = tc.tDec.tCMM(tc.tDec.tKeys, testAwsLoadOptions...)
					} else {
						cmm2 = tc.tDec.tCMMi
					}
				}
				assert.NotNil(t, cmm2)

				// TODO assert header when implemented
				plaintextSdk3, _, err := c2.Decrypt(ctx, ciphertextCli2, cmm2)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrDecryption)
					assert.NotErrorIs(t, err, crypto.ErrEncryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tf.data, plaintextSdk3)
				assert.Equal(t, plaintextSdk3, plaintextSdk2)
				assert.Equal(t, plaintextSdk3, plaintextCli1)
				tLog.Debug().
					Int("len", len(plaintextSdk3)).
					Msg("5. Decrypt SDK(new cmm2 and c2)")
				///////////
				// encrypt with SDK
				// using cmm2 and c2 that was used to Decrypt

				ciphertextSdk2, header2, err := c2.EncryptWithOpts(ctx, tf.data, tc.tEnc.tEC, cmm2, tc.tAlg, tc.tEnc.tFrame)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrEncryption)
					assert.NotErrorIs(t, err, crypto.ErrDecryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.NotNil(t, ciphertextSdk2)
				assert.NotNil(t, header2)

				tLog.Debug().
					Int("len", len(ciphertextSdk2)).
					Msg("6. Encrypt SDK(cmm2 and c2)")

				///////////
				// encrypt with SDK
				// using cmm and c that was used to Encrypt initially

				ciphertextSdk3, header3, err := c.EncryptWithOpts(ctx, tf.data, tc.tEnc.tEC, cmm, tc.tAlg, tc.tEnc.tFrame)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrEncryption)
					assert.NotErrorIs(t, err, crypto.ErrDecryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.NotNil(t, ciphertextSdk3)
				assert.NotNil(t, header3)

				tLog.Debug().
					Int("len", len(ciphertextSdk3)).
					Msg("7. Encrypt SDK(cmm and c)")

				///////////
				// Decrypt with SDK
				// using cmm and c that was used to Encrypt initially
				// TODO assert header when implemented
				plaintextSdk4, _, err := c.Decrypt(ctx, ciphertextSdk2, cmm)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrDecryption)
					assert.NotErrorIs(t, err, crypto.ErrEncryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tf.data, plaintextSdk4)
				assert.Equal(t, plaintextSdk3, plaintextSdk4)
				assert.Equal(t, plaintextSdk2, plaintextSdk4)
				assert.Equal(t, plaintextCli1, plaintextSdk4)
				tLog.Debug().
					Int("len", len(plaintextSdk4)).
					Msg("8. Decrypt SDK(cmm and c)")

				///////////
				// Decrypt with SDK
				// using cmm2 and c2 that was used Decrypt
				// TODO assert header when implemented
				plaintextSdk5, _, err := c2.Decrypt(ctx, ciphertextSdk3, cmm2)
				if err != nil && tc.tWantErr {
					assert.ErrorIs(t, err, crypto.ErrDecryption)
					assert.NotErrorIs(t, err, crypto.ErrEncryption)
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tf.data, plaintextSdk5)
				assert.Equal(t, plaintextSdk3, plaintextSdk5)
				tLog.Debug().
					Int("len", len(plaintextSdk5)).
					Msg("9. Decrypt SDK(cmm2 and c2)")
			})
		}
	}
}
