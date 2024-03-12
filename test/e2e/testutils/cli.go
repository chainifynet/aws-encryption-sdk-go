// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/test/e2e/logger"
)

var log = logger.L().Level(zerolog.DebugLevel) //nolint:gochecknoglobals

const (
	cliCmd = "aws-encryption-cli"
)

type CliCmd struct {
	stdout  *bytes.Buffer
	stdin   *bytes.Buffer
	stderr  *bytes.Buffer
	debug   bool
	command string
	args    []string
}

func NewEncryptCmd(keyIDs []string, ec map[string]string, frame, edk int, alg string, policy suite.CommitmentPolicy) *CliCmd {
	command, args := encryptCmdArgs(keyIDs, ec, frame, edk, alg, mapCommitmentPolicy(policy))
	//log.Trace().Str("command", command).Strs("args", args).Msg("new EncryptCmd")
	return &CliCmd{
		stdout:  new(bytes.Buffer),
		stderr:  new(bytes.Buffer),
		debug:   true,
		command: command,
		args:    args,
	}
}

func NewDecryptCmd(keyIDs []string, ec map[string]string, frame, edk int, policy suite.CommitmentPolicy) *CliCmd {
	command, args := decryptCmdArgs(keyIDs, ec, frame, edk, mapCommitmentPolicy(policy))
	//log.Trace().Str("command", command).Strs("args", args).Msg("new DecryptCmd")
	return &CliCmd{
		stdout:  new(bytes.Buffer),
		stderr:  new(bytes.Buffer),
		debug:   true,
		command: command,
		args:    args,
	}
}

func NewVersionCmd() *CliCmd {
	return &CliCmd{
		stdout:  new(bytes.Buffer),
		stderr:  new(bytes.Buffer),
		debug:   false,
		command: cliCmd,
		args:    []string{"--version"},
	}
}

func (c *CliCmd) Run(input []byte, wantErr bool) (output []byte, err error) {
	inputCpy := make([]byte, len(input))
	if len(input) > 0 {
		copy(inputCpy, input)
	}

	getLogger := func() zerolog.Logger {
		if c.debug {
			return log.Level(zerolog.DebugLevel)
		}
		return log.Level(zerolog.WarnLevel)
	}

	logCmd := getLogger()

	c.stdin = bytes.NewBuffer(inputCpy)

	cmd := exec.Command(c.command, c.args...) //#nosec:G204
	// see https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/key_providers/kms.py#L963-L965
	// = compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
	// # If an AWS SDK Default Region can not be obtained
	// # initialization MUST fail.
	cmd.Env = append(os.Environ(), "AWS_DEFAULT_REGION=us-east-1")
	log.Trace().
		Str("cmd", cmd.String()).
		Msg("CliCmd.Run")
	logCmd.Debug().
		Int("stdin", c.stdin.Len()).
		Int("stdinBytes", len(c.stdin.Bytes())).
		Msg("stdin")
	cmd.Stdout = c.stdout
	cmd.Stderr = c.stderr
	if c.stdin.Len() > 0 {
		cmd.Stdin = c.stdin
	}
	if err = cmd.Run(); err != nil {
		if c.stderr.Len() > 0 && !wantErr {
			log.Error().
				Int("stdout", c.stdout.Len()).
				Int("stderrLen", c.stderr.Len()).
				Msg("stderr not empty")
			fmt.Print(c.stderr.String())
		}
		return nil, fmt.Errorf("cmd.Run: %w", err)
	}
	logCmd.Debug().
		Int("stdout", c.stdout.Len()).
		Int("stdoutBytes", len(c.stdout.Bytes())).
		Msg("stdout")
	if c.stderr.Len() > 0 {
		if !wantErr {
			log.Error().Int("stderrLen", c.stderr.Len()).
				Msg("stderr not empty")
			fmt.Print(c.stderr.String())
		}
		return nil, fmt.Errorf("stderr not empty")
	}
	stdoutCpy := make([]byte, c.stdout.Len())
	copy(stdoutCpy, c.stdout.Bytes())
	return stdoutCpy, nil
}

//goland:noinspection GoUnusedParameter
func decryptCmdArgs(keyIDs []string, ec map[string]string, _, edk int, policy string) (command string, args []string) {
	wrappedKeys := wrappingKeysArg(keyIDs)
	ecArgs := encryptionContextArg(ec)
	cmdArgs := []string{
		"--decrypt",
		//"-vvvv",
		"--buffer", // decrypt only
		"--suppress-metadata",
		"--input", "-",
		"--output", "-",
		"--commitment-policy", policy, // decrypt optional
		//"--frame-length", "1024", // enc only
		"--max-encrypted-data-keys", strconv.Itoa(edk), // dec optional
	}
	if wrappedKeys != nil {
		cmdArgs = append(cmdArgs, wrappedKeys...)
	} else {
		// discovery=true attribute of the --wrapping-keys parameter to allow
		// AWS Encryption CLI gets the AWS KMS keys from metadata in the encrypted message
		cmdArgs = append(cmdArgs, "--wrapping-keys", "discovery=true")
	}
	if ecArgs != nil {
		cmdArgs = append(cmdArgs, ecArgs...)
	}
	return cliCmd, cmdArgs
}

func encryptCmdArgs(keyIDs []string, ec map[string]string, frame, edk int, algorithm, policy string) (command string, args []string) {
	wrappedKeys := encryptWrappingKeysArg(keyIDs)
	ecArgs := encryptionContextArg(ec)
	cmdArgs := []string{
		"--encrypt",
		//"-vvvv",
		//"--buffer", // decrypt only
		"--suppress-metadata",
		"--input", "-",
		"--output", "-",
		"--commitment-policy", policy,
		"--frame-length", strconv.Itoa(frame), // enc only
		"--max-encrypted-data-keys", strconv.Itoa(edk), // enc only
	}
	if algorithm != "" {
		cmdArgs = append(cmdArgs, "--algorithm", algorithm)
	}
	if wrappedKeys != nil {
		cmdArgs = append(cmdArgs, wrappedKeys...)
	}
	if ecArgs != nil {
		cmdArgs = append(cmdArgs, ecArgs...)
	}
	return cliCmd, cmdArgs
}

func mapCommitmentPolicy(p suite.CommitmentPolicy) string {
	switch p {
	case suite.CommitmentPolicyForbidEncryptAllowDecrypt:
		return "forbid-encrypt-allow-decrypt"
	case suite.CommitmentPolicyRequireEncryptAllowDecrypt:
		return "require-encrypt-allow-decrypt"
	case suite.CommitmentPolicyRequireEncryptRequireDecrypt:
		return "require-encrypt-require-decrypt"
	default:
		return "require-encrypt-require-decrypt"
	}
}

func encryptionContextArg(ec map[string]string) []string {
	values := make([]string, 0, len(ec))
	for k, v := range ec {
		values = append(values, fmt.Sprintf("%s=%s", k, v))
	}
	if len(values) == 0 {
		return nil
	}
	ecArgs := []string{
		"--encryption-context",
	}
	ecArgs = append(ecArgs, values...)
	return ecArgs
}

func wrappingKeysArg(keyIDs []string) []string {
	wrapKeys := make([]string, 0, len(keyIDs))
	//wrapKeys = append(wrapKeys, "--wrapping-keys")
	for _, keyID := range keyIDs {
		//wrapKeys = append(wrapKeys, "--wrapping-keys")
		wrapKeys = append(wrapKeys, "--wrapping-keys", fmt.Sprintf("key=%s", keyID))
	}
	if len(wrapKeys) == 0 {
		return nil
	}
	return wrapKeys
}

func encryptWrappingKeysArg(keyIDs []string) []string {
	wrapKeys := make([]string, 0, len(keyIDs))
	//wrapKeys = append(wrapKeys, "--wrapping-keys")
	for _, keyID := range keyIDs {
		//wrapKeys = append(wrapKeys, "--wrapping-keys") // default
		wrapKeys = append(wrapKeys, "--wrapping-keys", fmt.Sprintf("key=%s", keyID))
	}
	if len(wrapKeys) == 0 {
		return nil
	}
	return wrapKeys
}
