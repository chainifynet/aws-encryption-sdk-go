# AWS Encryption SDK for Go

[![Go Unit](https://github.com/chainifynet/aws-encryption-sdk-go/actions/workflows/go-unit.yml/badge.svg?branch=main)](https://github.com/chainifynet/aws-encryption-sdk-go/actions/workflows/go-unit.yml)
[![Go E2E](https://github.com/chainifynet/aws-encryption-sdk-go/actions/workflows/go-e2e.yml/badge.svg?branch=main)](https://github.com/chainifynet/aws-encryption-sdk-go/actions/workflows/go-e2e.yml)
![Code style: gofmt](https://img.shields.io/badge/code_style-gofmt-00ADD8.svg)

This project is an implementation of the [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/reference.html) for the Go programming language, providing a set of libraries for developers to easily add encryption and decryption functionality to their Go applications. This implementation is inspired by the [aws-encryption-sdk-python](https://github.com/aws/aws-encryption-sdk-python) and follows the [AWS Encryption SDK specification](https://github.com/awslabs/aws-encryption-sdk-specification/tree/c35fbd91b28303d69813119088c44b5006395eb4) closely.

## Motivation

The motivation behind this project was the absence of a Go implementation of the AWS Encryption SDK.
This SDK aims to fill that gap, offering Go developers the tools to implement encryption according to AWS standards.

## Features

- Support for Message Format Version 2 and related [algorithms](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html).
- AWS KMS Master Key Provider with a discovery filter.
- Raw Master Key provider using static keys.
- Comprehensive [end-to-end tests](test/e2e/enc_dec_test.go) ensuring compatibility with `aws-encryption-sdk-cli`.

### Current Limitations

- Does not support the Caching Materials Manager feature yet.
- Does not support KMS aliases and MRK keys at this stage.
- Raw Master Key provider does not support RSA encryption.
- Only framed content type is supported.

## Requirements

- Go v1.20 or later.
- AWS SDK for Go v2

## Installation

To install the AWS Encryption SDK for Go, use the following command:

```bash
$ go get github.com/chainify/aws-encryption-sdk-go
```

## Usage

This SDK provides a straightforward interface for encrypting and decrypting data.

#### For advanced use cases, check [examples](example).

### Setting Up the Client

First, set up the client with the necessary configuration.

#### Default Client Configuration

```go
import (
	"github.com/chainify/aws-encryption-sdk-go/client"
	"github.com/chainify/aws-encryption-sdk-go/clientconfig"
	"github.com/chainify/aws-encryption-sdk-go/materials"
	"github.com/chainify/aws-encryption-sdk-go/providers"
	"github.com/chainify/aws-encryption-sdk-go/suite"
)

// setup Encryption SDK client with default config
sdkClient := client.NewClient()
```

#### Custom Client Configuration (advanced)

You can specify the commitment policy and the limit of maximum encrypted data keys.

```go
// setup Encryption SDK client with custom client config
cfg, err := clientconfig.NewConfigWithOpts(
	clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptRequireDecrypt),
	clientconfig.WithMaxEncryptedDataKeys(3),
)
if err != nil {
	panic(err) // handle error
}

// setup Encryption SDK client with a custom config
sdkClient := client.NewClientWithConfig(cfg)
```

### Prepare the Key Provider

#### Raw Key Provider using static keys

```go
rawKeyProvider, err := providers.NewRawKeyProviderWithOpts(
	"raw",
	providers.WithStaticKey("static1", []byte("superSecureKeySecureKey32bytes32")),
)
if err != nil {
	panic("raw key provider setup failed") // handle error
}
```

#### KMS Key Provider using KMS CMKs

You can optionally enable [discovery](example/discoveryKmsProvider) or specify a [discovery filter](example/discoveryFilterKmsProvider).

```go
// KMS key ARN to be used for encryption and decryption
kmsKeyArn := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

// setup KMS key provider
kmsKeyProvider, err := providers.NewKmsKeyProvider(kmsKeyArn)
if err != nil {
	panic("raw key provider setup failed") // handle error
}
```

### Create the Crypto Materials Manager

You can use either the KMS Key Provider, Raw Key Provider, or [both combining](example/multipleKeyProvider) them.

#### Crypto Materials Manager with the Raw Key Provider

```go
cmm, err := materials.NewDefault(rawKeyProvider)
if err != nil {
	panic("materials manager setup failed") // handle error
}
```

#### Crypto Materials Manager with KMS Key Provider

```go
cmm, err := materials.NewDefault(kmsKeyProvider)
if err != nil {
	panic("materials manager setup failed") // handle error
}
```

#### Crypto Materials Manager using both KMS and Raw Key Providers

```go
cmm, err := materials.NewDefault(kmsKeyProvider, rawKeyProvider)
if err != nil {
	panic("materials manager setup failed") // handle error
}
```

### Encrypting Data

To encrypt data, call the `Encrypt` method on the client.

```go
// define the encryption context, which is a set of key-value pairs that represent additional authenticated data
encryptionContext := map[string]string{
	"purpose": "test",
}

// data to encrypt
secretData := []byte("secret data to encrypt")

// encrypt data
ciphertext, header, err := sdkClient.Encrypt(
	context.TODO(),
	secretData,
	encryptionContext,
	cmm,
)
if err != nil {
    panic("encryption failed") // handle error
}
```

### Decrypting Data

To decrypt data, use the `Decrypt` method on the client.

```go
// decrypt data
plaintext, header, err := sdkClient.Decrypt(context.TODO(), ciphertext, cmm)
if err != nil {
	panic("decryption failed") // handle error
}
```

## TODO

- [ ] Add support for Caching Materials Manager.
- [ ] Add support for KMS aliases and MRK keys.
- [ ] Cover `providers` package with tests.
- [ ] Cover `keys` package with tests.
- [ ] Cover `materials` package with tests.
- [ ] GoDoc documentation.
- [ ] Streamlined encryption and decryption.

## Support and Contributions

If you encounter any issues or would like to contribute to the project, please submit an issue or pull request on GitHub.

## License

This SDK is licensed under the Apache License 2.0. See the [LICENSE](LICENSE.txt) file for details.

For more information on how to use this SDK, please refer to the `example` directory and the detailed API reference in the documentation.

---

Stay tuned for further updates and features. Contributions and feedback are welcome!
