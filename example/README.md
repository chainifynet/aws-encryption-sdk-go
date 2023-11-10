# Usage examples

### [Basic encryption](basicEncryption)

Basic encryption uses a static key to encrypt and decrypt data.
It doesn't require AWS credentials and KMS keys.

### Requirements for AWS KMS examples: 

- **In order to run the examples, you need to have a valid AWS account and credentials configured.**

- You need also set the following environment variables:
    - `KEY_1_ARN`
    - `KEY_2_ARN`

`KEY_1_ARN` and `KEY_2_ARN` with the ARN of the KMS keys you want to use for the examples.

Alternatively, you can replace the values in `main.go` with the ARN of the keys you want to use.

### [Encryption with Custom AWS Config](customAwsKmsConfig)

### [Using Discovery Filter with AWS KMS Key Provider](discoveryFilterKmsProvider)

### [Encrypt and Decrypt with Discovery enabled KMS provider](discoveryKmsProvider)

### [Using KMS and Raw providers to encrypt and decrypt](multipleKeyProvider)

### [Encryption and decryption under multiple AWS KMS CMK](multipleKmsKey)

### [Encryption and decryption with AWS KMS CMK](oneKmsKey)

### [Encrypt using AWS KMS CMK with custom options](oneKmsKeyUnsigned)
