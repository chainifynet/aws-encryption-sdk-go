# Usage examples

### 1. [Basic encryption](basicEncryption)

Basic encryption uses a static key to encrypt and decrypt data.
It doesn't require AWS credentials and KMS keys.

### Requirements for AWS KMS examples: 

- **In order to run the examples, you need to have a valid AWS account and credentials configured.**

- You need also set the following environment variables:
    - `KEY_1_ARN`
    - `KEY_2_ARN`

`KEY_1_ARN` and `KEY_2_ARN` with the ARN of the KMS keys you want to use for the examples.

Alternatively, you can replace the values in `main.go` with the ARN of the keys you want to use.

### 2. [Encryption with Custom AWS Config](customAwsKmsConfig)

### 3. [Using Discovery Filter with AWS KMS Key Provider](discoveryFilterKmsProvider)

### 4. [Encrypt and Decrypt with Discovery enabled KMS provider](discoveryKmsProvider)

### 5. [Encrypt and Decrypt with MRK-aware enabled KMS provider](mrkAwareKmsProvider)

### 6. [Using KMS and Raw providers to encrypt and decrypt](multipleKeyProvider)

### 7. [Encryption and decryption under multiple AWS KMS CMK](multipleKmsKey)

### 8. [Encryption and decryption with AWS KMS CMK](oneKmsKey)

### 9. [Encrypt using AWS KMS CMK with custom options](oneKmsKeyUnsigned)

### 10. [Custom Key Provider and Master Key implementations](customKeyProvider)
Do not use `MyKey` and `MyProvider` in production!
Custom `MyKey` implementation for simplicity of demonstration uses **base64** encoding for encryption and decryption.

---
