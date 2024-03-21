## Custom Key Provider Example

This example demonstrates how to implement your own custom key provider along with custom master key to encrypt and decrypt data with the AWS Encryption SDK for Go.

**Disclaimer**: Provided example is for demonstration purposes only.

Do not use `MyProvider` and `MyKey` in production due to security reasons.

`MyKey` uses **base64** encoding for encryption and decryption for simplicity of demonstration.

### How to run the example

Run the example with the following command:

```bash
go get
go run ./...
```

Output should look like:

```text
encrypted data key count: 2
encrypted encryption context: map[Purpose:testing User:Alice Year:2023]
decrypted data using key 1: secret data to encrypt
decrypted data using key 2: secret data to encrypt
```
