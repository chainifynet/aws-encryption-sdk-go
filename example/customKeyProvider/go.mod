module github.com/chainifynet/aws-encryption-sdk-go-tests/example/customKeyProvider

go 1.22

toolchain go1.24.1

require github.com/chainifynet/aws-encryption-sdk-go v0.5.0

require (
	github.com/aws/aws-sdk-go-v2 v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.39.0 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	golang.org/x/crypto v0.32.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
