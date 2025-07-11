module github.com/chainifynet/aws-encryption-sdk-go/example/basicEncryption

go 1.23.0

toolchain go1.24.1

require github.com/chainifynet/aws-encryption-sdk-go v0.5.0

require (
	github.com/aws/aws-sdk-go-v2 v1.36.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.41.0 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	golang.org/x/crypto v0.40.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
