module github.com/chainifynet/aws-encryption-sdk-go-tests/example/customKeyProvider

go 1.21

require github.com/chainifynet/aws-encryption-sdk-go v0.5.0

require (
	github.com/aws/aws-sdk-go-v2 v1.32.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.6 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	golang.org/x/crypto v0.29.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
