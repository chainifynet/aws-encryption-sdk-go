module github.com/chainifynet/aws-encryption-sdk-go-tests/example/customKeyProvider

go 1.20

require github.com/chainifynet/aws-encryption-sdk-go v0.4.0

require (
	github.com/aws/aws-sdk-go-v2 v1.28.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.33.0 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	golang.org/x/crypto v0.22.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
