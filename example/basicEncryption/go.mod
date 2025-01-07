module github.com/chainifynet/aws-encryption-sdk-go/example/basicEncryption

go 1.21

require github.com/chainifynet/aws-encryption-sdk-go v0.5.0

require (
	github.com/aws/aws-sdk-go-v2 v1.32.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.8 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	golang.org/x/crypto v0.32.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
