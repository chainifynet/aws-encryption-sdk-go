module github.com/chainifynet/aws-encryption-sdk-go/example/basicEncryption

go 1.20

require github.com/chainifynet/aws-encryption-sdk-go v0.4.0

require (
	github.com/aws/aws-sdk-go-v2 v1.26.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.30.0 // indirect
	github.com/aws/smithy-go v1.20.1 // indirect
	golang.org/x/crypto v0.21.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
