module github.com/chainifynet/aws-encryption-sdk-go/example/multipleKmsKey

go 1.21

require github.com/chainifynet/aws-encryption-sdk-go v0.5.0

require (
	github.com/aws/aws-sdk-go-v2 v1.33.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.29.0 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.53 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.8 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	golang.org/x/crypto v0.32.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
