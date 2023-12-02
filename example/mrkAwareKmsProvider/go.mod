module github.com/chainifynet/aws-encryption-sdk-go/example/mrkAwareKmsProvider

go 1.20

require github.com/chainifynet/aws-encryption-sdk-go v0.1.0

require (
	github.com/aws/aws-sdk-go-v2 v1.23.5 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.25.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.16.8 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.10.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.27.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.18.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.21.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.26.1 // indirect
	github.com/aws/smithy-go v1.18.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rs/zerolog v1.31.0 // indirect
	golang.org/x/crypto v0.16.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
