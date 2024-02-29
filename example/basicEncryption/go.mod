module github.com/chainifynet/aws-encryption-sdk-go/example/basicEncryption

go 1.20

require github.com/chainifynet/aws-encryption-sdk-go v0.2.1

require (
	github.com/aws/aws-sdk-go-v2 v1.25.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.28.0 // indirect
	github.com/aws/smithy-go v1.20.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rs/zerolog v1.32.0 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

replace github.com/chainifynet/aws-encryption-sdk-go => ../..
