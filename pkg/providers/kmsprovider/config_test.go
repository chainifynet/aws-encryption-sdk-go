// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/keyprovider"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/providers/kmsclient"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/keys/kms"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/types"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/providers"
)

func Test_resolveProviderType(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
		want ProviderType
	}{
		{
			name: "Default Provider",
			opts: &Options{},
			want: StrictKmsProvider,
		},
		{
			name: "MRK Aware Provider",
			opts: &Options{
				mrkAware: true,
			},
			want: MrkAwareStrictKmsProvider,
		},
		{
			name: "Discovery Provider",
			opts: &Options{
				discovery: true,
			},
			want: DiscoveryKmsProvider,
		},
		{
			name: "MRK Aware Discovery Provider",
			opts: &Options{
				mrkAware:  true,
				discovery: true,
			},
			want: MrkAwareDiscoveryKmsProvider,
		},
		{
			name: "MRK Aware Discovery Provider with Discovery Region",
			opts: &Options{
				mrkAware:        true,
				discovery:       true,
				discoveryRegion: "us-west-1",
			},
			want: MrkAwareDiscoveryKmsProvider,
		},
		{
			name: "Discovery Provider with Discovery Region",
			opts: &Options{
				discovery:       true,
				discoveryRegion: "eu-central-1",
			},
			want: MrkAwareDiscoveryKmsProvider,
		},
		{
			name: "Strict Provider with Discovery Region",
			opts: &Options{
				discoveryRegion: "ap-southeast-1",
			},
			want: MrkAwareDiscoveryKmsProvider,
		},
		{
			name: "MRK Aware Provider with Discovery Region",
			opts: &Options{
				mrkAware:        true,
				discoveryRegion: "us-east-1",
			},
			want: MrkAwareDiscoveryKmsProvider,
		},
		{
			name: "Discovery Provider with Empty Discovery Region",
			opts: &Options{
				discovery:       true,
				discoveryRegion: "",
			},
			want: DiscoveryKmsProvider,
		},
		{
			name: "MRK Aware Provider with Empty Discovery Region",
			opts: &Options{
				mrkAware:        true,
				discoveryRegion: "",
			},
			want: MrkAwareStrictKmsProvider,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := resolveProviderType(tc.opts)
			assert.Equal(t, tc.want, result)
		})
	}
}

func Test_validateConfig(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		keyIDs       []string
		options      *Options
		wantErr      bool
		wantErrStr   string
	}{
		// Strict Provider tests
		{
			name:         "Strict Provider Valid",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options: &Options{
				keyFactory:  mocks.NewMockMasterKeyFactory(t),
				keyProvider: mocks.NewMockKeyProvider(t),
			},
			wantErr: false,
		},
		{
			name:         "Strict Provider Invalid Key ARN",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"invalid"},
			options:      &Options{},
			wantErr:      true,
			wantErrStr:   "keyIDs validation",
		},
		{
			name:         "Strict Provider Empty Key IDs",
			providerType: StrictKmsProvider,
			keyIDs:       []string{},
			options:      &Options{},
			wantErr:      true,
			wantErrStr:   "keyIDs must not be empty",
		},
		{
			name:         "Strict Provider With Discovery Enabled",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options:      &Options{discovery: true},
			wantErr:      true,
			wantErrStr:   "discovery must not be enabled",
		},
		{
			name:         "Strict Provider With Discovery Filter",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options:      &Options{discoveryFilter: &discoveryFilter{}},
			wantErr:      true,
			wantErrStr:   "discovery filter must not be set",
		},
		{
			name:         "Strict Provider With Discovery Region",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options:      &Options{discoveryRegion: "some-region"},
			wantErr:      true,
			wantErrStr:   "discovery region must not be set",
		},
		// MRK Aware Strict Provider tests
		{
			name:         "MRK Aware Strict Provider Valid",
			providerType: MrkAwareStrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options: &Options{
				keyFactory:  mocks.NewMockMasterKeyFactory(t),
				keyProvider: mocks.NewMockKeyProvider(t),
			},
			wantErr: false,
		},
		{
			name:         "MRK Aware Strict Provider Duplicate MRKs",
			providerType: MrkAwareStrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-1:123456789012:key/mrk-1234", "arn:aws:kms:us-west-2:123456789012:key/mrk-1234"},
			options:      &Options{},
			wantErr:      true,
			wantErrStr:   "MRK keyIDs validation",
		},
		// Discovery Provider tests
		{
			name:         "Discovery Provider Valid",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{},
			options: &Options{
				keyFactory:  mocks.NewMockMasterKeyFactory(t),
				keyProvider: mocks.NewMockKeyProvider(t),
				discovery:   true,
			},
			wantErr: false,
		},
		{
			name:         "Discovery Provider Non-empty Key IDs",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{"non-empty"},
			options:      &Options{discovery: true},
			wantErr:      true,
			wantErrStr:   "keyIDs must be empty",
		},
		{
			name:         "Discovery Provider Discovery Disabled",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{},
			options:      &Options{discovery: false},
			wantErr:      true,
			wantErrStr:   "discovery must be enabled",
		},
		{
			name:         "Discovery Provider Discovery Enabled With Discovery Region",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{},
			options:      &Options{discovery: true, discoveryRegion: "us-west-2"},
			wantErr:      true,
			wantErrStr:   "discovery region must not be set",
		},
		{
			name:         "Discovery Provider Invalid Discovery Filter",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{},
			options:      &Options{discovery: true, discoveryFilter: &discoveryFilter{accountIDs: []string{}}},
			wantErr:      true,
			wantErrStr:   "discovery filter error",
		},
		{
			name:         "Discovery Provider Invalid Discovery Partition Not Supported",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{},
			options:      &Options{discovery: true, discoveryFilter: &discoveryFilter{accountIDs: []string{"123456789012"}}},
			wantErr:      true,
			wantErrStr:   "discovery filter error",
		},
		{
			name:         "Discovery Provider Valid Discovery Filter",
			providerType: DiscoveryKmsProvider,
			keyIDs:       []string{},
			options: &Options{
				keyFactory:      mocks.NewMockMasterKeyFactory(t),
				keyProvider:     mocks.NewMockKeyProvider(t),
				discovery:       true,
				discoveryFilter: &discoveryFilter{accountIDs: []string{"123456789012"}, partition: "aws"},
			},
			wantErr: false,
		},
		// MRK Aware Discovery Provider tests
		{
			name:         "MRK Aware Discovery Provider Valid",
			providerType: MrkAwareDiscoveryKmsProvider,
			keyIDs:       []string{},
			options: &Options{
				keyFactory:      mocks.NewMockMasterKeyFactory(t),
				keyProvider:     mocks.NewMockKeyProvider(t),
				discovery:       true,
				discoveryRegion: "us-west-2",
			},
			wantErr: false,
		},
		{
			name:         "MRK Aware Discovery Provider With Default Region",
			providerType: MrkAwareDiscoveryKmsProvider,
			keyIDs:       []string{},
			options: &Options{
				keyFactory:    mocks.NewMockMasterKeyFactory(t),
				keyProvider:   mocks.NewMockKeyProvider(t),
				discovery:     true,
				defaultRegion: "us-west-2",
			},
			wantErr: false,
		},
		{
			name:         "MRK Aware Discovery Provider Without Discovery Region",
			providerType: MrkAwareDiscoveryKmsProvider,
			keyIDs:       []string{},
			options:      &Options{discovery: true},
			wantErr:      true,
			wantErrStr:   "discovery region must be set",
		},
		{
			name:         "MRK Aware Discovery Provider Non-empty Key IDs",
			providerType: MrkAwareDiscoveryKmsProvider,
			keyIDs:       []string{"non-empty"},
			options:      &Options{discovery: true, discoveryRegion: "us-west-2"},
			wantErr:      true,
			wantErrStr:   "keyIDs must be empty",
		},
		// Additional test cases
		{
			name:         "Invalid Provider Type",
			providerType: ProviderType(999),
			keyIDs:       []string{},
			options:      &Options{},
			wantErr:      true,
			wantErrStr:   "unknown KMS provider type",
		},
		{
			name:         "Invalid keyFactory",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options: &Options{
				keyProvider: mocks.NewMockKeyProvider(t),
			},
			wantErr:    true,
			wantErrStr: "keyFactory must not be nil",
		},
		{
			name:         "Invalid keyProvider",
			providerType: StrictKmsProvider,
			keyIDs:       []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			options: &Options{
				keyFactory: mocks.NewMockMasterKeyFactory(t),
			},
			wantErr:    true,
			wantErrStr: "keyProvider must not be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.providerType, tt.keyIDs, tt.options)
			if tt.wantErr {
				assert.Error(t, err, "Test case: %s", tt.name)
				assert.ErrorIs(t, err, providers.ErrConfig)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err, "Test case: %s", tt.name)
			}
		})
	}
}

func Test_validateAccountID(t *testing.T) {
	tests := []struct {
		name       string
		accountID  string
		wantErr    bool
		wantErrStr string
	}{
		{
			name:      "Valid Account ID",
			accountID: "123456789012",
			wantErr:   false,
		},
		{
			name:       "Empty Account ID",
			accountID:  "",
			wantErr:    true,
			wantErrStr: "accountID must not be empty",
		},
		{
			name:       "Account ID Length short",
			accountID:  "123",
			wantErr:    true,
			wantErrStr: "accountID must be 12 digits long",
		},
		{
			name:       "Account ID Length long",
			accountID:  "12345678901234567890",
			wantErr:    true,
			wantErrStr: "accountID must be 12 digits long",
		},
		{
			name:       "Account ID with Non-Digit Characters",
			accountID:  "12345abc9012",
			wantErr:    true,
			wantErrStr: "accountID must contain only digits",
		},
		{
			name:       "Account ID with Special Characters",
			accountID:  "1234567-9012",
			wantErr:    true,
			wantErrStr: "accountID must contain only digits",
		},
		{
			name:       "Account ID with Spaces",
			accountID:  "123 45679012",
			wantErr:    true,
			wantErrStr: "accountID must contain only digits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAccountID(tt.accountID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
				assert.ErrorContains(t, err, tt.accountID)
			} else {
				assert.NoErrorf(t, err, "Test case: %s", tt.name)
			}
		})
	}
}

func Test_validateDiscoveryFilter(t *testing.T) {
	tests := []struct {
		name       string
		df         *discoveryFilter
		wantErr    bool
		wantErrStr string
	}{
		{
			name: "Valid Discovery Filter",
			df: &discoveryFilter{
				accountIDs: []string{"123456789012"},
				partition:  _awsPartition,
			},
			wantErr: false,
		},
		{
			name: "Empty Account IDs",
			df: &discoveryFilter{
				accountIDs: []string{},
				partition:  _awsPartition,
			},
			wantErr:    true,
			wantErrStr: "accountIDs must not be empty",
		},
		{
			name: "Unsupported Partition",
			df: &discoveryFilter{
				accountIDs: []string{"123456789012"},
				partition:  "unsupported",
			},
			wantErr:    true,
			wantErrStr: "partition is not supported",
		},
		{
			name: "Invalid Account ID Format",
			df: &discoveryFilter{
				accountIDs: []string{"invalidID"},
				partition:  _awsPartition,
			},
			wantErr:    true,
			wantErrStr: "validate accountID:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiscoveryFilter(tt.df)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr)
			} else {
				assert.NoError(t, err, "Test case: %s", tt.name)
			}
		})
	}
}

func Test_validateKeyArns(t *testing.T) {
	tests := []struct {
		name       string
		keyIDs     []string
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "Valid ARN",
			keyIDs:  []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			wantErr: false,
		},
		{
			name:       "Invalid ARN Format",
			keyIDs:     []string{"invalid-arn"},
			wantErr:    true,
			wantErrStr: "keyID is not a valid ARN",
		},
		{
			name:       "Empty ARN",
			keyIDs:     []string{""},
			wantErr:    true,
			wantErrStr: "keyID is not a valid ARN",
		},
		{
			name:       "Multiple ARNs with One Invalid",
			keyIDs:     []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef", "invalid-arn"},
			wantErr:    true,
			wantErrStr: "keyID is not a valid ARN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyArns(tt.keyIDs)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr, "Test case: %s", tt.name)
			} else {
				assert.NoError(t, err, "Test case: %s", tt.name)
			}
		})
	}
}

func Test_validateUniqueMrks(t *testing.T) {
	tests := []struct {
		name       string
		keyIDs     []string
		wantErr    bool
		wantErrStr string
	}{
		{
			name:    "Unique MRKs",
			keyIDs:  []string{"arn:aws:kms:us-west-1:123456789012:key/mrk-1234", "arn:aws:kms:us-west-1:123456789012:key/mrk-5678"},
			wantErr: false,
		},
		{
			name:       "Duplicate MRKs different region",
			keyIDs:     []string{"arn:aws:kms:us-west-1:123456789012:key/mrk-1234", "arn:aws:kms:eu-west-1:123456789012:key/mrk-1234"},
			wantErr:    true,
			wantErrStr: "configured MRK key ids must be unique",
		},
		{
			name:       "Duplicate MRKs same region",
			keyIDs:     []string{"arn:aws:kms:us-west-1:123456789012:key/mrk-1234", "arn:aws:kms:us-west-1:123456789012:key/mrk-1234"},
			wantErr:    true,
			wantErrStr: "configured MRK key ids must be unique",
		},
		{
			name: "Duplicate four different MRKs",
			keyIDs: []string{
				"arn:aws:kms:us-west-1:123456789012:key/mrk-1234",
				"arn:aws:kms:eu-west-1:123456789012:key/mrk-1234",
				"arn:aws:kms:us-west-1:123456789012:key/mrk-5678",
				"arn:aws:kms:eu-west-1:123456789012:key/mrk-5678",
			},
			wantErr:    true,
			wantErrStr: "configured MRK key ids must be unique",
		},
		{
			name: "Duplicate MRKs Mixed with Invalid MRK",
			keyIDs: []string{
				"arn:aws:kms:us-west-1:123456789012:key/mrk-1234",
				"arn:aws:kms:eu-west-1:123456789012:key/mrk-1234",
				"arn:aws:kms:us-west-1:123456789012:key/mrk-5678",
				"arn:aws:kms:eu-west-1:123456789012:key/mrk-5678",
				"alias/mrk-5678",
				"arn:aws:kms:eu-west-1:123456789012:key/mrk-5678",
				"mrk-5678",
			},
			wantErr:    true,
			wantErrStr: "configured MRK key ids must be unique",
		},
		{
			name:       "Mixed Valid and Invalid ARNs",
			keyIDs:     []string{"arn:aws:kms:us-west-1:123456789012:key/mrk-1234", "arn:aws:kms:us-west-1:123456789012:invalid/mrk-1234"},
			wantErr:    true,
			wantErrStr: "malformed Key ARN",
		},
		{
			name:    "Invalid MRK Format",
			keyIDs:  []string{"invalid-mrk-id"},
			wantErr: false, // non-MRK IDs are filtered out and not considered errors
		},
		{
			name:    "No MRKs",
			keyIDs:  []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			wantErr: false,
		},
		{
			name:    "No MRKs Duplicated ARN",
			keyIDs:  []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef", "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUniqueMrks(tt.keyIDs)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrStr, "Test case: %s", tt.name)
			} else {
				assert.NoError(t, err, "Test case: %s", tt.name)
			}
		})
	}
}

func Test_resolveVendOnDecrypt(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		want         bool
	}{
		{"Strict Provider", StrictKmsProvider, false},
		{"MRK Aware Strict Provider", MrkAwareStrictKmsProvider, false},
		{"Discovery Provider", DiscoveryKmsProvider, true},
		{"MRK Aware Discovery Provider", MrkAwareDiscoveryKmsProvider, true},
		{"Invalid ProviderType", ProviderType(999), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, resolveVendOnDecrypt(tt.providerType), "resolveVendOnDecrypt(%v)", tt.providerType)
		})
	}
}

func Test_resolveDefaultRegion(t *testing.T) {
	mockAwsConfigLoader := func(options *config.LoadOptions) error {
		options.Region = "eu-central-1"
		return nil
	}

	tests := []struct {
		name           string
		keyIDs         []string
		opts           *Options
		expectedRegion string
	}{
		{
			name:           "Pre-set Default Region",
			keyIDs:         []string{},
			opts:           &Options{defaultRegion: "us-east-1"},
			expectedRegion: "us-east-1",
		},
		{
			name:           "Valid ARN Region Extraction",
			keyIDs:         []string{"arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"},
			opts:           &Options{},
			expectedRegion: "us-west-2",
		},
		{
			name:           "Invalid ARN, Fallback to Config Loader",
			keyIDs:         []string{"invalid-arn"},
			opts:           &Options{awsConfigLoaders: []func(options *config.LoadOptions) error{mockAwsConfigLoader}},
			expectedRegion: "eu-central-1",
		},
		{
			name:           "No ARNs, Fallback to Config Loader",
			keyIDs:         []string{},
			opts:           &Options{awsConfigLoaders: []func(options *config.LoadOptions) error{mockAwsConfigLoader}},
			expectedRegion: "eu-central-1",
		},
		{
			name:           "Invalid ARN, No Config Loader Region",
			keyIDs:         []string{"invalid-arn"},
			opts:           &Options{},
			expectedRegion: "",
		},
		{
			name:           "No ARNs, No Config Loader Region",
			keyIDs:         nil,
			opts:           &Options{},
			expectedRegion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveDefaultRegion(tt.keyIDs, tt.opts)
			assert.Equal(t, tt.expectedRegion, tt.opts.defaultRegion)
		})
	}
}

func Test_resolveKeyProvider(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		opts         *Options
		want         model.BaseKeyProvider
	}{
		{
			name:         "StrictKmsProvider with keyProvider not set",
			providerType: StrictKmsProvider,
			opts:         &Options{},
			want:         keyprovider.NewKeyProvider(types.KmsProviderID, types.AwsKms, false),
		},
		{
			name:         "MrkAwareStrictKmsProvider with keyProvider not set",
			providerType: MrkAwareStrictKmsProvider,
			opts:         &Options{},
			want:         keyprovider.NewKeyProvider(types.KmsProviderID, types.AwsKms, false),
		},
		{
			name:         "DiscoveryKmsProvider with keyProvider not set",
			providerType: DiscoveryKmsProvider,
			opts:         &Options{},
			want:         keyprovider.NewKeyProvider(types.KmsProviderID, types.AwsKms, true),
		},
		{
			name:         "MrkAwareDiscoveryKmsProvider with keyProvider not set",
			providerType: MrkAwareDiscoveryKmsProvider,
			opts:         &Options{},
			want:         keyprovider.NewKeyProvider(types.KmsProviderID, types.AwsKms, true),
		},
		{
			name:         "keyProvider already set",
			providerType: StrictKmsProvider,
			opts: &Options{
				keyProvider: keyprovider.NewKeyProvider("existing", types.AwsKms, true),
			},
			want: keyprovider.NewKeyProvider("existing", types.AwsKms, true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveKeyProvider(tt.providerType, tt.opts)
			got := tt.opts.keyProvider
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_resolveKeyFactory(t *testing.T) {
	defaultKeyFactory := &kms.KeyFactory{}
	mrkKeyFactory := &kms.MrkKeyFactory{}

	masterKeyFactoryMock := mocks.NewMockMasterKeyFactory(t)

	tests := []struct {
		name         string
		providerType ProviderType
		opts         *Options
		want         model.MasterKeyFactory
	}{
		{
			name:         "StrictKmsProvider with keyFactory not set",
			providerType: StrictKmsProvider,
			opts:         &Options{},
			want:         defaultKeyFactory,
		},
		{
			name:         "DiscoveryKmsProvider with keyFactory not set",
			providerType: DiscoveryKmsProvider,
			opts:         &Options{},
			want:         defaultKeyFactory,
		},
		{
			name:         "MrkAwareStrictKmsProvider with keyFactory not set",
			providerType: MrkAwareStrictKmsProvider,
			opts:         &Options{},
			want:         mrkKeyFactory,
		},
		{
			name:         "MrkAwareDiscoveryKmsProvider with keyFactory not set",
			providerType: MrkAwareDiscoveryKmsProvider,
			opts:         &Options{},
			want:         mrkKeyFactory,
		},
		{
			name:         "keyFactory already set",
			providerType: StrictKmsProvider,
			opts: &Options{
				keyFactory: masterKeyFactoryMock,
			},
			want: masterKeyFactoryMock,
		},
		{
			name:         "Unknown ProviderType",
			providerType: ProviderType(999),
			opts:         &Options{},
			want:         defaultKeyFactory,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveKeyFactory(tt.providerType, tt.opts)
			got := tt.opts.keyFactory
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_resolveClientFactory(t *testing.T) {
	clientFactoryMock := mocks.NewMockKMSClientFactory(t)
	tests := []struct {
		name string
		opts *Options
		want model.KMSClientFactory
	}{
		{
			name: "clientFactory not set",
			opts: &Options{},
			want: kmsclient.NewFactory(),
		},
		{
			name: "clientFactory already set",
			opts: &Options{
				clientFactory: kmsclient.NewFactory(),
			},
			want: kmsclient.NewFactory(),
		},
		{
			name: "mock clientFactory",
			opts: &Options{
				clientFactory: clientFactoryMock,
			},
			want: clientFactoryMock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveClientFactory(tt.opts)
			got := tt.opts.clientFactory
			assert.Equal(t, tt.want, got)
		})
	}
}
