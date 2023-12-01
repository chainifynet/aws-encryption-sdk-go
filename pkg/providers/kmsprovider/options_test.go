// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kmsprovider

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"

	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
)

func TestWithAwsLoadOptions(t *testing.T) {
	tests := []struct {
		name   string
		optFns []func(*config.LoadOptions) error
	}{
		{
			name:   "No options",
			optFns: nil,
		},
		{
			name: "Single option",
			optFns: []func(*config.LoadOptions) error{
				func(o *config.LoadOptions) error { return nil },
			},
		},
		{
			name: "Multiple options",
			optFns: []func(*config.LoadOptions) error{
				func(o *config.LoadOptions) error { return nil },
				func(o *config.LoadOptions) error { return nil },
			},
		},
		{
			name: "Option with custom logic",
			optFns: []func(*config.LoadOptions) error{
				func(o *config.LoadOptions) error { o.Region = "us-west-1"; return nil },
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			options := &Options{}
			err := WithAwsLoadOptions(tc.optFns...)(options)
			assert.NoError(t, err)
			assert.Len(t, tc.optFns, len(options.awsConfigLoaders))

			for i, fn := range options.awsConfigLoaders {
				mockLoadOptions := &config.LoadOptions{}

				errTestFn := tc.optFns[i](mockLoadOptions)
				errOptionFn := fn(mockLoadOptions)

				// assert that both functions return the same result
				assert.Equal(t, errTestFn, errOptionFn)
			}
		})
	}
}

func TestWithDiscovery(t *testing.T) {
	tests := []struct {
		name    string
		initial bool
		want    bool
	}{
		{
			name:    "Initial false want true",
			initial: false,
			want:    true,
		},
		{
			name:    "Initial true want true",
			initial: true,
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			options := &Options{
				discovery: tc.initial,
			}

			err := WithDiscovery()(options)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, options.discovery)
		})
	}
}

func TestWithDiscoveryFilter(t *testing.T) {
	tests := []struct {
		name       string
		accountIDs []string
		partition  string
		wantErr    bool
		want       *Options
	}{
		{
			name:       "Empty accountIDs And partition",
			accountIDs: []string{},
			partition:  "",
			wantErr:    false,
			want: &Options{
				discovery:       true,
				discoveryFilter: &discoveryFilter{accountIDs: []string{}, partition: ""},
			},
		},
		{
			name:       "Single accountID",
			accountIDs: []string{"123456789012"},
			partition:  "aws",
			wantErr:    false,
			want: &Options{
				discovery:       true,
				discoveryFilter: &discoveryFilter{accountIDs: []string{"123456789012"}, partition: "aws"},
			},
		},
		{
			name:       "Multiple accountIDs",
			accountIDs: []string{"123456789012", "210987654321"},
			partition:  "aws",
			wantErr:    false,
			want: &Options{
				discovery:       true,
				discoveryFilter: &discoveryFilter{accountIDs: []string{"123456789012", "210987654321"}, partition: "aws"},
			},
		},
		{
			name:       "nil accountIDs",
			accountIDs: nil,
			partition:  "aws",
			wantErr:    false,
			want: &Options{
				discovery:       true,
				discoveryFilter: &discoveryFilter{accountIDs: nil, partition: "aws"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{}
			err := WithDiscoveryFilter(tt.accountIDs, tt.partition)(options)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, options)
			}
		})
	}
}

func TestWithMrkAwareness(t *testing.T) {
	tests := []struct {
		name            string
		initialMrkAware bool
		wantOptions     *Options
	}{
		{
			name:            "Initially False",
			initialMrkAware: false,
			wantOptions:     &Options{mrkAware: true},
		},
		{
			name:            "Initially True",
			initialMrkAware: true,
			wantOptions:     &Options{mrkAware: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{mrkAware: tt.initialMrkAware}
			err := WithMrkAwareness()(options)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantOptions, options)
		})
	}
}

func TestWithDiscoveryRegion(t *testing.T) {
	tests := []struct {
		name        string
		region      string
		wantOptions *Options
	}{
		{
			name:        "Empty Region",
			region:      "",
			wantOptions: &Options{discoveryRegion: ""},
		},
		{
			name:        "Region us-west-1",
			region:      "us-west-1",
			wantOptions: &Options{discoveryRegion: "us-west-1"},
		},
		{
			name:        "Region eu-central-1",
			region:      "eu-central-1",
			wantOptions: &Options{discoveryRegion: "eu-central-1"},
		},
		{
			name:        "Region ap-southeast-1",
			region:      "ap-southeast-1",
			wantOptions: &Options{discoveryRegion: "ap-southeast-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{}
			err := WithDiscoveryRegion(tt.region)(options)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantOptions, options)
		})
	}
}

func Test_discoveryFilter_IsAllowed(t *testing.T) {
	tests := []struct {
		name   string
		filter *discoveryFilter
		keyID  string
		want   bool
	}{
		{
			name:   "Allowed Key in Account",
			filter: &discoveryFilter{accountIDs: []string{"123456789012"}, partition: "aws"},
			keyID:  "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			want:   true,
		},
		{
			name:   "Disallowed Key wrong Account",
			filter: &discoveryFilter{accountIDs: []string{"123456789012"}, partition: "aws"},
			keyID:  "arn:aws:kms:us-west-2:210987654321:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			want:   false,
		},
		{
			name:   "Disallowed Key invalid partition",
			filter: &discoveryFilter{accountIDs: []string{"123456789012"}, partition: "aws"},
			keyID:  "arn:aws-cn:kms:cn-north-1:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef",
			want:   false,
		},
		{
			name:   "Invalid KeyID Format",
			filter: &discoveryFilter{accountIDs: []string{"123456789012"}, partition: "aws"},
			keyID:  "invalid-arn",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.IsAllowed(tt.keyID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithKeyFactory(t *testing.T) {
	tests := []struct {
		name       string
		keyFactory model.MasterKeyFactory
	}{
		{
			name:       "With KeyFactory",
			keyFactory: mocks.NewMockMasterKeyFactory(t),
		},
		{
			name:       "With Nil KeyFactory",
			keyFactory: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			err := WithKeyFactory(tt.keyFactory)(opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.keyFactory, opts.keyFactory)
		})
	}
}

func TestWithKeyProvider(t *testing.T) {
	tests := []struct {
		name        string
		keyProvider model.BaseKeyProvider
	}{
		{
			name:        "With KeyProvider",
			keyProvider: mocks.NewMockKeyProvider(t),
		},
		{
			name:        "With Nil KeyProvider",
			keyProvider: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			err := WithKeyProvider(tt.keyProvider)(opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.keyProvider, opts.keyProvider)
		})
	}
}

func TestWithClientFactory(t *testing.T) {
	tests := []struct {
		name    string
		factory model.KMSClientFactory
	}{
		{
			name:    "With ClientFactory",
			factory: mocks.NewMockKMSClientFactory(t),
		},
		{
			name:    "With Nil ClientFactory",
			factory: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{}
			err := WithClientFactory(tt.factory)(opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.factory, opts.clientFactory)
		})
	}
}
