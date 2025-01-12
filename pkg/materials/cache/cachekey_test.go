// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials/cache"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

type mockKeyHasher struct{}

func (m *mockKeyHasher) Update(_ []byte) {
}

func (m *mockKeyHasher) Compute() string {
	return "dummyHash"
}

func TestComputeDecCacheKey(t *testing.T) {
	tests := []struct {
		name      string
		partition []byte
		request   model.DecryptionMaterialsRequest
		hashFn    model.KeyHasherFunc
		want      string
	}{
		{
			name:      "NilAlgorithmNoEDK",
			partition: []byte("partition1"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         nil,
				EncryptedDataKeys: nil,
				EncryptionContext: suite.EncryptionContext{},
			},
			want: "bcdd977d01a6eb03728a5843f8e49aca1748bc521373883ed569e755dadc95a94f5807497b211e00de268b56c9361fda6a577a8bb120db462ef80d7709731f03",
		},
		{
			name:      "With HasherFunc",
			partition: []byte("partition1"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         nil,
				EncryptedDataKeys: nil,
				EncryptionContext: suite.EncryptionContext{},
			},
			hashFn: cache.NewKeyHasher,
			want:   "bcdd977d01a6eb03728a5843f8e49aca1748bc521373883ed569e755dadc95a94f5807497b211e00de268b56c9361fda6a577a8bb120db462ef80d7709731f03",
		},
		{
			name:      "Mocked KeyHasher",
			partition: []byte("partition2"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_IV12_TAG16,
				EncryptedDataKeys: nil,
				EncryptionContext: suite.EncryptionContext{"key1": "value1"},
			},
			hashFn: func() model.CacheHasher { return &mockKeyHasher{} },
			want:   "dummyHash",
		},
		{
			name:      "WithAlgorithmNoEDK",
			partition: []byte("partition2"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_IV12_TAG16,
				EncryptedDataKeys: nil,
				EncryptionContext: suite.EncryptionContext{"key1": "value1"},
			},
			want: "28984fc1cceeeecab834079420f4cf84d755695a50ca86bd385a5a686355b1c4953c0ebc9429adcfe06260903b45772c0ea6f3b0cee413b26a8621a426a8f471",
		},
		{
			name:      "WithEDKEmptyArray",
			partition: []byte("partition3"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
				EncryptedDataKeys: []model.EncryptedDataKeyI{},
				EncryptionContext: suite.EncryptionContext{"key2": "value2"},
			},
			want: "fe8f68ad3c6acd6a09ceb99ee449263e19085f9d95c795db90ba8782abe60abbb2f395040280f461c7936d86d605d3a527cbc8044902e771586e3a107ef07900",
		},
		{
			name:      "WithNonNilEDKSingle",
			partition: []byte("partition4"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_IV12_TAG16,
				EncryptedDataKeys: []model.EncryptedDataKeyI{model.NewEncryptedDataKey(model.WithKeyMeta("provider1", "key1"), []byte("dataKey1"))},
				EncryptionContext: suite.EncryptionContext{"key3": "value3"},
			},
			want: "63245d578cd26d1c5c1e5fb097da9ffc4196420d74a754d677c78845afcfa74c602fbececaf32c335653b2e7f9070f16ac449c658a7b2d0cdfaa4cc763656d6b",
		},
		{
			name:      "WithNonNilEDKMultiple",
			partition: []byte("partition5"),
			request: model.DecryptionMaterialsRequest{
				Algorithm: suite.AES_192_GCM_IV12_TAG16,
				EncryptedDataKeys: []model.EncryptedDataKeyI{
					model.NewEncryptedDataKey(model.WithKeyMeta("provider2", "key2"), []byte("dataKey2")),
					model.NewEncryptedDataKey(model.WithKeyMeta("provider3", "key3"), []byte("dataKey3")),
				},
				EncryptionContext: suite.EncryptionContext{"key4": "value4"},
			},
			want: "85074a0cca5afc4f3d178c0399fa65c0956c4c2c986bafdd982db4692b1b862a3783078629d7fd4e50cd46dd1ea042b9abed378c8afc2cf578f4edc55aedc080",
		},
		{
			name:      "NilEDKProviderID",
			partition: []byte("partition6"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_192_GCM_IV12_TAG16_HKDF_SHA256,
				EncryptedDataKeys: []model.EncryptedDataKeyI{model.NewEncryptedDataKey(model.WithKeyMeta("", "key4"), []byte("dataKey4"))},
				EncryptionContext: suite.EncryptionContext{"key5": "value5"},
			},
			want: "56296933eaba2ca86d527c4ea8ef6f4372cfd71f85300949c2bbcee9705a538fdbf617ca3cf8e87c15f82a7fc418bbc58f94be78d8c4a601e5bb50220ad11ae1",
		},
		{
			name:      "NilEDKEncryptedDataKey",
			partition: []byte("partition7"),
			request: model.DecryptionMaterialsRequest{
				Algorithm:         suite.AES_128_GCM_IV12_TAG16,
				EncryptedDataKeys: []model.EncryptedDataKeyI{model.NewEncryptedDataKey(model.WithKeyMeta("provider4", "key5"), nil)},
				EncryptionContext: suite.EncryptionContext{"key6": "value6"},
			},
			want: "f20d6e2d001d0612af838b33cb09f9cf7bf495de978457d5bd5773263f9379750e6f23b94c006f48d59809668fada950b481eb9875696f39c754595ec789ccb1",
		},
		{
			name:      "MultipleEDKsMixed",
			partition: []byte("partition8"),
			request: model.DecryptionMaterialsRequest{
				Algorithm: suite.AES_128_GCM_IV12_TAG16,
				EncryptedDataKeys: []model.EncryptedDataKeyI{
					model.NewEncryptedDataKey(model.WithKeyMeta("provider5", "key6"), []byte("dataKey5")),
					nil,
					model.NewEncryptedDataKey(model.WithKeyMeta("provider6", "key7"), []byte("dataKey6")),
				},
				EncryptionContext: suite.EncryptionContext{"key7": "value7"},
			},
			want: "f7f9574b9df93032e06b3f39afde3752c58777bd8d18df006ff66083b2e0a9aa5c4eb1005c046b2de020832d47176a08fe56ee4d291bae44deba5adfec48dde2",
		},
		{
			name:      "EmptyEncryptionContext",
			partition: []byte("partition9"),
			request: model.DecryptionMaterialsRequest{
				Algorithm: suite.AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
				EncryptedDataKeys: []model.EncryptedDataKeyI{
					model.NewEncryptedDataKey(model.WithKeyMeta("provider7", "key8"), []byte("dataKey7")),
				},
				EncryptionContext: nil,
			},
			want: "015a26a3d599b9949ffdfeea131756af7c25190ba6034a6420bdc799e49882b759d93f6ac55106c85390622489d52999f513410b100d1b10e376fe5d7a997a8c",
		},
		{
			name:      "ComplexEncryptionContext",
			partition: []byte("partition10"),
			request: model.DecryptionMaterialsRequest{
				Algorithm: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
				EncryptedDataKeys: []model.EncryptedDataKeyI{
					model.NewEncryptedDataKey(model.WithKeyMeta("provider8", "key9"), []byte("dataKey8")),
				},
				EncryptionContext: suite.EncryptionContext{
					"key9":  "value9",
					"key10": "value10",
					"key11": "value11",
				},
			},
			want: "767ca181064361ca9c3db4952ad32d45f43a2a39eb9ed33c5d78d38946768cc2da58303abd398c57995898af97db8a853d0ee564cf6011d22c4c78a789e7cd86",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.ComputeDecCacheKey(tt.partition, tt.request, tt.hashFn)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComputeEncCacheKey(t *testing.T) {
	tests := []struct {
		name      string
		partition []byte
		request   model.EncryptionMaterialsRequest
		hashFn    model.KeyHasherFunc
		want      string
	}{
		{
			name:      "NilAlgorithm",
			partition: []byte("partition1"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         nil,
				EncryptionContext: suite.EncryptionContext{},
			},
			want: "bcc4efab8b9629ef3c5b1face5d89cff34e6a06d4867ed42f8eebe35a6bc380ef0aabd1af100e45dc8cd29d78facee63856605d0cd9a106447bebd6b940dbdc5",
		},
		{
			name:      "With HasherFunc",
			partition: []byte("partition1"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         nil,
				EncryptionContext: suite.EncryptionContext{},
			},
			hashFn: cache.NewKeyHasher,
			want:   "bcc4efab8b9629ef3c5b1face5d89cff34e6a06d4867ed42f8eebe35a6bc380ef0aabd1af100e45dc8cd29d78facee63856605d0cd9a106447bebd6b940dbdc5",
		},
		{
			name:      "Mocked KeyHasher",
			partition: []byte("partition1"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         nil,
				EncryptionContext: suite.EncryptionContext{},
			},
			hashFn: func() model.CacheHasher { return &mockKeyHasher{} },
			want:   "dummyHash",
		},
		{
			name:      "SimpleContext",
			partition: []byte("partition2"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_IV12_TAG16,
				EncryptionContext: suite.EncryptionContext{"key1": "value1"},
			},
			want: "1590bc7b6583153be91fc101872ceaf0407cab005e8032d0356debfff540e1d27e435737df8bab4a30ca5c1fa367cf4c3aac9f291670718fa6313adf43aad925",
		},
		{
			name:      "ComplexContext",
			partition: []byte("partition3"),
			request: model.EncryptionMaterialsRequest{
				Algorithm: suite.AES_192_GCM_IV12_TAG16,
				EncryptionContext: suite.EncryptionContext{
					"first":  "valueFirst",
					"second": "valueSecond",
					"third":  "valueThird",
				},
			},
			want: "87899c435fd3783a4d73e8a6c9c26f35700a5a1b87cc1cb66d3e64a5499aa627182887cdf3ffb72224f369c06dff324165034526ecbd73512d3b1bffb61f3cb0",
		},
		{
			name:      "EmptyContext",
			partition: []byte("partition4"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_128_GCM_IV12_TAG16,
				EncryptionContext: suite.EncryptionContext{},
			},
			want: "baa8592fedd56f8aaba0c6bcd5df07bb538131e696df1aa4deb12d52b798d63a2fc739f1f9d898d696c5d935305243987edeffb82c062b87fc85e670248eddc9",
		},
		{
			name:      "NoPartition",
			partition: nil,
			request: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
				EncryptionContext: suite.EncryptionContext{"key2": "value2"},
			},
			want: "0e7b1cf3dac5a21b82d9ae5ff7ee858c8b8eb690e7e5ca6c2ab366c030a78630ed61c7ab9577d3ab6e8904fff17a95d49b253a51d71bf9e9f480ad44b2be23d2",
		},
		{
			name:      "NilAlgorithmWithContext",
			partition: []byte("partition5"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         nil,
				EncryptionContext: suite.EncryptionContext{"key3": "value3"},
			},
			want: "5148bdadff983c879f3143c0029ba684384eec91a5b5f79a10d5d23c4e2ecbf2d28e1cbe348c2c0fb6649f197e3ae414cd6f7450ee7c10b3105a5a11ae4ab963",
		},
		{
			name:      "FullContext",
			partition: []byte("partition6"),
			request: model.EncryptionMaterialsRequest{
				Algorithm: suite.AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
				EncryptionContext: suite.EncryptionContext{
					"full":    "context",
					"with":    "multiple",
					"entries": "entires",
				},
			},
			want: "16e008bde75bfead94a596fba8624b6a19d944065ae6c9e9fe147d171590520a8344c6355f0e8ae54a52c814fb145a3c2ef47938fd062cebf03fdbdc86b3f981",
		},
		{
			name:      "NilContext",
			partition: []byte("partition7"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_128_GCM_IV12_TAG16,
				EncryptionContext: nil,
			},
			want: "dd5945217d8c1a538278ae23554d93281ed4f265ea9bf1694bcc921b2d3a1e6d610423ee80e924d64872de63945c24332284c0a9b575fffb00a68c96ee4fb06f",
		},
		{
			name:      "SingleEntryContext",
			partition: []byte("partition8"),
			request: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_192_GCM_IV12_TAG16,
				EncryptionContext: suite.EncryptionContext{"only": "one"},
			},
			want: "95de623d8acdbdf685b9722ace1003655b9e0dea91d6c1ce8634fb03f8b292d0a98b5610c55c3aba19e080840f06d890870f1ce850949d1761d4aee1aa9fe922",
		},
		{
			name:      "NoPartitionNilContext",
			partition: nil,
			request: model.EncryptionMaterialsRequest{
				Algorithm:         suite.AES_128_GCM_IV12_TAG16_HKDF_SHA256,
				EncryptionContext: nil,
			},
			want: "1e49a67b5dbca0b323630405170906e142d2a11eeddb90fd8c9f46219d5a71f4e5beb657c1ece417063b761b6d8ea3ee1211a4ac649463816197405cf635ad66",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cache.ComputeEncCacheKey(tt.partition, tt.request, tt.hashFn)
			assert.Equal(t, tt.want, got)
		})
	}
}
