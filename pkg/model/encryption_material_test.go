// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNewEncryptionMaterials(t *testing.T) {
	dataEncryptionKey := &DataKey{}
	encryptedDataKeys := []EncryptedDataKeyI{&EncryptedDataKey{}}
	type args struct {
		dataEncryptionKey DataKeyI
		encryptedDataKeys []EncryptedDataKeyI
		ec                suite.EncryptionContext
		signingKey        *ecdsa.PrivateKey
	}
	tests := []struct {
		name string
		args args
		want *EncryptionMaterials
	}{
		{
			name: "NewEncryptionMaterials with valid data",
			args: args{
				dataEncryptionKey: dataEncryptionKey,
				encryptedDataKeys: encryptedDataKeys,
				ec:                suite.EncryptionContext{"purpose": "test"},
				signingKey:        &ecdsa.PrivateKey{},
			},
			want: &EncryptionMaterials{
				dataEncryptionKey: dataEncryptionKey,
				encryptedDataKeys: encryptedDataKeys,
				encryptionContext: suite.EncryptionContext{"purpose": "test"},
				signingKey:        &ecdsa.PrivateKey{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewEncryptionMaterials(tt.args.dataEncryptionKey, tt.args.encryptedDataKeys, tt.args.ec, tt.args.signingKey))
		})
	}
}

func TestEncryptionMaterials_Getters(t *testing.T) {
	dataEncryptionKey := &DataKey{}
	encryptedDataKeys := []EncryptedDataKeyI{&EncryptedDataKey{}}
	type fields struct {
		dataEncryptionKey DataKeyI
		encryptedDataKeys []EncryptedDataKeyI
		encryptionContext suite.EncryptionContext
		signingKey        *ecdsa.PrivateKey
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Getters with valid data",
			fields: fields{
				dataEncryptionKey: dataEncryptionKey,
				encryptedDataKeys: encryptedDataKeys,
				encryptionContext: suite.EncryptionContext{"purpose": "test"},
				signingKey:        &ecdsa.PrivateKey{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := EncryptionMaterials{
				dataEncryptionKey: tt.fields.dataEncryptionKey,
				encryptedDataKeys: tt.fields.encryptedDataKeys,
				encryptionContext: tt.fields.encryptionContext,
				signingKey:        tt.fields.signingKey,
			}
			assert.Equal(t, tt.fields.dataEncryptionKey, e.DataEncryptionKey())
			assert.Equal(t, tt.fields.encryptedDataKeys, e.EncryptedDataKeys())
			assert.Equal(t, tt.fields.encryptionContext, e.EncryptionContext())
			assert.Equal(t, tt.fields.signingKey, e.SigningKey())
		})
	}
}

func TestNewDecryptionMaterials(t *testing.T) {
	dataKey := &DataKey{}
	verificationKey := []byte("test")
	type args struct {
		dataKey         DataKeyI
		verificationKey []byte
	}
	tests := []struct {
		name string
		args args
		want *DecryptionMaterials
	}{
		{
			name: "NewDecryptionMaterials with valid data",
			args: args{
				dataKey:         dataKey,
				verificationKey: verificationKey,
			},
			want: &DecryptionMaterials{
				dataKey:         dataKey,
				verificationKey: verificationKey,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewDecryptionMaterials(tt.args.dataKey, tt.args.verificationKey), "NewDecryptionMaterials(%v, %v)", tt.args.dataKey, tt.args.verificationKey)
		})
	}
}

func TestDecryptionMaterials_Getters(t *testing.T) {
	dataKey := &DataKey{}
	verificationKey := []byte("test")
	type fields struct {
		dataKey         DataKeyI
		verificationKey []byte
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Getters with valid data",
			fields: fields{
				dataKey:         dataKey,
				verificationKey: verificationKey,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DecryptionMaterials{
				dataKey:         tt.fields.dataKey,
				verificationKey: tt.fields.verificationKey,
			}
			assert.Equal(t, tt.fields.dataKey, d.DataKey())
			assert.Equal(t, tt.fields.verificationKey, d.VerificationKey())
		})
	}
}
