// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package decrypter

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	signaturemock "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/internal_/crypto/signature"
	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	formatmocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	encryptionmocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/signature"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		cfg        crypto.DecrypterConfig
		setupMocks func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager)
	}{
		{
			name: "Valid Decrypter",
			cfg: crypto.DecrypterConfig{
				ClientCfg: clientconfig.ClientConfig{},
			},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager) {
				cmm.EXPECT().GetInstance().Return(cmm).Once()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmm := mocks.NewMockCryptoMaterialsManager(t)
			tt.setupMocks(t, cmm)

			got := New(tt.cfg, cmm)
			assert.NotNil(t, got)

			assert.IsType(t, &Decrypter{}, got)

			assert.Equal(t, tt.cfg, got.(*Decrypter).cfg)
			assert.Equal(t, cmm, got.(*Decrypter).cmm)
			assert.NotNil(t, got.(*Decrypter).aeadDecrypter)
			assert.NotNil(t, got.(*Decrypter).deser)
			assert.NotNil(t, got.(*Decrypter).verifierFn)

			assert.Nil(t, got.(*Decrypter).header)
			assert.Nil(t, got.(*Decrypter).verifier)
			assert.Nil(t, got.(*Decrypter)._derivedDataKey)
		})
	}
}

func TestDecrypter_updateVerifier(t *testing.T) {
	tests := []struct {
		name       string
		b          []byte
		setupMocks func(t *testing.T, verifier *signaturemock.MockVerifier)
		wantErr    bool
	}{
		{
			name: "Update Success",
			b:    []byte("test"),
			setupMocks: func(t *testing.T, verifier *signaturemock.MockVerifier) {
				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Update Write Error",
			b:    []byte("test"),
			setupMocks: func(t *testing.T, verifier *signaturemock.MockVerifier) {
				verifier.EXPECT().Write(mock.Anything).Return(0, assert.AnError).Once()
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := signaturemock.NewMockVerifier(t)
			tt.setupMocks(t, verifier)
			d := &Decrypter{
				verifier: verifier,
			}

			err := d.updateVerifier(tt.b)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "verifier write error")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func setupEDKMock(t *testing.T) *formatmocks.MockMessageEDK {
	edk := formatmocks.NewMockMessageEDK(t)
	edk.EXPECT().ProviderID().Return("test-aws").Once()
	edk.EXPECT().ProviderInfo().Return("test-info").Once()
	edk.EXPECT().EncryptedDataKey().Return([]byte("test-edk")).Once()
	return edk
}

func setupAADMock(t *testing.T) *formatmocks.MockMessageAAD {
	aad := formatmocks.NewMockMessageAAD(t)
	aad.EXPECT().EncryptionContext().Return(nil).Once()
	return aad
}

func TestDecrypter_Decrypt(t *testing.T) {
	algSuiteDataMock := []byte{0x7F, 0xBF, 0x61, 0xB4, 0x54, 0x5F, 0x30, 0x62, 0x59, 0x76, 0xF1, 0x19, 0x7C, 0x15, 0xFF, 0xB1, 0x57, 0x6C, 0x9E, 0xCC, 0xEF, 0xB1, 0x84, 0x9C, 0x8, 0x9B, 0x2A, 0xA6, 0x8, 0xA9, 0x6C, 0x95}
	tests := []struct {
		name          string
		clientCfgOpts []clientconfig.ConfigOptionFunc
		ciphertext    []byte
		setupMocks    func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer)
		want          []byte
		wantErr       bool
		wantErrType   error
		wantErrStr    string
	}{
		{
			name:       "Valid Decrypt",
			ciphertext: []byte{0x02, 0x00},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				// header
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Times(10)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Times(3)
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Times(3)
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

				// body
				frame := formatmocks.NewMockBodyFrame(t)
				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()
				frame.EXPECT().Bytes().Return([]byte("test-frame")).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted1"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Signature().Return([]byte("test-signature")).Once()

				deser.EXPECT().DeserializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				verifier.EXPECT().Verify(mock.Anything).Return(nil).Once()
			},
			want:    []byte("decrypted1"),
			wantErr: false,
		},
		{
			name:       "Decrypt Error",
			ciphertext: nil,
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
			},
			want:        nil,
			wantErr:     true,
			wantErrType: crypto.ErrDecryption,
			wantErrStr:  "SDK error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			cmm := mocks.NewMockCryptoMaterialsManager(t)
			deser := formatmocks.NewMockDeserializer(t)
			verifier := signaturemock.NewMockVerifier(t)
			aeadDecrypter := encryptionmocks.NewMockAEADDecrypter(t)

			tt.setupMocks(t, cmm, verifier, aeadDecrypter, deser)

			verifierFn := func(hashFn func() hash.Hash, c elliptic.Curve) signature.Verifier {
				return verifier
			}

			clientCfg, _ := clientconfig.NewConfigWithOpts(tt.clientCfgOpts...)
			cfgMock := crypto.DecrypterConfig{
				ClientCfg: *clientCfg,
			}

			d := &Decrypter{
				cmm:           cmm,
				cfg:           cfgMock,
				aeadDecrypter: aeadDecrypter,
				deser:         deser,
				verifierFn:    verifierFn,
			}

			plaintext, h, err := d.Decrypt(ctx, tt.ciphertext)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, h)
				assert.Nil(t, plaintext)
				assert.Nil(t, d._derivedDataKey)
				assert.Nil(t, d.header)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, h)
				assert.Equal(t, tt.want, plaintext)
				assert.Nil(t, d._derivedDataKey)
			}
		})
	}
}

func TestDecrypter_decryptData(t *testing.T) {
	algSuiteDataMock := []byte{0x7F, 0xBF, 0x61, 0xB4, 0x54, 0x5F, 0x30, 0x62, 0x59, 0x76, 0xF1, 0x19, 0x7C, 0x15, 0xFF, 0xB1, 0x57, 0x6C, 0x9E, 0xCC, 0xEF, 0xB1, 0x84, 0x9C, 0x8, 0x9B, 0x2A, 0xA6, 0x8, 0xA9, 0x6C, 0x95}
	tests := []struct {
		name          string
		clientCfgOpts []clientconfig.ConfigOptionFunc
		ciphertext    []byte
		setupMocks    func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer)
		want          []byte
		wantErr       bool
		wantErrType   error
		wantErrStr    string
	}{
		{
			name:       "Valid Decrypt",
			ciphertext: []byte{0x02, 0x00},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				// header
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Times(10)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Times(3)
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Times(3)
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

				// body
				frame := formatmocks.NewMockBodyFrame(t)
				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()
				frame.EXPECT().Bytes().Return([]byte("test-frame")).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted1"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Signature().Return([]byte("test-signature")).Once()

				deser.EXPECT().DeserializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				verifier.EXPECT().Verify(mock.Anything).Return(nil).Once()
			},
			want:    []byte("decrypted1"),
			wantErr: false,
		},
		{
			name:       "Empty Ciphertext",
			ciphertext: nil,
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {

			},
			want:       nil,
			wantErr:    true,
			wantErrStr: "empty ciphertext",
		},
		{
			name:       "Invalid Ciphertext First Bytes",
			ciphertext: []byte{0x03},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
			},
			want:        nil,
			wantErr:     true,
			wantErrType: ErrInvalidMessage,
			wantErrStr:  "first byte does not contain message version",
		},
		{
			name:       "Header Decrypt Error",
			ciphertext: []byte{0x02, 0x00},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(nil, nil, assert.AnError).Once()
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name:       "Body Decrypt Error",
			ciphertext: []byte{0x02, 0x00},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				// header
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Times(9)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Times(2)
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Times(2)
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

				// body
				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name:       "Footer Deserialize Error",
			ciphertext: []byte{0x02, 0x00},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				// header
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Times(10)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Times(3)
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Times(3)
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

				// body
				frame := formatmocks.NewMockBodyFrame(t)
				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()
				frame.EXPECT().Bytes().Return([]byte("test-frame")).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted1"), nil).Once()

				// footer
				deser.EXPECT().DeserializeFooter(mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name:       "Footer Signature Error",
			ciphertext: []byte{0x02, 0x00},
			setupMocks: func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				// header
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Times(10)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Times(3)
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Times(3)
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

				// body
				frame := formatmocks.NewMockBodyFrame(t)
				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()
				frame.EXPECT().Bytes().Return([]byte("test-frame")).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted1"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Signature().Return([]byte("test-signature")).Once()

				deser.EXPECT().DeserializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				verifier.EXPECT().Verify(mock.Anything).Return(assert.AnError).Once()
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			cmm := mocks.NewMockCryptoMaterialsManager(t)
			deser := formatmocks.NewMockDeserializer(t)
			verifier := signaturemock.NewMockVerifier(t)
			aeadDecrypter := encryptionmocks.NewMockAEADDecrypter(t)

			tt.setupMocks(t, cmm, verifier, aeadDecrypter, deser)

			verifierFn := func(hashFn func() hash.Hash, c elliptic.Curve) signature.Verifier {
				return verifier
			}

			clientCfg, _ := clientconfig.NewConfigWithOpts(tt.clientCfgOpts...)
			cfgMock := crypto.DecrypterConfig{
				ClientCfg: *clientCfg,
			}

			d := &Decrypter{
				cmm:           cmm,
				cfg:           cfgMock,
				aeadDecrypter: aeadDecrypter,
				deser:         deser,
				verifierFn:    verifierFn,
			}

			plaintext, h, err := d.decryptData(ctx, tt.ciphertext)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, h)
				assert.Nil(t, plaintext)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, h)
				assert.Equal(t, tt.want, plaintext)
			}
		})
	}
}

func TestDecrypter_decryptHeader(t *testing.T) {
	algSuiteDataMock := []byte{0x7F, 0xBF, 0x61, 0xB4, 0x54, 0x5F, 0x30, 0x62, 0x59, 0x76, 0xF1, 0x19, 0x7C, 0x15, 0xFF, 0xB1, 0x57, 0x6C, 0x9E, 0xCC, 0xEF, 0xB1, 0x84, 0x9C, 0x8, 0x9B, 0x2A, 0xA6, 0x8, 0xA9, 0x6C, 0x95}
	tests := []struct {
		name          string
		clientCfgOpts []clientconfig.ConfigOptionFunc
		alg           *suite.AlgorithmSuite
		setupMocks    func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter)
		wantErr       bool
		wantErrType   error
		wantErrStr    string
	}{
		{
			name: "Valid Committing Signing",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(8)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Twice()
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Valid Committing NonSigning",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(6)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Twice()
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Valid NonCommitting NonSigning",
			clientCfgOpts: []clientconfig.ConfigOptionFunc{
				clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptAllowDecrypt),
			},
			alg: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(5)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Once()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().DataKey().Return(dataKey).Once()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Valid NonCommitting Signing",
			clientCfgOpts: []clientconfig.ConfigOptionFunc{
				clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyForbidEncryptAllowDecrypt),
			},
			alg: suite.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(7)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Once()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Once()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Deserialize Header Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).
					Return(nil, nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name: "Policy Conflict Error",
			alg:  suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(1)

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

			},
			wantErr: true,
		},
		{
			name: "Verifier Update Header Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(4)
				header.EXPECT().Bytes().Return([]byte("test")).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(0, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name: "Verifier Update Header Auth Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(4)
				header.EXPECT().Bytes().Return([]byte("test")).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write([]byte("test")).Return(4, nil).Once()
				verifier.EXPECT().Write([]byte("test-auth")).Return(0, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name: "CMM DecryptMaterials Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(5)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()

				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "decrypt materials",
		},
		{
			name: "Verifier Elliptic Key Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(5)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(assert.AnError).Once()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "decrypt verifier error",
		},
		{
			name: "Derive DataKey Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(6)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return(nil).Once() // that result in key derivation error

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Once()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()
			},
			wantErr:    true,
			wantErrStr: "decrypt key derivation error",
		},
		{
			name: "Commitment Key Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(8)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Twice()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Once()
				dataKey.EXPECT().DataKey().Return(nil).Once() // that result in key commitment error

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()
			},
			wantErr:    true,
			wantErrStr: "decrypt calculate commitment key error",
		},
		{
			name: "Commitment Key Match Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(8)
				header.EXPECT().Bytes().Return([]byte("test")).Once()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Twice()
				header.EXPECT().AlgorithmSuiteData().Return([]byte{0x00}).Once() // that result in key commitment error

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()
			},
			wantErr:    true,
			wantErrStr: "key commitment validation failed",
		},
		{
			name: "Header Auth Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, alg *suite.AlgorithmSuite, cmm *mocks.MockCryptoMaterialsManager, deser *formatmocks.MockDeserializer, verifier *signaturemock.MockVerifier, aeadDecrypter *encryptionmocks.MockAEADDecrypter) {
				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().AlgorithmSuite().Return(alg).Times(8)
				header.EXPECT().Bytes().Return([]byte("test")).Twice()
				header.EXPECT().EncryptedDataKeys().Return([]format.MessageEDK{setupEDKMock(t)}).Once()
				header.EXPECT().AADData().Return(setupAADMock(t)).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Twice()
				header.EXPECT().AlgorithmSuiteData().Return(algSuiteDataMock).Once()

				headerAuth := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuth.EXPECT().Bytes().Return([]byte("test-auth")).Once()
				headerAuth.EXPECT().AuthData().Return([]byte("test-auth-data")).Once()

				deser.EXPECT().DeserializeHeader(mock.Anything, mock.Anything).Return(header, headerAuth, nil).Once()

				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Twice()
				verifier.EXPECT().LoadECCKey(mock.Anything).Return(nil).Once()

				dataKey := mocks.NewMockDataKey(t)
				dataKey.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()

				decMaterials := mocks.NewMockDecryptionMaterial(t)
				decMaterials.EXPECT().VerificationKey().Return([]byte("test-key")).Once()
				decMaterials.EXPECT().DataKey().Return(dataKey).Twice()
				cmm.EXPECT().DecryptMaterials(mock.Anything, mock.Anything).Return(decMaterials, nil).Once()

				aeadDecrypter.EXPECT().ValidateHeaderAuth(mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "decrypt header auth error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			cmm := mocks.NewMockCryptoMaterialsManager(t)
			deser := formatmocks.NewMockDeserializer(t)
			verifier := signaturemock.NewMockVerifier(t)
			aeadDecrypter := encryptionmocks.NewMockAEADDecrypter(t)

			tt.setupMocks(t, tt.alg, cmm, deser, verifier, aeadDecrypter)

			verifierFn := func(hashFn func() hash.Hash, c elliptic.Curve) signature.Verifier {
				return verifier
			}

			clientCfg, _ := clientconfig.NewConfigWithOpts(tt.clientCfgOpts...)
			cfgMock := crypto.DecrypterConfig{
				ClientCfg: *clientCfg,
			}

			d := &Decrypter{
				cmm:           cmm,
				cfg:           cfgMock,
				aeadDecrypter: aeadDecrypter,
				deser:         deser,
				verifierFn:    verifierFn,
			}

			err := d.decryptHeader(ctx, bytes.NewBuffer([]byte("test")))
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, d.header)
				assert.Empty(t, d._derivedDataKey)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, d.header)
				assert.NotEmpty(t, d._derivedDataKey)
				if tt.alg.IsSigning() {
					assert.NotNil(t, d.verifier)
				} else {
					assert.Nil(t, d.verifier)
				}
			}
		})
	}
}

func TestDecrypter_decryptBody(t *testing.T) {
	tests := []struct {
		name           string
		derivedDataKey []byte
		setupMocks     func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer)
		want           []byte
		wantErr        bool
		wantErrType    error
		wantErrStr     string
	}{
		{
			name:           "Valid Decrypt",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				frame := formatmocks.NewMockBodyFrame(t)
				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted1"), nil).Once()
			},
			want:    []byte("decrypted1"),
			wantErr: false,
		},
		{
			name:           "Valid Two Frames Decrypt",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.FramedContent).Twice()
				header.EXPECT().MessageID().Return([]byte("test-id")).Twice()

				frame1 := formatmocks.NewMockBodyFrame(t)
				frame1.EXPECT().IsFinal().Return(false).Once()
				frame1.EXPECT().SequenceNumber().Return(1).Once()
				frame1.EXPECT().EncryptedContent().Return([]byte("test-content1")).Twice()
				frame1.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame1.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()

				frame2 := formatmocks.NewMockBodyFrame(t)
				frame2.EXPECT().IsFinal().Return(true).Once()
				frame2.EXPECT().SequenceNumber().Return(2).Once()
				frame2.EXPECT().EncryptedContent().Return([]byte("test-content2")).Twice()
				frame2.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame2.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame1, frame2}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted1"), nil).Once()
				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("decrypted2"), nil).Once()
			},
			want:    []byte("decrypted1decrypted2"),
			wantErr: false,
		},
		{
			name:           "Deserialize Body Error",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY).Once()
				header.EXPECT().FrameLength().Return(1024).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "deserialize body error",
		},
		{
			name:           "Decrypt Frame Error",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, deser *formatmocks.MockDeserializer) {
				header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY).Once()
				header.EXPECT().FrameLength().Return(1024).Once()
				header.EXPECT().ContentType().Return(suite.NonFramedContent).Once() // that result in decrypt frame error

				frame := formatmocks.NewMockBodyFrame(t)
				frame.EXPECT().IsFinal().Return(true).Once()

				body := formatmocks.NewMockMessageBody(t)
				body.EXPECT().Frames().
					Return([]format.BodyFrame{frame}).Once()

				deser.EXPECT().DeserializeBody(mock.Anything, mock.Anything, mock.Anything).
					Return(body, nil).Once()
			},
			want:       nil,
			wantErr:    true,
			wantErrStr: "decrypt frame error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := formatmocks.NewMockMessageHeader(t)
			deser := formatmocks.NewMockDeserializer(t)
			aeadDecrypter := encryptionmocks.NewMockAEADDecrypter(t)

			tt.setupMocks(t, header, aeadDecrypter, deser)

			d := &Decrypter{
				aeadDecrypter:   aeadDecrypter,
				deser:           deser,
				_derivedDataKey: tt.derivedDataKey,
				header:          header,
			}

			plaintext, err := d.decryptBody(bytes.NewBuffer([]byte("test")))
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, plaintext)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, plaintext)
				assert.Equal(t, tt.want, plaintext)
			}
		})
	}
}

func TestDecrypter_decryptFrame(t *testing.T) {
	tests := []struct {
		name           string
		derivedDataKey []byte
		setupMocks     func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, frame *formatmocks.MockBodyFrame) signature.Verifier
		want           []byte
		wantErr        bool
		wantErrType    error
		wantErrStr     string
	}{
		{
			name:           "Valid Decrypt Final Frame",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, frame *formatmocks.MockBodyFrame) signature.Verifier {
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()
				frame.EXPECT().Bytes().Return([]byte("test-frame")).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("test-decrypted"), nil).Once()

				verifier := signaturemock.NewMockVerifier(t)
				verifier.EXPECT().Write(mock.Anything).Return(4, nil).Once()
				return verifier
			},
			want:    []byte("test-decrypted"),
			wantErr: false,
		},
		{
			name:           "Valid Decrypt NonFinal Frame",
			derivedDataKey: []byte("test-key2"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, frame *formatmocks.MockBodyFrame) signature.Verifier {
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				frame.EXPECT().IsFinal().Return(false).Once()
				frame.EXPECT().SequenceNumber().Return(2).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("test-decrypted2"), nil).Once()

				return nil
			},
			want:    []byte("test-decrypted2"),
			wantErr: false,
		},
		{
			name:           "BodyAAD NonFramed Error",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, frame *formatmocks.MockBodyFrame) signature.Verifier {
				header.EXPECT().ContentType().Return(suite.NonFramedContent).Once()

				frame.EXPECT().IsFinal().Return(true).Once()
				return nil
			},
			want:       nil,
			wantErr:    true,
			wantErrStr: "bodyaad error",
		},
		{
			name:           "AEAD Decrypt Error",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, frame *formatmocks.MockBodyFrame) signature.Verifier {
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()

				return nil
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "decrypt frame AEAD error",
		},
		{
			name:           "Verifier Error",
			derivedDataKey: []byte("test-key"),
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadDecrypter *encryptionmocks.MockAEADDecrypter, frame *formatmocks.MockBodyFrame) signature.Verifier {
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-id")).Once()

				frame.EXPECT().IsFinal().Return(true).Once()
				frame.EXPECT().SequenceNumber().Return(1).Once()
				frame.EXPECT().EncryptedContent().Return([]byte("test-content")).Twice()
				frame.EXPECT().IV().Return([]byte("test-iv")).Once()
				frame.EXPECT().AuthenticationTag().Return([]byte("test-tag")).Once()
				frame.EXPECT().Bytes().Return([]byte("test-frame")).Once()

				aeadDecrypter.EXPECT().Decrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("test-decrypted"), nil).Once()

				verifier := signaturemock.NewMockVerifier(t)
				verifier.EXPECT().Write(mock.Anything).Return(0, assert.AnError).Once()
				return verifier
			},
			want:        nil,
			wantErr:     true,
			wantErrType: assert.AnError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := formatmocks.NewMockMessageHeader(t)
			aeadDecrypter := encryptionmocks.NewMockAEADDecrypter(t)
			frame := formatmocks.NewMockBodyFrame(t)

			verifier := tt.setupMocks(t, header, aeadDecrypter, frame)

			d := &Decrypter{
				aeadDecrypter:   aeadDecrypter,
				verifier:        verifier,
				_derivedDataKey: tt.derivedDataKey,
				header:          header,
			}

			b, err := d.decryptFrame(frame)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, b)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, b)
				assert.Equal(t, tt.want, b)
			}
		})
	}
}

func TestDecrypter_reset(t *testing.T) {
	tests := []struct {
		name           string
		header         format.MessageHeader
		derivedDataKey []byte
		err            error
		wantHeader     bool
	}{
		{
			name:           "Reset Cleanup",
			header:         formatmocks.NewMockMessageHeader(t),
			derivedDataKey: []byte("test-key"),
			err:            nil,
			wantHeader:     false,
		},
		{
			name:           "Reset On Error",
			header:         formatmocks.NewMockMessageHeader(t),
			derivedDataKey: []byte("test-key"),
			err:            assert.AnError,
			wantHeader:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Decrypter{
				header:          tt.header,
				_derivedDataKey: tt.derivedDataKey,
			}
			d.reset(tt.err)
			if tt.wantHeader {
				assert.Nil(t, d.header)
			}
			assert.Empty(t, d._derivedDataKey)
		})
	}
}
