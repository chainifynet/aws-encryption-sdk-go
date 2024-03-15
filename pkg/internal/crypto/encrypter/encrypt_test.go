package encrypter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	signaturemock "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/internal_/crypto/signature"
	randmocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/internal_/utils/rand"
	mocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	formatmocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	encryptionmocks "github.com/chainifynet/aws-encryption-sdk-go/mocks/github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/clientconfig"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/signature"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/rand"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

func TestEncrypter_reset(t *testing.T) {
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
			derivedDataKey: []byte("derivedDataKey"),
			err:            nil,
			wantHeader:     false,
		},
		{
			name:           "Reset On Error",
			header:         formatmocks.NewMockMessageHeader(t),
			derivedDataKey: []byte("derivedDataKey"),
			err:            assert.AnError,
			wantHeader:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Encrypter{
				header:          tt.header,
				_derivedDataKey: tt.derivedDataKey,
			}
			e.reset(tt.err)
			if tt.wantHeader {
				assert.Nil(t, e.header)
			} else {
				assert.NotNil(t, e.header)
			}
			assert.Empty(t, e._derivedDataKey)
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		cfg        crypto.EncrypterConfig
		setupMocks func(t *testing.T, cmm *mocks.MockCryptoMaterialsManager)
	}{
		{
			name: "Valid Encrypter",
			cfg: crypto.EncrypterConfig{
				ClientCfg:   clientconfig.ClientConfig{},
				Algorithm:   suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
				FrameLength: 4096,
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

			assert.IsType(t, &Encrypter{}, got)

			assert.Equal(t, tt.cfg, got.(*Encrypter).cfg)
			assert.Equal(t, cmm, got.(*Encrypter).cmm)
			assert.NotNil(t, got.(*Encrypter).aeadEncrypter)
			assert.NotNil(t, got.(*Encrypter).ser)
			assert.NotNil(t, got.(*Encrypter).signerFn)
			assert.NotNil(t, got.(*Encrypter).ciphertextBuf)

			assert.Nil(t, got.(*Encrypter).header)
			assert.Nil(t, got.(*Encrypter).signer)
			assert.Nil(t, got.(*Encrypter)._derivedDataKey)
		})
	}
}

func TestEncrypter_updateCiphertextBuf(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func(t *testing.T, buf *mocks.MockEncryptionBuffer)
		ciphertext  []byte
		wantBuf     []byte
		wantErr     bool
		wantErrType error
	}{
		{
			name: "Empty ciphertext",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) {
				buf.EXPECT().Write(mock.Anything).
					Return(0, nil).Once()
				buf.EXPECT().Bytes().
					Return([]byte(nil)).Once()
			},
			ciphertext: []byte{},
			wantBuf:    []byte(nil),
			wantErr:    false,
		},
		{
			name: "Non-empty ciphertext",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) {
				buf.EXPECT().Write(mock.Anything).
					Return(3, nil).Once()
				buf.EXPECT().Bytes().
					Return([]byte{1, 2, 3}).Once()
			},
			ciphertext: []byte{1, 2, 3},
			wantBuf:    []byte{1, 2, 3},
			wantErr:    false,
		},
		{
			name: "Error On Write",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) {
				buf.EXPECT().Write(mock.Anything).
					Return(0, assert.AnError).Once()
			},
			ciphertext:  []byte{4, 5, 6},
			wantBuf:     nil,
			wantErr:     true,
			wantErrType: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := mocks.NewMockEncryptionBuffer(t)
			tt.setupMocks(t, buf)

			e := &Encrypter{
				ciphertextBuf: buf,
			}
			err := e.updateCiphertextBuf(tt.ciphertext)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantBuf, e.ciphertextBuf.Bytes())
			}
		})
	}
}

func TestEncrypter_updateBuffers(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func(t *testing.T, buf *mocks.MockEncryptionBuffer) signature.Signer
		ciphertext  []byte
		wantErr     bool
		wantErrType error
	}{
		{
			name: "Empty ciphertext",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) signature.Signer {
				buf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				return nil
			},
			ciphertext: []byte{},
			wantErr:    false,
		},
		{
			name: "Сiphertext With Signer",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) signature.Signer {
				buf.EXPECT().Write(mock.Anything).Return(3, nil).Once()
				signer := signaturemock.NewMockSigner(t)
				signer.EXPECT().Write(mock.Anything).Return(3, nil).Once()
				return signer
			},
			ciphertext: []byte{1, 2, 3},
			wantErr:    false,
		},
		{
			name: "Buffer Write Error",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) signature.Signer {
				buf.EXPECT().Write(mock.Anything).Return(0, assert.AnError).Once()
				return nil
			},
			ciphertext:  []byte{4, 5, 6},
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name: "Signer Write Error",
			setupMocks: func(t *testing.T, buf *mocks.MockEncryptionBuffer) signature.Signer {
				buf.EXPECT().Write(mock.Anything).Return(3, nil).Once()
				signer := signaturemock.NewMockSigner(t)
				signer.EXPECT().Write(mock.Anything).Return(0, assert.AnError).Once()
				return signer
			},
			ciphertext:  []byte{4, 5, 6},
			wantErr:     true,
			wantErrType: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := mocks.NewMockEncryptionBuffer(t)
			signer := tt.setupMocks(t, buf)

			e := &Encrypter{
				ciphertextBuf: buf,
				signer:        signer,
			}
			err := e.updateBuffers(tt.ciphertext)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_calcFrameLen(t *testing.T) {
	tests := []struct {
		name       string
		bufLen     int
		frameLen   int
		wantResult int
		wantIsLast bool
	}{
		{
			// case 1
			name:       "Buffer length greater than frame length",
			bufLen:     1000,
			frameLen:   500,
			wantResult: 500,
			wantIsLast: false,
		},
		{
			// case 2
			name:       "Buffer length equal to frame length",
			bufLen:     1000,
			frameLen:   1000,
			wantResult: 1000,
			wantIsLast: false,
		},
		{
			// case 3 default
			name:       "Buffer length less than frame length",
			bufLen:     500,
			frameLen:   1000,
			wantResult: 500,
			wantIsLast: true,
		},
		{
			// case 3 default
			name:       "Zero buffer length",
			bufLen:     0,
			frameLen:   500,
			wantResult: 0,
			wantIsLast: true,
		},
		{
			// case 1
			name:       "Zero frame length",
			bufLen:     500,
			frameLen:   0,
			wantResult: 0,
			wantIsLast: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, isLast := calcFrameLen(tt.bufLen, tt.frameLen)
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantIsLast, isLast)
		})
	}
}

func Test_calcFrames(t *testing.T) {
	tests := []struct {
		name         string
		plaintextLen int
		frameLen     int
		want         int
	}{
		{
			// 1 empty frame
			name:         "Zero Plaintext",
			plaintextLen: 0,
			frameLen:     10,
			want:         1,
		},
		{
			// 1 frame, 10 bytes, no extra frame
			name:         "Plaintext Less Than FrameLen",
			plaintextLen: 10,
			frameLen:     20,
			want:         1,
		},
		{
			// 2 frame, 10 bytes x 1 frame + 1 extra empty frame
			name:         "Plaintext Equal To FrameLen ExtraFrame",
			plaintextLen: 10,
			frameLen:     10,
			want:         2,
		},
		{
			// 6 frames, 10 bytes x 5 frames + 1 extra empty frame
			name:         "Plaintext Greater Than FrameLen ExtraFrame",
			plaintextLen: 50,
			frameLen:     10,
			want:         6,
		},
		{
			// 7 frames, 10 bytes x 6 frames + 5 bytes x 1 frame
			name:         "Plaintext Greater Than FrameLen",
			plaintextLen: 65,
			frameLen:     10,
			want:         7,
		},
		{
			name:         "P_1024 F256",
			plaintextLen: 1024,
			frameLen:     256,
			want:         5,
		},
		{
			name:         "P_1024 F128",
			plaintextLen: 1024,
			frameLen:     128,
			want:         9,
		},
		{
			name:         "P_4096 F128",
			plaintextLen: 4096,
			frameLen:     128,
			want:         33,
		},
		{
			name:         "P_4096 F1024",
			plaintextLen: 4096,
			frameLen:     1024,
			want:         5,
		},
		{
			name:         "P_1Mb F1024",
			plaintextLen: 1048576,
			frameLen:     1024,
			want:         1025,
		},
		{
			name:         "P_1Mb F4096",
			plaintextLen: 1048576,
			frameLen:     4096,
			want:         257,
		},
		{
			name:         "P_1023 F1024",
			plaintextLen: 1023,
			frameLen:     1024,
			want:         1,
		},
		{
			name:         "P_1024 F1024",
			plaintextLen: 1024,
			frameLen:     1024,
			want:         2,
		},
		{
			name:         "P_1025 F1024",
			plaintextLen: 1025,
			frameLen:     1024,
			want:         2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calcFrames(tt.plaintextLen, tt.frameLen)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEncrypter_encryptFrame(t *testing.T) {
	type args struct {
		seqNum    int
		isFinal   bool
		iv        []byte
		plaintext []byte
	}
	finalFrameMock := args{
		seqNum:    1,
		isFinal:   true,
		iv:        []byte("test-iv"),
		plaintext: []byte("test-plaintext"),
	}
	frameMock := args{
		seqNum:    2,
		isFinal:   false,
		iv:        []byte("test-iv"),
		plaintext: []byte("test-plaintext"),
	}
	tests := []struct {
		name           string
		derivedDataKey []byte
		args           args
		setupMocks     func(t *testing.T, header *formatmocks.MockMessageHeader, aeadEncrypter *encryptionmocks.MockAEADEncrypter)
		wantCiphertext []byte
		wantAuthTag    []byte
		wantErr        bool
		wantErrType    error
		wantErrStr     string
	}{
		{
			name:           "BodyAAD Error",
			derivedDataKey: []byte("derivedDataKey"),
			args:           finalFrameMock,
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadEncrypter *encryptionmocks.MockAEADEncrypter) {
				header.EXPECT().ContentType().Return(suite.NonFramedContent).Once()
			},
			wantCiphertext: nil,
			wantAuthTag:    nil,
			wantErr:        true,
			wantErrStr:     "encrypt frame error",
		},
		{
			name:           "AEAD Encrypt Error",
			derivedDataKey: []byte("derivedDataKey"),
			args:           frameMock,
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadEncrypter *encryptionmocks.MockAEADEncrypter) {
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Once()

				aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil, assert.AnError).Once()
			},
			wantCiphertext: nil,
			wantAuthTag:    nil,
			wantErr:        true,
			wantErrType:    assert.AnError,
			wantErrStr:     "encrypt frame error",
		},
		{
			name:           "Valid Frame Encrypt",
			derivedDataKey: []byte("derivedDataKey"),
			args:           frameMock,
			setupMocks: func(t *testing.T, header *formatmocks.MockMessageHeader, aeadEncrypter *encryptionmocks.MockAEADEncrypter) {
				header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Once()

				aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("ciphertext1"), []byte("authTag1"), nil).Once()
			},
			wantCiphertext: []byte("ciphertext1"),
			wantAuthTag:    []byte("authTag1"),
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := formatmocks.NewMockMessageHeader(t)
			aeadEncrypter := encryptionmocks.NewMockAEADEncrypter(t)

			tt.setupMocks(t, header, aeadEncrypter)

			e := &Encrypter{
				aeadEncrypter:   aeadEncrypter,
				header:          header,
				_derivedDataKey: tt.derivedDataKey,
			}

			ciphertext, authTag, err := e.encryptFrame(tt.args.seqNum, tt.args.isFinal, tt.args.iv, tt.args.plaintext)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, ciphertext)
				assert.Nil(t, authTag)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ciphertext)
				assert.Equal(t, tt.wantCiphertext, ciphertext)
				assert.NotNil(t, authTag)
				assert.Equal(t, tt.wantAuthTag, authTag)
			}
		})
	}
}

func TestEncrypter_encryptBody(t *testing.T) {
	type mocksParams struct {
		header        *formatmocks.MockMessageHeader
		aeadEncrypter *encryptionmocks.MockAEADEncrypter
		ser           *formatmocks.MockSerializer
		ciphertextBuf *mocks.MockEncryptionBuffer
	}
	tests := []struct {
		name           string
		derivedDataKey []byte
		setupMocks     func(t *testing.T, m mocksParams)
		plaintext      []byte
		frameLen       int
		wantErr        bool
		wantErrType    error
		wantErrStr     string
	}{
		{
			name:           "Serialize Body Error",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Once()

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
			},
			plaintext:   make([]byte, 1024),
			frameLen:    512,
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "body error",
		},
		{
			name:           "Encrypt Frame Error",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Once()

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(formatmocks.NewMockMessageBody(t), nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("test-iv")).Once()

				m.header.EXPECT().ContentType().Return(suite.NonFramedContent).Once()
			},
			plaintext:  make([]byte, 1024),
			frameLen:   512,
			wantErr:    true,
			wantErrStr: "encrypt frame error",
		},
		{
			name:           "Body Add Frame Error",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("wrong-iv")).Once()

				m.header.EXPECT().ContentType().Return(suite.FramedContent).Once()
				m.header.EXPECT().MessageID().Return([]byte("test-message-id")).Once()

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return([]byte("ciphertext1"), []byte("authTag1"), nil).Once()

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(assert.AnError).Once()
			},
			plaintext:   make([]byte, 1024),
			frameLen:    512,
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "body frame error",
		},
		{
			name:           "Valid Encrypt Body Two Frames",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().AlgorithmSuite().
					Return(suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				m.header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				m.header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
			},
			plaintext: make([]byte, 1023),
			frameLen:  512,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := formatmocks.NewMockMessageHeader(t)
			aeadEncrypter := encryptionmocks.NewMockAEADEncrypter(t)
			ser := formatmocks.NewMockSerializer(t)
			ciphertextBuf := mocks.NewMockEncryptionBuffer(t)

			tt.setupMocks(t, mocksParams{
				header:        header,
				aeadEncrypter: aeadEncrypter,
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
			})

			cfgMock := crypto.EncrypterConfig{
				FrameLength: tt.frameLen,
			}

			e := &Encrypter{
				aeadEncrypter:   aeadEncrypter,
				cfg:             cfgMock,
				header:          header,
				ser:             ser,
				ciphertextBuf:   ciphertextBuf,
				_derivedDataKey: tt.derivedDataKey,
			}

			err := e.encryptBody(bytes.NewBuffer(tt.plaintext))
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEncrypter_generateHeaderAuth(t *testing.T) {
	type mocksParams struct {
		header        *formatmocks.MockMessageHeader
		aeadEncrypter *encryptionmocks.MockAEADEncrypter
		ser           *formatmocks.MockSerializer
		ciphertextBuf *mocks.MockEncryptionBuffer
	}
	tests := []struct {
		name           string
		derivedDataKey []byte
		setupMocks     func(t *testing.T, m mocksParams)
		wantErr        bool
		wantErrType    error
		wantErrStr     string
	}{
		{
			name:           "AEAD Auth Error",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return(nil, nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "header auth error",
		},
		{
			name:           "Serialize Header Auth Error",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				m.header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "header auth serialize error",
		},
		{
			name:           "Valid Header Auth",
			derivedDataKey: []byte("derivedDataKey"),
			setupMocks: func(t *testing.T, m mocksParams) {
				m.header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				m.header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := formatmocks.NewMockMessageHeader(t)
			aeadEncrypter := encryptionmocks.NewMockAEADEncrypter(t)
			ser := formatmocks.NewMockSerializer(t)
			ciphertextBuf := mocks.NewMockEncryptionBuffer(t)

			tt.setupMocks(t, mocksParams{
				header:        header,
				aeadEncrypter: aeadEncrypter,
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
			})

			e := &Encrypter{
				aeadEncrypter:   aeadEncrypter,
				header:          header,
				ser:             ser,
				ciphertextBuf:   ciphertextBuf,
				_derivedDataKey: tt.derivedDataKey,
			}

			err := e.generateHeaderAuth()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func setupEDKMock(t *testing.T, providerID string) *mocks.MockEncryptedDataKey {
	edk := mocks.NewMockEncryptedDataKey(t)
	edk.EXPECT().KeyProvider().Return(model.WithKeyMeta(providerID, "test-info")).Twice()
	edk.EXPECT().EncryptedDataKey().Return([]byte("test-edk")).Once()
	return edk
}

func TestEncrypter_generateHeader(t *testing.T) {
	type mocksParams struct {
		encMaterials  *mocks.MockEncryptionMaterial
		ser           *formatmocks.MockSerializer
		ciphertextBuf *mocks.MockEncryptionBuffer
	}
	tests := []struct {
		name        string
		alg         *suite.AlgorithmSuite
		setupMocks  func(t *testing.T, m mocksParams)
		wantErr     bool
		wantErrType error
		wantErrStr  string
	}{
		{
			name: "EDK Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "aws-wrong")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Once()
			},
			wantErr:    true,
			wantErrStr: "EDK error",
		},
		{
			name: "Commitment Key Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "test-aws")
				edk2 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1, edk2}).Once()
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return(nil).Once()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Once()
			},
			wantErr:    true,
			wantErrStr: "calculate commitment key error",
		},
		{
			name: "Header Serialize Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Once()
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Once()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Once()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "header serialize error",
		},
		{
			name: "Valid Generate Header",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Once()
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Once()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Once()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encMaterials := mocks.NewMockEncryptionMaterial(t)
			ser := formatmocks.NewMockSerializer(t)
			ciphertextBuf := mocks.NewMockEncryptionBuffer(t)

			tt.setupMocks(t, mocksParams{
				encMaterials:  encMaterials,
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
			})

			e := &Encrypter{
				cfg: crypto.EncrypterConfig{
					Algorithm:   tt.alg,
					FrameLength: 4096,
				},
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
			}

			err := e.generateHeader([]byte("test-message-id"), encMaterials)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, e.header)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, e.header)
			}
		})
	}
}

func TestEncrypter_prepareMessage(t *testing.T) {
	type mocksParams struct {
		cmm           *mocks.MockCryptoMaterialsManager
		encMaterials  *mocks.MockEncryptionMaterial
		ser           *formatmocks.MockSerializer
		ciphertextBuf *mocks.MockEncryptionBuffer
		signer        *signaturemock.MockSigner
		rnd           *randmocks.MockRandomGenerator
	}
	tests := []struct {
		name          string
		clientCfgOpts []clientconfig.ConfigOptionFunc
		alg           *suite.AlgorithmSuite
		setupMocks    func(t *testing.T, m mocksParams)
		wantErr       bool
		wantErrType   error
		wantErrStr    string
	}{
		{
			name: "Policy Validation Error",
			clientCfgOpts: []clientconfig.ConfigOptionFunc{
				clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptAllowDecrypt),
			},
			alg:        suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			setupMocks: func(t *testing.T, m mocksParams) {},
			wantErr:    true,
		},
		{
			name: "Get Encryption Materials Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "encrypt materials",
		},
		{
			name: "CMM Max Keys Error",
			clientCfgOpts: []clientconfig.ConfigOptionFunc{
				clientconfig.WithMaxEncryptedDataKeys(1),
			},
			alg: suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{nil, nil}).Once()
				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()
			},
			wantErr:    true,
			wantErrStr: "max encrypted data keys exceeded",
		},
		{
			name: "MessageID CryptoRandom Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{nil}).Once()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return(nil, assert.AnError).Once()
			},
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "messageID error",
		},
		{
			name: "Key Derivation Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{nil}).Once()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return(nil).Once()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Once()
			},
			wantErr:    true,
			wantErrStr: "key derivation failed",
		},
		{
			name: "Generate Header Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "aws-wrong")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Once()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Once()
			},
			wantErr:    true,
			wantErrStr: "generate header error",
		},
		{
			name: "Valid Prepare Message",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			randomGen := randmocks.NewMockRandomGenerator(t)
			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()
			rand.CryptoRandGen = randomGen

			cmm := mocks.NewMockCryptoMaterialsManager(t)
			encMaterials := mocks.NewMockEncryptionMaterial(t)
			ser := formatmocks.NewMockSerializer(t)
			ciphertextBuf := mocks.NewMockEncryptionBuffer(t)
			signer := signaturemock.NewMockSigner(t)

			tt.setupMocks(t, mocksParams{
				cmm:           cmm,
				encMaterials:  encMaterials,
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
				signer:        signer,
				rnd:           randomGen,
			})

			signerFn := func(hashFn func() hash.Hash, c elliptic.Curve, signLen int, key *ecdsa.PrivateKey) signature.Signer {
				return signer
			}

			clientCfg, _ := clientconfig.NewConfigWithOpts(tt.clientCfgOpts...)

			e := &Encrypter{
				cmm: cmm,
				cfg: crypto.EncrypterConfig{
					ClientCfg:   *clientCfg,
					Algorithm:   tt.alg,
					FrameLength: 4096,
				},
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
				signerFn:      signerFn,
			}

			err := e.prepareMessage(ctx, 1024, nil)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Nil(t, e.header)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, e.header)
				assert.NotEmpty(t, e._derivedDataKey)
			}
		})
	}
}

func TestEncrypter_encryptData(t *testing.T) {
	type mocksParams struct {
		alg           *suite.AlgorithmSuite
		cmm           *mocks.MockCryptoMaterialsManager
		aeadEncrypter *encryptionmocks.MockAEADEncrypter
		encMaterials  *mocks.MockEncryptionMaterial
		ser           *formatmocks.MockSerializer
		ciphertextBuf *mocks.MockEncryptionBuffer
		signer        *signaturemock.MockSigner
		rnd           *randmocks.MockRandomGenerator
	}
	tests := []struct {
		name          string
		clientCfgOpts []clientconfig.ConfigOptionFunc
		alg           *suite.AlgorithmSuite
		setupMocks    func(t *testing.T, m mocksParams)
		source        []byte
		wantErr       bool
		wantErrType   error
		wantErrStr    string
	}{
		{
			name:       "Empty Source Error",
			alg:        suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {},
			source:     nil,
			wantErr:    true,
			wantErrStr: "empty source",
		},
		{
			name: "Prepare Message Error",
			clientCfgOpts: []clientconfig.ConfigOptionFunc{
				clientconfig.WithCommitmentPolicy(suite.CommitmentPolicyRequireEncryptAllowDecrypt),
			},
			alg:        suite.AES_256_GCM_IV12_TAG16_HKDF_SHA256,
			setupMocks: func(t *testing.T, m mocksParams) {},
			source:     make([]byte, 1023),
			wantErr:    true,
			wantErrStr: "prepare message error",
		},
		{
			name: "Header Auth Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return(nil, nil, assert.AnError).Once()
			},
			source:     make([]byte, 1023),
			wantErr:    true,
			wantErrStr: "encrypt error",
		},
		{
			name: "Encrypt Body Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
			},
			source:     make([]byte, 1023),
			wantErr:    true,
			wantErrStr: "encrypt error",
		},
		{
			name: "Signer Sign Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// signer
				m.signer.EXPECT().Sign().Return(nil, assert.AnError).Once()
			},
			source:      make([]byte, 1023),
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "encrypt sign error",
		},
		{
			name: "Serialize Footer Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// signer
				m.signer.EXPECT().Sign().Return([]byte("signature"), nil).Once()

				m.ser.EXPECT().SerializeFooter(mock.Anything, mock.Anything).
					Return(nil, assert.AnError).Once()
			},
			source:      make([]byte, 1023),
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "encrypt sign error",
		},
		{
			name: "Ciphertext Buffer Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// signer
				m.signer.EXPECT().Sign().Return([]byte("signature"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Bytes().Return([]byte("footer-bytes")).Once()
				m.ser.EXPECT().SerializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, assert.AnError).Once()
			},
			source:      make([]byte, 1023),
			wantErr:     true,
			wantErrType: assert.AnError,
		},
		{
			name: "Ciphertext Buffer Read Error",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// signer
				m.signer.EXPECT().Sign().Return([]byte("signature"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Bytes().Return([]byte("footer-bytes")).Once()
				m.ser.EXPECT().SerializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.ciphertextBuf.EXPECT().Len().Return(1023).Once()
				m.ciphertextBuf.EXPECT().Read(mock.Anything).Return(0, assert.AnError).Once()
			},
			source:      make([]byte, 1023),
			wantErr:     true,
			wantErrType: assert.AnError,
			wantErrStr:  "ciphertext read error",
		},
		{
			name: "Valid Encrypt Data",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// signer
				m.signer.EXPECT().Sign().Return([]byte("signature"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Bytes().Return([]byte("footer-bytes")).Once()
				m.ser.EXPECT().SerializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.ciphertextBuf.EXPECT().Len().Return(1023).Once()
				m.ciphertextBuf.EXPECT().Read(mock.Anything).Return(1023, nil).Once()
				m.ciphertextBuf.EXPECT().Reset().Return().Once()
			},
			source:  make([]byte, 1023),
			wantErr: false,
			//wantErrType: assert.AnError,
			//wantErrStr:  "ciphertext read error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			randomGen := randmocks.NewMockRandomGenerator(t)
			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()
			rand.CryptoRandGen = randomGen

			cmm := mocks.NewMockCryptoMaterialsManager(t)
			aeadEncrypter := encryptionmocks.NewMockAEADEncrypter(t)
			encMaterials := mocks.NewMockEncryptionMaterial(t)
			ser := formatmocks.NewMockSerializer(t)
			ciphertextBuf := mocks.NewMockEncryptionBuffer(t)
			signer := signaturemock.NewMockSigner(t)

			tt.setupMocks(t, mocksParams{
				alg:           tt.alg,
				cmm:           cmm,
				aeadEncrypter: aeadEncrypter,
				encMaterials:  encMaterials,
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
				signer:        signer,
				rnd:           randomGen,
			})

			signerFn := func(hashFn func() hash.Hash, c elliptic.Curve, signLen int, key *ecdsa.PrivateKey) signature.Signer {
				return signer
			}

			clientCfg, _ := clientconfig.NewConfigWithOpts(tt.clientCfgOpts...)

			e := &Encrypter{
				cmm:           cmm,
				aeadEncrypter: aeadEncrypter,
				cfg: crypto.EncrypterConfig{
					ClientCfg:   *clientCfg,
					Algorithm:   tt.alg,
					FrameLength: 512,
				},
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
				signerFn:      signerFn,
			}

			ciphertext, h, err := e.encryptData(ctx, tt.source, nil)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Empty(t, ciphertext)
				assert.Nil(t, h)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, ciphertext)
				assert.NotNil(t, h)
			}
		})
	}
}

func TestEncrypter_Encrypt(t *testing.T) {
	type mocksParams struct {
		alg           *suite.AlgorithmSuite
		cmm           *mocks.MockCryptoMaterialsManager
		aeadEncrypter *encryptionmocks.MockAEADEncrypter
		encMaterials  *mocks.MockEncryptionMaterial
		ser           *formatmocks.MockSerializer
		ciphertextBuf *mocks.MockEncryptionBuffer
		signer        *signaturemock.MockSigner
		rnd           *randmocks.MockRandomGenerator
	}
	tests := []struct {
		name          string
		clientCfgOpts []clientconfig.ConfigOptionFunc
		alg           *suite.AlgorithmSuite
		setupMocks    func(t *testing.T, m mocksParams)
		source        []byte
		wantErr       bool
		wantErrType   error
		wantErrStr    string
	}{
		{
			name:        "Encrypt Error",
			alg:         suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks:  func(t *testing.T, m mocksParams) {},
			source:      nil,
			wantErr:     true,
			wantErrType: crypto.ErrEncryption,
			wantErrStr:  "SDK error",
		},
		{
			name: "Encrypt Success",
			alg:  suite.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
			setupMocks: func(t *testing.T, m mocksParams) {
				// prepare message
				edk1 := setupEDKMock(t, "test-aws")
				m.encMaterials.EXPECT().EncryptedDataKeys().Return([]model.EncryptedDataKeyI{edk1}).Twice()
				m.encMaterials.EXPECT().SigningKey().Return(&ecdsa.PrivateKey{}).Once()

				m.cmm.EXPECT().GetEncryptionMaterials(mock.Anything, mock.Anything).
					Return(m.encMaterials, nil).Once()

				m.rnd.EXPECT().CryptoRandomBytes(mock.Anything).Return([]byte("message-ID"), nil).Once()

				// header
				dk := mocks.NewMockDataKey(t)
				dk.EXPECT().DataKey().Return([]byte("test-data-key")).Twice()
				m.encMaterials.EXPECT().DataEncryptionKey().Return(dk).Twice()
				m.encMaterials.EXPECT().EncryptionContext().Return(nil).Once()

				header := formatmocks.NewMockMessageHeader(t)
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()

				m.ser.EXPECT().SerializeHeader(mock.Anything).Return(header, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// header auth
				header.EXPECT().Bytes().Return([]byte("header-bytes")).Once()
				header.EXPECT().Version().Return(suite.V2).Once()

				m.aeadEncrypter.EXPECT().GenerateHeaderAuth(mock.Anything, mock.Anything).
					Return([]byte("headerAuthTag"), []byte("auth-iv"), nil).Once()

				headerAuthData := formatmocks.NewMockMessageHeaderAuth(t)
				headerAuthData.EXPECT().Bytes().Return([]byte("headerAuthData-bytes")).Once()

				m.ser.EXPECT().SerializeHeaderAuth(mock.Anything, mock.Anything, mock.Anything).
					Return(headerAuthData, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// encrypt body
				header.EXPECT().AlgorithmSuite().
					Return(m.alg).Once()

				body := formatmocks.NewMockMessageBody(t)

				m.ser.EXPECT().SerializeBody(mock.Anything, mock.Anything).
					Return(body, nil).Once()

				m.aeadEncrypter.EXPECT().ConstructIV(mock.Anything).Return([]byte("testIv12byte")).Times(2)

				header.EXPECT().ContentType().Return(suite.FramedContent).Times(2)
				header.EXPECT().MessageID().Return([]byte("test-message-id")).Times(2)

				m.aeadEncrypter.EXPECT().Encrypt(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(make([]byte, 512), []byte("auth-Tag-16bytes"), nil).Times(2)

				body.EXPECT().AddFrame(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Times(2)
				body.EXPECT().Bytes().Return([]byte("body-bytes")).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.signer.EXPECT().Write(mock.Anything).Return(0, nil).Once()

				// signer
				m.signer.EXPECT().Sign().Return([]byte("signature"), nil).Once()

				// footer
				footer := formatmocks.NewMockMessageFooter(t)
				footer.EXPECT().Bytes().Return([]byte("footer-bytes")).Once()
				m.ser.EXPECT().SerializeFooter(mock.Anything, mock.Anything).
					Return(footer, nil).Once()

				m.ciphertextBuf.EXPECT().Write(mock.Anything).Return(0, nil).Once()
				m.ciphertextBuf.EXPECT().Len().Return(1023).Once()
				m.ciphertextBuf.EXPECT().Read(mock.Anything).Return(1023, nil).Once()
				m.ciphertextBuf.EXPECT().Reset().Return().Once()
			},
			source:  make([]byte, 1023),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			randomGen := randmocks.NewMockRandomGenerator(t)
			defer func() {
				rand.CryptoRandGen = rand.DefaultRandomGenerator{}
			}()
			rand.CryptoRandGen = randomGen

			cmm := mocks.NewMockCryptoMaterialsManager(t)
			aeadEncrypter := encryptionmocks.NewMockAEADEncrypter(t)
			encMaterials := mocks.NewMockEncryptionMaterial(t)
			ser := formatmocks.NewMockSerializer(t)
			ciphertextBuf := mocks.NewMockEncryptionBuffer(t)
			signer := signaturemock.NewMockSigner(t)

			tt.setupMocks(t, mocksParams{
				alg:           tt.alg,
				cmm:           cmm,
				aeadEncrypter: aeadEncrypter,
				encMaterials:  encMaterials,
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
				signer:        signer,
				rnd:           randomGen,
			})

			signerFn := func(hashFn func() hash.Hash, c elliptic.Curve, signLen int, key *ecdsa.PrivateKey) signature.Signer {
				return signer
			}

			clientCfg, _ := clientconfig.NewConfigWithOpts(tt.clientCfgOpts...)

			e := &Encrypter{
				cmm:           cmm,
				aeadEncrypter: aeadEncrypter,
				cfg: crypto.EncrypterConfig{
					ClientCfg:   *clientCfg,
					Algorithm:   tt.alg,
					FrameLength: 512,
				},
				ser:           ser,
				ciphertextBuf: ciphertextBuf,
				signerFn:      signerFn,
			}

			ciphertext, h, err := e.Encrypt(ctx, tt.source, nil)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrType != nil {
					assert.ErrorIs(t, err, tt.wantErrType)
				}
				if tt.wantErrStr != "" {
					assert.ErrorContains(t, err, tt.wantErrStr)
				}
				assert.Empty(t, ciphertext)
				assert.Nil(t, h)
				assert.Nil(t, e.header)
				assert.Empty(t, e._derivedDataKey)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, ciphertext)
				assert.NotNil(t, h)
				assert.NotNil(t, e.header)
				assert.Empty(t, e._derivedDataKey)
			}
		})
	}
}
