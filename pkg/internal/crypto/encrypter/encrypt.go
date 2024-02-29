// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package encrypter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/signature"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/bodyaad"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/keyderivation"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

type Encrypter struct {
	cmm             model.CryptoMaterialsManager
	cfg             crypto.EncrypterConfig
	aeadEncrypter   encryption.AEADEncrypter
	ser             format.Serializer
	header          format.MessageHeader
	_derivedDataKey []byte
	signer          signature.Signer
	signerFn        signature.SignerFunc
	ciphertextBuf   model.EncryptionBuffer
}

func New(cfg crypto.EncrypterConfig, cmm model.CryptoMaterialsManager) model.EncryptionHandler {
	return &Encrypter{
		cmm:           cmm.GetInstance(),
		cfg:           cfg,
		aeadEncrypter: encryption.Gcm{},
		ser:           serialization.NewSerializer(),
		signerFn:      signature.NewECCSigner,
		ciphertextBuf: new(bytes.Buffer),
	}
}

func (e *Encrypter) Encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, format.MessageHeader, error) {
	ciphertext, header, err := e.encryptData(ctx, source, ec)
	if err != nil {
		e.reset(err)
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(crypto.ErrEncryption, err))
	}
	e.reset(nil)
	return ciphertext, header, nil
}

func (e *Encrypter) encryptData(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, format.MessageHeader, error) {
	var b []byte
	b = make([]byte, len(source))
	copy(b, source)
	if len(source) == 0 || len(b) == 0 {
		return nil, nil, fmt.Errorf("empty source")
	}
	buf := bytes.NewBuffer(b)
	if err := e.prepareMessage(ctx, buf.Len(), ec); err != nil {
		return nil, nil, fmt.Errorf("prepare message error: %w", err)
	}

	if err := e.generateHeaderAuth(); err != nil {
		return nil, nil, fmt.Errorf("encrypt error: %w", err)
	}

	if err := e.encryptBody(buf); err != nil {
		return nil, nil, fmt.Errorf("encrypt error: %w", err)
	}

	if e.signer != nil {
		sign, err := e.signer.Sign()
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt sign error: %w", err)
		}
		footer, err := e.ser.SerializeFooter(e.cfg.Algorithm, sign)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt sign error: %w", err)
		}
		if errBuf := e.updateCiphertextBuf(footer.Bytes()); errBuf != nil {
			return nil, nil, errBuf // already wrapped in updateCiphertextBuf
		}
	}

	var ciphertext []byte
	ciphertext = make([]byte, e.ciphertextBuf.Len())
	_, err := e.ciphertextBuf.Read(ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("ciphertext read error: %w", err)
	}

	e.ciphertextBuf.Reset()

	return ciphertext, e.header, nil
}

func (e *Encrypter) prepareMessage(ctx context.Context, plaintextLen int, ec suite.EncryptionContext) error {
	if err := policy.ValidateOnEncrypt(e.cfg.ClientCfg.CommitmentPolicy(), e.cfg.Algorithm); err != nil {
		return err // just return err
	}

	emr := model.EncryptionMaterialsRequest{
		EncryptionContext: ec,
		Algorithm:         e.cfg.Algorithm,
		PlaintextLength:   plaintextLen,
	}

	encMaterials, err := e.cmm.GetEncryptionMaterials(ctx, emr)
	if err != nil {
		return fmt.Errorf("encrypt materials: %w", err)
	}
	if len(encMaterials.EncryptedDataKeys()) > e.cfg.ClientCfg.MaxEncryptedDataKeys() {
		return fmt.Errorf("materials: max encrypted data keys exceeded")
	}

	if e.cfg.Algorithm.IsSigning() {
		e.signer = e.signerFn(
			e.cfg.Algorithm.Authentication.HashFunc,
			e.cfg.Algorithm.Authentication.Algorithm,
			e.cfg.Algorithm.Authentication.SignatureLen,
			encMaterials.SigningKey(),
		)
	}

	messageID, err := rand.CryptoRandomBytes(e.cfg.Algorithm.MessageIDLen())
	if err != nil {
		return fmt.Errorf("messageID error: %w", err)
	}

	derivedDataKey, err := keyderivation.DeriveDataEncryptionKey(encMaterials.DataEncryptionKey().DataKey(), e.cfg.Algorithm, messageID)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	e._derivedDataKey = derivedDataKey

	if errHeader := e.generateHeader(messageID, encMaterials); errHeader != nil {
		return fmt.Errorf("generate header error: %w", errHeader)
	}

	return nil
}

func (e *Encrypter) generateHeader(messageID []byte, encMaterials model.EncryptionMaterial) error {
	edks, err := serialization.EDK.FromEDKs(encMaterials.EncryptedDataKeys())
	if err != nil {
		return fmt.Errorf("EDK error: %w", err)
	}

	var commitmentKey []byte
	if e.cfg.Algorithm.IsCommitting() {
		commitmentKey, err = keyderivation.CalculateCommitmentKey(encMaterials.DataEncryptionKey().DataKey(), e.cfg.Algorithm, messageID)
		if err != nil {
			return fmt.Errorf("calculate commitment key error: %w", err)
		}
	}

	params := format.HeaderParams{
		AlgorithmSuite:     e.cfg.Algorithm,
		MessageID:          messageID,
		EncryptionContext:  encMaterials.EncryptionContext(),
		EncryptedDataKeys:  edks,
		ContentType:        suite.FramedContent,
		FrameLength:        e.cfg.FrameLength,
		AlgorithmSuiteData: commitmentKey,
	}

	header, err := e.ser.SerializeHeader(params)
	if err != nil {
		return fmt.Errorf("header serialize error: %w", err)
	}
	e.header = header

	return e.updateBuffers(e.header.Bytes())
}

func (e *Encrypter) generateHeaderAuth() error {
	headerAuthTag, iv, err := e.aeadEncrypter.GenerateHeaderAuth(e._derivedDataKey, e.header.Bytes())
	if err != nil {
		return fmt.Errorf("header auth error: %w", err)
	}
	headerAuthData, err := e.ser.SerializeHeaderAuth(e.header.Version(), iv, headerAuthTag)
	if err != nil {
		return fmt.Errorf("header auth serialize error: %w", err)
	}
	return e.updateBuffers(headerAuthData.Bytes())
}

func (e *Encrypter) encryptBody(plaintextBuffer *bytes.Buffer) error {
	body, errBody := e.ser.SerializeBody(e.header.AlgorithmSuite(), e.cfg.FrameLength)
	if errBody != nil {
		return fmt.Errorf("body error: %w", errBody)
	}

	frames := calcFrames(plaintextBuffer.Len(), e.cfg.FrameLength)

	for seqNum := 1; seqNum <= frames; seqNum++ {
		bytesToRead, isFinal := calcFrameLen(plaintextBuffer.Len(), e.cfg.FrameLength)
		plaintext := plaintextBuffer.Next(bytesToRead)
		iv := e.aeadEncrypter.ConstructIV(seqNum)
		ciphertext, authTag, err := e.encryptFrame(seqNum, isFinal, iv, plaintext)
		if err != nil {
			return err
		}
		if errFrame := body.AddFrame(isFinal, seqNum, iv, len(plaintext), ciphertext, authTag); errFrame != nil {
			return fmt.Errorf("body frame error: %w", errFrame)
		}
	}

	return e.updateBuffers(body.Bytes())
}

// calcFrames calculates the number of frames needed to store a given plaintext length, based on the frame length parameter.
// It returns the number of frames as an integer.
//
// The frames are calculated by dividing the plaintext length by the frame length and rounding up using math.Ceil.
// An extra final frame is added if the plaintext length is exactly divisible by the frame length.
func calcFrames(plaintextLen, frameLen int) int {
	frames := math.Ceil(float64(plaintextLen) / float64(frameLen))
	// Check if an extra final frame is needed when the plaintextBuffer
	//  length is exactly divisible by the frame length
	if plaintextLen%frameLen == 0 {
		frames++
	}
	return int(frames)
}

// calcFrameLen calculates the frame length based on the buffer length and frame length parameters.
// It returns the calculated frame length and a boolean indicating whether it is the last frame or not.
//
// If bufLen is greater than frameLen, it returns frameLen and false.
// If bufLen is equal to frameLen, it returns frameLen and false.
// If bufLen is less than frameLen, it returns bufLen and true.
func calcFrameLen(bufLen, frameLen int) (int, bool) {
	switch {
	case bufLen > frameLen:
		return frameLen, false // false means not last frame
	case bufLen == frameLen:
		return frameLen, false // false means not last frame
	default:
		return bufLen, true // true means last frame
	}
}

func (e *Encrypter) encryptFrame(seqNum int, isFinal bool, iv, plaintext []byte) ([]byte, []byte, error) {
	contentString, err := bodyaad.ContentString(e.header.ContentType(), isFinal)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt frame error: %w", err)
	}
	associatedData := bodyaad.ContentAADBytes(
		e.header.MessageID(),
		contentString,
		seqNum,
		len(plaintext),
	)
	ciphertext, authTag, err := e.aeadEncrypter.Encrypt(
		e._derivedDataKey,
		iv,
		plaintext,
		associatedData,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt frame error: %w", err)
	}
	return ciphertext, authTag, nil
}

func (e *Encrypter) updateCiphertextBuf(b []byte) error {
	_, err := e.ciphertextBuf.Write(b)
	if err != nil {
		return fmt.Errorf("ciphertext buffer write error: %w", err)
	}

	return nil
}

func (e *Encrypter) updateBuffers(b []byte) error {
	if err := e.updateCiphertextBuf(b); err != nil {
		return err
	}
	if e.signer != nil {
		_, err := e.signer.Write(b)
		if err != nil {
			return fmt.Errorf("signer write error: %w", err)
		}
	}

	return nil
}

func (e *Encrypter) reset(err error) {
	e._derivedDataKey = nil
	if err != nil {
		e.header = nil
	}
}
